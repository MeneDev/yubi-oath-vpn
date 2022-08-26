package netctrl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func DefaultNetworkController(ctx context.Context) NetworkController {
	return OpenVpnGuiConnectorNew(ctx)
}

func OpenVpnGuiConnectorNew(ctx context.Context) NetworkController {
	ctx, cancel := context.WithCancel(ctx)

	connector := &openVpnGuiConnector{ctx: ctx, canel: cancel}

	connector.resultsChan = make(chan ConnectionAttemptResult)
	go func() {
		defer cancel()
		defer close(connector.resultsChan)

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return connector
}

var _ NetworkController = (*openVpnGuiConnector)(nil)

type openVpnGuiConnector struct {
	ctx         context.Context
	canel       context.CancelFunc
	resultsChan chan ConnectionAttemptResult
}

func (ctor *openVpnGuiConnector) Connect(ctx context.Context, connectionName string, code string) {
	log.Debug().Str("connection", connectionName).Str("code", code).Msg("Connecting")
	storePassword(connectionName, code)

	go func() {

		reg, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\OpenVPN`, registry.QUERY_VALUE)
		if err != nil {
			log.Error().Err(err).Msg("error opening registry key")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}

		defer reg.Close()

		exePath, _, err := reg.GetStringValue(`exe_path`)
		if err != nil {
			log.Error().Err(err).Msg("error reading exe_path")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}
		log.Debug().Msg("exePath: " + exePath)

		logDir, _, err := reg.GetStringValue(`log_dir`)
		if err != nil {
			log.Error().Err(err).Msg("error reading log_dir")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}
		log.Debug().Msg("logDir: " + logDir)

		openVpnBin := filepath.Dir(exePath)

		homeDir := userHomeDir()

		exe := filepath.Join(openVpnBin, "openvpn-gui.exe")
		logPath := filepath.Join(homeDir, "OpenVPN", "log", connectionName+".log")

		log.Debug().Msg("exe: " + exe)
		log.Debug().Msg("logPath: " + logPath)

		log.Debug().Msg("Set silence")
		if err := execute(ctx, exe, "--command", "silent_connection", "1"); err != nil {
			log.Error().Err(err).Msg("error setting silence")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}
		log.Debug().Msg("Set silence ok")

		log.Debug().Msg("Trigger connection\n")
		if err := execute(ctx, exe, "--command", "connect", connectionName); err != nil {
			log.Error().Err(err).Msg("error triggering connection")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}
		log.Debug().Msg("Trigger connection ok")

		log.Debug().Msg("Unset silence")
		if err := execute(ctx, exe, "--command", "silent_connection", "1"); err != nil {
			log.Error().Err(err).Msg("error unsetting silence")
			ctor.resultsChan <- &nmcliResult{message: err.Error(), success: false}
			return
		}
		log.Debug().Msg("Unset silence ok")

		followContext, followCancel := context.WithCancel(ctx)
		linesChan := make(chan lineError)

		defer func() {
			followCancel()
			defer close(linesChan)
		}()

		fp, _ := os.Open(logPath)
		if fp != nil {
			fp.Truncate(0)
			fp.Sync()
			fp.Close()
		}

		followLogFile(followContext, logPath, linesChan)

		hasError := false

		loglines := make([]string, 0)

		connecting := true

		for connecting {
			select {
			case <-ctx.Done():
				log.Debug().Msg("Context canceled\n")

				ctor.resultsChan <- &nmcliResult{message: "Canceled", success: false}
				return
			case lineError := <-linesChan:
				if lineError.err != nil {
					log.Error().Err(lineError.err).Msg("error received")
					ctor.resultsChan <- &nmcliResult{message: lineError.err.Error(), success: false}
					hasError = true
					connecting = false
					break
				}

				line := lineError.line
				log.Debug().Str("line", line).Msg("openvpn log line")

				loglines = append(loglines, line)

				if strings.Contains(line, "Restart pause") || strings.Contains(line, "AUTH_FAILED") || strings.Contains(line, "ERROR") {
					log.Warn().Str("line", line).Msg("found error")
					hasError = true
					connecting = false
					break
				}
				// <Date> MANAGEMENT: >STATE:1548773463,CONNECTED,SUCCESS,10.111.60.17,212.23.151.151,1194,,
				if strings.Contains(line, "MANAGEMENT") && strings.Contains(line, "CONNECTED,SUCCESS") {
					log.Info().Str("line", line).Msg("connection successful")
					ctor.resultsChan <- &nmcliResult{message: "Done", success: true}
					connecting = false
					break
				}
			}
		}

		if hasError {

			disconnect := true
			for disconnect {
				disconnect = false
				log.Info().Msg("sending disconnect")
				if err := execute(ctx, exe, "--command", "disconnect", connectionName); err != nil {
					disconnect = true
					time.Sleep(100 * time.Millisecond)

					log.Warn().Err(err).Msg("could not disconnect")
				}
			}
			log.Info().Msg("sending disconnect: done")
		}

		ctor.resultsChan <- &nmcliResult{message: strings.Join(loglines, "\n"), success: false}
	}()
}

func storePassword(connectionName string, code string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\OpenVPN-GUI\configs\`+connectionName, registry.QUERY_VALUE|registry.WRITE)
	if err != nil {
		log.Error().Int("stage", 1).Err(err).Msg("error storing password")
		return
	}
	defer k.Close()

	entropy, _, err := k.GetBinaryValue("entropy")
	if err != nil {
		log.Error().Int("stage", 2).Err(err).Msg("error storing password")
		return
	}
	entropy = entropy[:len(entropy)-1]

	log.Debug().Hex("entropy", entropy).Msg("")

	utfCode, err := windows.UTF16FromString(code)

	buffer := bytes.NewBuffer(nil)

	err = binary.Write(buffer, binary.LittleEndian, utfCode)
	if err != nil {
		log.Error().Int("stage", 5).Err(err).Msg("error storing password")
		return
	}

	byteCode := buffer.Bytes()
	encrypt, err := Encrypt(byteCode, entropy)
	if err != nil {
		log.Error().Int("stage", 6).Err(err).Msg("error storing password")
		return
	}

	err = k.SetBinaryValue("auth-data", encrypt)
	if err != nil {
		log.Error().Int("stage", 7).Err(err).Msg("error storing password")
		return
	}
}

func Encrypt(data []byte, entropy []byte) ([]byte, error) {
	var outblob DataBlob
	r, _, err := procEncryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, uintptr(unsafe.Pointer(NewBlob(entropy))), 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procEncryptData = dllcrypt32.NewProc("CryptProtectData")
	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

func (b *DataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	//
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}
func NewBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

type lineError struct {
	line string
	err  error
}

func followLogFile(ctx context.Context, filePath string, lines chan<- lineError) {

	var running int32 = 0
	keepRunning := &running

	atomic.StoreInt32(keepRunning, 1)

	go func() {
		defer func() {
			recover()
		}()

		knownLines := make(map[string]interface{})

		for atomic.LoadInt32(keepRunning) == 1 {
			func() {
				file, err := os.Open(filePath)
				if err != nil {
					lines <- lineError{err: err}
					return
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if atomic.LoadInt32(keepRunning) != 1 {
						return
					}
					text := scanner.Text()
					if _, ok := knownLines[text]; !ok {
						lines <- lineError{line: text}
						knownLines[text] = true
					}
				}

				if err := scanner.Err(); err != nil {
					lines <- lineError{err: err}
				}
				time.Sleep(100 * time.Millisecond)
			}()
		}
	}()

	go func() {
		<-ctx.Done()
		atomic.StoreInt32(keepRunning, 0)
	}()
}

func execute(ctx context.Context, name string, args ...string) error {

	subProcess := exec.CommandContext(ctx, name, args...)

	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	subProcess.Stdout = stdout
	subProcess.Stderr = stderr

	if err := subProcess.Start(); err != nil { //Use start, not run
		return err
	}

	log.Debug().Str("name", name).Interface("args", args).Msg("executing command")
	if err := subProcess.Wait(); err != nil {
		return err
	}

	log.Debug().Str("name", name).Interface("args", args).Msg("executing command finished")

	stderrStr := stderr.String()
	if stderrStr != "" {
		return errors.New(stderrStr)
	}

	return nil
}

func (ctor *openVpnGuiConnector) ConnectionResults() <-chan ConnectionAttemptResult {
	return ctor.resultsChan
}

func userHomeDir() string {
	home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	return home
}
