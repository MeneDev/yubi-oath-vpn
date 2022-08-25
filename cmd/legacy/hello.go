package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/MeneDev/yubi-oath-vpn/gui"
	"github.com/MeneDev/yubi-oath-vpn/yubierror"
	"github.com/ebfe/scard"
	"github.com/google/gousb"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"
	"github.com/jessevdk/go-flags"
	"github.com/jochenvg/go-udev"
)

type TAG byte

const (
	NAME               TAG = 0x71
	NAME_LIST          TAG = 0x72
	KEY                TAG = 0x73
	CHALLENGE          TAG = 0x74
	RESPONSE           TAG = 0x75
	TRUNCATED_RESPONSE TAG = 0x76
	NO_RESPONSE        TAG = 0x77
	PROPERTY           TAG = 0x78
	VERSION            TAG = 0x79
	IMF                TAG = 0x7a
	ALGORITHM          TAG = 0x7b
	TOUCH              TAG = 0x7c
)

type ALGO byte

const (
	SHA1   ALGO = 0x01
	SHA256 ALGO = 0x02
	SHA512 ALGO = 0x03
)

type PROPERTIES byte

const (
	REQUIRE_TOUCH PROPERTIES = 0x02
)

type OATH_TYPE byte

const (
	HOTP OATH_TYPE = 0x10
	TOTP OATH_TYPE = 0x20
)

func askPassword(additionalMessage string) (string, error) {

	password := ""
	var err error

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		// Initialize GTK without parsing any command line arguments.
		gtk.Init(nil)

		builder, _ := gtk.BuilderNewFromFile("/home/marndt/go/src/github.com/MeneDev/yubi-oath-vpn/ConnectDialog.gtk")

		objDlg, _ := builder.GetObject("Dialog")
		win := objDlg.(*gtk.Window)

		objPassword, _ := builder.GetObject("txtPassword")
		txtPassword := objPassword.(*gtk.Entry)
		txtPassword.SetInputPurpose(gtk.INPUT_PURPOSE_PASSWORD)
		txtPassword.SetVisibility(false)

		objConnect, _ := builder.GetObject("btnConnect")
		btnConnect := objConnect.(*gtk.Button)

		objConnecting, _ := builder.GetObject("lblConnecting")
		lblConnect := objConnecting.(*gtk.Label)
		objConnectingSpinner, _ := builder.GetObject("spnConnecting")
		spnConnecting := objConnectingSpinner.(*gtk.Spinner)
		spnConnecting.Stop()
		lblConnect.SetLabel("")
		win.Connect("destroy", func() {
			gtk.MainQuit()
			err = yubierror.ErrorUserCancled
		})

		win.Connect("key-press-event", func(win *gtk.Window, ev *gdk.Event) {
			keyEvent := &gdk.EventKey{ev}

			if keyEvent.KeyVal() == gdk.KEY_Escape {
				err = yubierror.ErrorUserCancled
				win.Destroy()
			}
		})

		setPassword := func() {
			text, e := txtPassword.GetText()
			password = text
			err = e

			spnConnecting.Start()
			lblConnect.SetLabel("Connecting...")
			wg.Done()
		}

		btnConnect.Connect("clicked", setPassword)
		txtPassword.Connect("key-press-event", func(win *gtk.Entry, ev *gdk.Event) {
			keyEvent := &gdk.EventKey{ev}

			if keyEvent.KeyVal() == gdk.KEY_Return {
				setPassword()
			}
		})

		win.ShowAll()

		gtk.Main()
	}()

	wg.Wait()

	return password, err
}

func getCode(scardCtx *scard.Context, passwordAsker PasswordAsker) (string, error) {
	//fmt.Print("ListReaders... ")
	//// List available readers
	//readers, err := scardCtx.ListReaders()
	//if err != nil {
	//	fmt.Println("Error ListReaders:", err)
	//	return "", err
	//}
	//fmt.Println("done")
	//
	//// Use the first reader with "yubi" in its name
	//var reader string
	//for _, r := range readers {
	//	if strings.Contains(strings.ToLower(r), "yubi") {
	//		reader = r
	//		break
	//	}
	//}
	//
	//fmt.Println("Using reader:", reader)
	//
	//// Connect to the card
	//card, err := scardCtx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	//if err != nil {
	//	fmt.Println("Error Connect:", err)
	//	return "", err
	//}
	//
	//// Disconnect (when needed)
	//defer card.Disconnect(scard.LeaveCard)
	//
	//yubikey := YubiKey{card: *card}
	//
	//rsp, err := yubikey.selectAid(AID_OTP)
	//if err != nil {
	//	return "", err
	//}
	//
	//serial, err := yubikey.readSerial()
	//if err != nil {
	//	fmt.Println("Error Transmit:", err)
	//	return "", err
	//}
	//fmt.Printf("% 0x \n", rsp)
	//fmt.Printf("serial %d\n", serial)
	//
	//rsp_mgr, err := yubikey.selectAid(AID_MGR)
	//if err != nil {
	//	return "", err
	//}
	//
	//fmt.Printf("rsp_oath: % 0x \n", rsp_mgr)
	//
	//var cmd_3 = []byte{0x00, 0x1D, 0x00, 0x00, 0x00}
	//rsp_3, err := card.Transmit(cmd_3)
	//if err != nil {
	//	fmt.Println("Error Transmit:", err)
	//	return "", err
	//}
	//fmt.Printf("% 0x\n", rsp_3)
	//
	//resp_oath, err := yubikey.selectAid(AID_OATH)
	//if err != nil {
	//	return "", err
	//}
	//
	//tlvs, err := yubikey.parseTlvs(resp_oath)
	//if err != nil {
	//	return "", err
	//}
	//
	//OATH_TAG_NAME := byte(0x71)
	//OATH_TAG_CHALLENGE := byte(0x74)
	//OATH_TAG_ALGORITHM := byte(0x7b)
	//OATH_TAG_VERSION := byte(0x79)
	//OATH_TAG_RESPONSE := byte(0x75)
	//
	//name := binary.BigEndian.Uint64(tlvs[OATH_TAG_NAME].value)
	//
	//fmt.Printf("name: % 0x\n", tlvs[OATH_TAG_NAME].value)
	//fmt.Printf("name: %d\n", name)
	//
	//fmt.Printf("algorithm: % 0x\n", tlvs[OATH_TAG_ALGORITHM])
	//fmt.Printf("version: % 0x\n", tlvs[OATH_TAG_VERSION])
	//
	//pwd, _, err := passwordAsker("")
	//if err != nil {
	//	return "", err
	//}
	//
	//key := pbkdf2.Key([]byte(pwd), tlvs[OATH_TAG_NAME].value, 1000, 16, sha1.New)
	//
	//h := hmac.New(sha1.New, key)
	//h.Write(tlvs[OATH_TAG_CHALLENGE].value)
	//response := h.Sum(nil)
	//challenge := make([]byte, 8)
	//rand.Read(challenge)
	//
	//h = hmac.New(sha1.New, key)
	//h.Write(challenge)
	//verification := h.Sum(nil)
	//
	//response_tlv := Tlv{tag: OATH_TAG_RESPONSE, value: response}
	//challenge_tlv := Tlv{tag: OATH_TAG_CHALLENGE, value: challenge}
	//
	//validate_data := append(response_tlv.buffer(), challenge_tlv.buffer()...)
	//INS_VALIDATE := byte(0xa3)
	//
	//verify_resp, err := yubikey.send_apdu(0, INS_VALIDATE, 0, 0, validate_data)
	//if err, ok := err.(yubierror.YubiKeyError); ok && err == yubierror.ErrorChkWrong {
	//	if reflect.DeepEqual(verify_resp, []byte{0x6A, 0x80}) {
	//		return "", yubierror.ErrorWrongPassword
	//	}
	//}
	//if err != nil {
	//	return "", err
	//}
	//
	//verify_tlvs, err := yubikey.parseTlvs(verify_resp)
	//if err != nil {
	//	return "", err
	//}
	//
	//println(verify_tlvs)
	//fmt.Printf("verification: % 0x\n", verification)
	//fmt.Printf("verification: % 0x\n", verify_tlvs[OATH_TAG_RESPONSE].value)
	//
	//if !reflect.DeepEqual(verification, verify_tlvs[OATH_TAG_RESPONSE].value) {
	//	panic("Verification failed")
	//}
	//
	//var cmd_5 = []byte{0x00, byte(CALCULATE_ALL), 0x00, 0x01, 0x0A, 0x74, 0x08}
	//
	//timeBuffer := make([]byte, 8)
	//
	//binary.BigEndian.PutUint64(timeBuffer, uint64(time.Now().UTC().Unix()/30))
	//
	//cmd_5 = append(cmd_5, timeBuffer...)
	//
	//rsp_5, err := card.Transmit(cmd_5)
	//if err != nil {
	//	fmt.Println("Error Transmit:", err)
	//	return "", err
	//}
	//fmt.Printf("% 0x\n", rsp_5)
	//
	//creds_tlvs, err := yubikey.parseTlvs(rsp_5)
	//if err != nil {
	//	return "", err
	//}
	//
	//TRUNCATED_RESPONSE := byte(0x76)
	//
	//fmt.Printf("code is in: % 0x\n", creds_tlvs[TRUNCATED_RESPONSE].value)
	//
	//code := parseTruncated(creds_tlvs[TRUNCATED_RESPONSE].value[1:])
	//
	//fmt.Printf("code: %06d\n", code)
	//
	//strCode := fmt.Sprintf("%06d", code)
	//
	//return strCode, err
	panic("not implemented anymore")
}

func isConnectedToTun() (bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
		return false, err
	}

	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}

		if strings.HasPrefix(iface.Name, "tun") {
			return true, nil
		}
	}

	return false, nil
}

func _checkUsb(usbContext *gousb.Context) (bool, error) {
	found := false

	devs, err := usbContext.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		fmt.Println(desc)
		if desc.Vendor == 0x1050 && desc.Product == 0x0407 {
			found = true
		}
		return false
	})

	defer func() {
		for _, d := range devs {
			d.Close()
		}
	}()

	return found, err
}

func connect(connectionName string, codeProvider func() (string, error), informFinishedConnecting func()) error {
	code, err := codeProvider()
	if err != nil {
		return err
	}

	subProcess := exec.Command("nmcli", "con", "up", connectionName, "passwd-file", "/dev/fd/0")
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		return err
	}

	defer stdin.Close()

	subProcess.Stdout = os.Stdout
	subProcess.Stderr = os.Stderr

	if err = subProcess.Start(); err != nil { //Use start, not run
		fmt.Println("An error occured: ", err) //replace with logger, or anything you want
	}
	if err != nil {
		return err
	}

	io.WriteString(stdin, "vpn.secrets.password:"+code+"\n")
	stdin.Close()
	println("start connecting via nmcli")
	subProcess.Wait()
	informFinishedConnecting()
	println("finished connecting via nmcli")

	return nil
}

type PasswordAsker func(additionalMessage string) (string, context.Context, error)

type scardContextProviderResult struct {
	ctx *scard.Context
	err error
}

type scardContextProvider struct {
	initDone sync.WaitGroup
	result   scardContextProviderResult
}

func scardContextProviderNew() *scardContextProvider {
	provider := &scardContextProvider{}
	provider.initDone.Add(1)
	provider.init()

	return provider
}

func (provider *scardContextProvider) init() {
	go func() {
		fmt.Println("Establish a PC/SC context... ")
		// Establish a PC/SC context
		scardCtx, err := scard.EstablishContext()
		provider.result = scardContextProviderResult{scardCtx, err}

		provider.initDone.Done()
		fmt.Println("Establish a PC/SC context... done")
	}()
}

func (provider *scardContextProvider) Context() (*scard.Context, error) {
	provider.initDone.Wait()
	return provider.result.ctx, provider.result.err
}

func (provider *scardContextProvider) Release() error {
	provider.initDone.Wait()
	return provider.result.ctx.Release()
}

type CodeProvider struct {
	codeCache                 string
	codeError                 error
	askPassword               PasswordAsker
	_informFinishedConnecting func()
	_setError                 func(err error)
	provider                  *scardContextProvider
}

func (c *CodeProvider) Clear() {
	c.codeCache = ""
}
func (c *CodeProvider) GetCode() (string, error) {
	if len(c.codeCache) == 0 {
		ctx, _ := c.provider.Context()
		c.codeCache, c.codeError = getCode(ctx, c.askPassword)
	}
	return c.codeCache, c.codeError
}
func (c *CodeProvider) informFinishedConnecting() {
	c._informFinishedConnecting()
}
func (c *CodeProvider) SetError(err error) {
	c._setError(err)
}

func connectIfNotConnectedAndYubikeyPresent(connectionName string, usbChecker func() (bool, error), codeProvider CodeProvider) {

	retry := true

	for i := 0; i < 100 && retry; i++ {
		retry = false
		isConnected, err := isConnectedToTun()
		if err != nil {
			panic("error checking conncetion")
		}

		isYubikeyPresent, err := usbChecker()
		if err != nil {
			panic("error checking usb devices")
		}

		if !isConnected && isYubikeyPresent {
			err = connect(connectionName, codeProvider.GetCode, func() {
				codeProvider.informFinishedConnecting()
			})

			if err, ok := err.(yubierror.YubiKeyError); ok {
				if err == yubierror.ErrorWrongPassword {
					codeProvider.Clear()
					codeProvider.SetError(yubierror.ErrorWrongPassword)
					retry = true
				}
			}
			if scardError, ok := err.(scard.Error); ok {
				switch scardError {
				case scard.ErrResetCard:
					retry = true
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
	}

}

type Options struct {
	ConnectionName string `required:"yes" short:"c" long:"connection" description:"The name of the connection as shown by 'nmcli c show'"`
	ShowVersion    bool   `required:"no" short:"v" long:"version" description:"Show version and exit"`
}

func main() {
	var opts Options

	provider := scardContextProviderNew()
	defer provider.Release()

	//askPassword("Message")

	args, err := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash).Parse()
	if opts.ShowVersion {
		showVersion()
		os.Exit(0)
	}

	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	fmt.Println(args)
	fmt.Println(opts)
	fmt.Println(opts.ConnectionName)

	gtkGui := gui.GtkGui(context.TODO())
	gtkGui.Init()

	codeProvider := CodeProvider{
		askPassword: func(additionalMessage string) (string, context.Context, error) {
			return gtkGui.AskPassword(additionalMessage)
		},
		_informFinishedConnecting: func() {
			gtkGui.InformFinishedConnecting()
		},
		_setError: func(err error) {
			gtkGui.SetError(err)
		},
		provider: provider,
	}

	usbContext := gousb.NewContext()
	defer usbContext.Close()

	checkUsb := func() (bool, error) {
		return _checkUsb(usbContext)
	}

	// try initial connection
	connectIfNotConnectedAndYubikeyPresent(opts.ConnectionName, checkUsb, codeProvider)

	// Create Udev and Monitor
	u := udev.Udev{}
	m := u.NewMonitorFromNetlink("udev")

	// Add filters to monitor
	m.FilterAddMatchSubsystem("usb")
	//m.FilterAddMatchTag("uaccess")
	//m.FilterAddMatchTag("seat")

	// Create a context
	ctx, cancel := context.WithCancel(context.Background())

	// Start monitor goroutine and get receive channel
	ch, _ := m.DeviceChan(ctx)

	// WaitGroup for timers
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		fmt.Println("Started listening on channel")
		for d := range ch {
			action := d.Action()
			subsystem := d.Subsystem()
			tags := d.Tags()
			println(subsystem)
			println(tags)
			if action == "add" {
				println("add event")
				fmt.Println("Event:", d.Syspath(), d.Action())

				connectIfNotConnectedAndYubikeyPresent(opts.ConnectionName, checkUsb, codeProvider)
			}
			//if action == "remove" {
			//	yubiPresent, _ := checkUsb()
			//	if !yubiPresent {
			//		gtkGui.Cancel()
			//	}
			//}
		}
		cancel()
		fmt.Println("Channel closed")
		wg.Done()
	}()
	go func() {
		wg.Done()
	}()
	go func() {
		wg.Done()
	}()
	wg.Wait()
}

var Version string = "<unknown>"
var BuildDate string = "<unknown>"
var BuildNumber string = "<unknown>"
var BuildCommit string = "<unknown>"

func showVersion() {
	format := "%-13s%s\n"
	fmt.Printf(format, "Version:", Version)
	fmt.Printf(format, "BuildDate:", BuildDate)
	fmt.Printf(format, "BuildNumber:", BuildNumber)
	fmt.Printf(format, "BuildCommit:", BuildCommit)
}
