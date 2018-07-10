package main

import (
	"sync"
	"fmt"
	"time"
	"github.com/jochenvg/go-udev"
	"github.com/ebfe/scard"
	"context"
	"encoding/binary"
	"github.com/gotk3/gotk3/gtk"
	"log"
	"github.com/gotk3/gotk3/gdk"
	"reflect"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha1"
	"crypto/hmac"
	"math/rand"
	"net"
	"strings"
	"github.com/google/gousb"
	"os/exec"
	"io"
	"os"
	"github.com/jessevdk/go-flags"
)

type TAG byte
const (
	NAME TAG = 0x71
	NAME_LIST TAG = 0x72
	KEY TAG = 0x73
	CHALLENGE TAG = 0x74
	RESPONSE TAG = 0x75
	TRUNCATED_RESPONSE TAG = 0x76
	NO_RESPONSE TAG = 0x77
	PROPERTY TAG = 0x78
	VERSION TAG = 0x79
	IMF TAG = 0x7a
	ALGORITHM TAG = 0x7b
	TOUCH TAG = 0x7c
)

type ALGO byte
const (
	SHA1 ALGO = 0x01
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

type INS byte
const (
	PUT INS = 0x01
	DELETE INS = 0x02
	SET_CODE INS = 0x03
	RESET INS = 0x04
	LIST byte = 0xa1
	CALCULATE INS = 0xa2
	VALIDATE INS = 0xa3
	CALCULATE_ALL INS = 0xa4
	SEND_REMAINING INS = 0xa5
)

type YubiKeyError uint32

const (
	_ = iota
	ErrorChkWrong YubiKeyError = iota
	ErrorWrongPassword YubiKeyError = iota
	ErrorUserCancled YubiKeyError = iota
)

type YubiKey struct {
	card scard.Card
	tlvs []Tlv
}

type AID []byte

var	AID_OTP = AID{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}
var	AID_OATH = AID{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}
var	AID_MGR = AID{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}

func (e YubiKeyError) Error() string {
	return fmt.Sprint(e)
}

func (self YubiKey) send_apdu(cl byte, ins byte, p1 byte, p2 byte, data []byte) ([]byte, error) {
	card := self.card
	header := []byte {cl, ins, p1, p2, byte(len(data))}
	telegram := append(header, data...)

	fmt.Printf("sending: % 0x\n", telegram)

	rsp, err := card.Transmit(telegram)

	if err != nil {
		return rsp, err
	}

	fmt.Printf("received %d bytes: % 0x\n", len(rsp), rsp)

	chk_buffer := rsp[len(rsp) - 2:]

	chk := binary.BigEndian.Uint16(chk_buffer)
	if (chk != 0x9000) {
		return rsp, ErrorChkWrong
	}

	rsp = rsp[:len(rsp) - 2]
	return rsp, err
}
var GP_INS_SELECT byte = 0xA4

func (self YubiKey) selectAid(aid AID) ([]byte, error) {
	resp, err := self.send_apdu(0, GP_INS_SELECT, 0x04, 0, aid)
	return resp, err
}

var SLOT_DEVICE_SERIAL byte = 0x10
var OTP_INS_YK2_REQ byte = 0x01

func (self YubiKey) readSerial() (uint32, error) {
	resp, err := self.send_apdu(0, OTP_INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0, []byte {})
	if err != nil {
		return 0, err
	}
	serial := binary.BigEndian.Uint32(resp)
	return serial, err
}

type Tlv struct {
	tag byte
	value []byte
}

func (self YubiKey) parseTlvs(response []byte) (map[byte]Tlv, error) {
	tlvs := make(map[byte]Tlv)
	for len(response) > 0 {
		tag := response[0]
		ln := uint64(response[1])
		offs := uint64(2)
		if ln > 0x80 {
			n_bytes := ln - 0x80

			lenBuffer := response[offs : offs+n_bytes]
			buf := make([]byte, 8)
			copy(buf[8-len(lenBuffer):], lenBuffer)
			ln = binary.BigEndian.Uint64(buf)
			offs = offs + n_bytes
		}

		value := response[offs : offs+ln]
		response = response[offs+ln:]

		tlv := Tlv{
			tag:   tag,
			value: value,
		}

		tlvs[tag] = tlv
	}

	return tlvs, nil
}

func (self Tlv) buffer() []byte {
	res := make([]byte, 1)
	res[0] = self.tag
	res = append(append(res, byte(len(self.value))), self.value...)
	return res
}

func parseTruncated(data []byte) uint32 {
	res := binary.BigEndian.Uint32(data) & 0x7fffffff
	return res
}

func askPassword(additionalMessage string) (string, error) {

	password := ""
	var err error

	// Initialize GTK without parsing any command line arguments.
	gtk.Init(nil)

	// Create a new toplevel window, set its title, and connect it to the
	// "destroy" signal to exit the GTK main loop when it is destroyed.
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		log.Fatal("Unable to create window:", err)
	}
	win.SetTitle("Yubikey Password Required")
	win.Connect("destroy", func() {
		gtk.MainQuit()
		err = ErrorUserCancled
	})

	win.Connect("key-press-event", func(win *gtk.Window, ev *gdk.Event) {
		keyEvent := &gdk.EventKey{ev}

		if keyEvent.KeyVal() == gdk.KEY_Escape {
			err = ErrorUserCancled
			win.Destroy()
		}
	})

	win.SetPosition(gtk.WIN_POS_CENTER)

	input, err := gtk.EntryNew()

	input.SetInputPurpose(gtk.INPUT_PURPOSE_PASSWORD)
	input.SetVisibility(false)

	button, err := gtk.ButtonNew()
	button.SetLabel("OK")
	grid, err := gtk.GridNew()
	if err != nil {
		log.Fatal("Unable to create grid:", err)
		if err != nil {
			return "", err
		}
	}
	grid.SetOrientation(gtk.ORIENTATION_VERTICAL)

	if len(additionalMessage) > 0 {
		message, err := gtk.LabelNew(additionalMessage)
		if err != nil {
			return "", err
		}

		message.SetMarginBottom(10)
		grid.Add(message)
	}

	grid.Add(input)
	grid.Add(button)

	setPassword := func() {
		text, e := input.GetText()

		win.Destroy()

		password = text
		err = e
	}

	button.Connect("clicked", setPassword)
	input.Connect("key-press-event", func(win *gtk.Entry, ev *gdk.Event) {
		keyEvent := &gdk.EventKey{ev}

		if keyEvent.KeyVal() == gdk.KEY_Return {
			setPassword()
		}
	})

	input.SetMarginBottom(10)
	win.Add(grid)
	grid.SetMarginBottom(10)
	grid.SetMarginTop(10)
	grid.SetMarginEnd(10)
	grid.SetMarginStart(10)

	win.ShowAll()

	gtk.Main()

	return password, err
}

func getCode() (string, error) {
	// Establish a PC/SC context
	scardCtx, err := scard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return "", err
	}

	// Release the PC/SC context (when needed)
	defer scardCtx.Release()

	// List available readers
	readers, err := scardCtx.ListReaders()
	if err != nil {
		fmt.Println("Error ListReaders:", err)
		return "", err
	}

	// Use the first reader with "yubi" in its name
	var reader string
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), "yubi") {
			reader = r
			break
		}
	}

	fmt.Println("Using reader:", reader)

	// Connect to the card
	card, err := scardCtx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fmt.Println("Error Connect:", err)
		return "", err
	}

	// Disconnect (when needed)
	defer card.Disconnect(scard.LeaveCard)

	yubikey := YubiKey{card: *card}

	rsp, err := yubikey.selectAid(AID_OTP)
	if err != nil {
		return "", err
	}

	serial, err := yubikey.readSerial()
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return "", err
	}
	fmt.Printf("% 0x \n", rsp)
	fmt.Printf("serial %d\n", serial)

	rsp_mgr, err := yubikey.selectAid(AID_MGR)
	if err != nil {
		return "", err
	}

	fmt.Printf("rsp_oath: % 0x \n", rsp_mgr)

	var cmd_3 = []byte{0x00, 0x1D, 0x00, 0x00, 0x00}
	rsp_3, err := card.Transmit(cmd_3)
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return "", err
	}
	fmt.Printf("% 0x\n", rsp_3)

	resp_oath, err := yubikey.selectAid(AID_OATH)
	if err != nil {
		return "", err
	}

	tlvs, err := yubikey.parseTlvs(resp_oath)
	if err != nil {
		return "", err
	}

	OATH_TAG_NAME := byte(0x71)
	OATH_TAG_CHALLENGE := byte(0x74)
	OATH_TAG_ALGORITHM := byte(0x7b)
	OATH_TAG_VERSION := byte(0x79)
	OATH_TAG_RESPONSE := byte(0x75)

	name := binary.BigEndian.Uint64(tlvs[OATH_TAG_NAME].value)

	fmt.Printf("name: % 0x\n", tlvs[OATH_TAG_NAME].value)
	fmt.Printf("name: %d\n", name)

	fmt.Printf("algorithm: % 0x\n", tlvs[OATH_TAG_ALGORITHM])
	fmt.Printf("version: % 0x\n", tlvs[OATH_TAG_VERSION])

	pwd, err := askPassword("")
	if err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(pwd), tlvs[OATH_TAG_NAME].value, 1000, 16, sha1.New)

	h := hmac.New(sha1.New, key)
	h.Write(tlvs[OATH_TAG_CHALLENGE].value)
	response := h.Sum(nil)
	challenge := make([]byte, 8)
	rand.Read(challenge)

	h = hmac.New(sha1.New, key)
	h.Write(challenge)
	verification := h.Sum(nil)

	response_tlv := Tlv{tag: OATH_TAG_RESPONSE, value: response}
	challenge_tlv := Tlv{tag: OATH_TAG_CHALLENGE, value: challenge}

	validate_data := append(response_tlv.buffer(), challenge_tlv.buffer()...)
	INS_VALIDATE := byte(0xa3)

	verify_resp, err := yubikey.send_apdu(0, INS_VALIDATE, 0, 0, validate_data)
	if err, ok := err.(YubiKeyError); ok && err == ErrorChkWrong {
		if reflect.DeepEqual(verify_resp, []byte {0x6A, 0x80}) {
			return "", ErrorWrongPassword
		}
	}
	if err != nil {
		return "", err
	}

	verify_tlvs, err := yubikey.parseTlvs(verify_resp)
	if err != nil {
		return "", err
	}

	println(verify_tlvs)
	fmt.Printf("verification: % 0x\n", verification)
	fmt.Printf("verification: % 0x\n", verify_tlvs[OATH_TAG_RESPONSE].value)

	if (!reflect.DeepEqual(verification, verify_tlvs[OATH_TAG_RESPONSE].value)) {
		panic("Verification failed")
	}

	var cmd_5 = []byte{0x00, byte(CALCULATE_ALL), 0x00, 0x01, 0x0A, 0x74, 0x08}

	timeBuffer := make([]byte, 8)

	binary.BigEndian.PutUint64(timeBuffer, uint64(time.Now().UTC().Unix() / 30))

	cmd_5 = append(cmd_5, timeBuffer...)

	rsp_5, err := card.Transmit(cmd_5)
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return "", err
	}
	fmt.Printf("% 0x\n", rsp_5)

	creds_tlvs, err := yubikey.parseTlvs(rsp_5)
	if err != nil {
		return "", err
	}

	TRUNCATED_RESPONSE := byte(0x76)

	fmt.Printf("code is in: % 0x\n", creds_tlvs[TRUNCATED_RESPONSE].value)

	code := parseTruncated(creds_tlvs[TRUNCATED_RESPONSE].value[1:])

	fmt.Printf("code: %06d\n", code)

	strCode := fmt.Sprintf("%06d", code)

	return strCode, err
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

func connect(connectionName string, codeProvider func() (string, error)) error {
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

	io.WriteString(stdin, "vpn.secrets.password:" + code + "\n")
	stdin.Close()
	println("start connecting via nmcli")
	subProcess.Wait()
	println("finished connecting via nmcli")

	return nil
}

type CodeProvider struct {
	codeCache string
	codeError error
}

func (self CodeProvider) Clear()  {
	self.codeCache = ""
}
func (self CodeProvider) GetCode() (string, error) {
	if len(self.codeCache) == 0 {
		self.codeCache, self.codeError = getCode()
	}
	return self.codeCache, self.codeError
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
			err = connect(connectionName, codeProvider.GetCode)

			if err, ok := err.(YubiKeyError); ok {
				if err == ErrorWrongPassword {
					codeProvider.Clear()
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
	ShowVersion bool `required:"no" short:"v" long:"version" description:"Show version and exit"`
}

func main() {
	var opts Options

	args, err := flags.NewParser(&opts, flags.HelpFlag | flags.PassDoubleDash).Parse()
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
	codeProvider := CodeProvider{}

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
	m.FilterAddMatchSubsystem("usbmisc")
	m.FilterAddMatchTag("uaccess")
	m.FilterAddMatchTag("seat")

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
			if action == "add" {
				println("add event")
				fmt.Println("Event:", d.Syspath(), d.Action())

				connectIfNotConnectedAndYubikeyPresent(opts.ConnectionName, checkUsb, codeProvider)
			}
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
