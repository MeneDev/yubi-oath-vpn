package main

import (
	"sync"
	"fmt"
	"time"
	"github.com/jochenvg/go-udev"
	"github.com/joshdk/ykmango"
	"github.com/ebfe/scard"
	"context"
	"encoding/binary"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha1"
	"crypto/hmac"
	"math/rand"
	"reflect"
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

type YubiKey struct {
	card scard.Card
	tlvs []Tlv
}

func (self YubiKey) send_apdu(cl byte, ins byte, p1 byte, p2 byte, data []byte) ([]byte, error) {
	card := self.card
	header := []byte {cl, ins, p1, p2, byte(len(data))}
	rsp, err := card.Transmit(append(header, data...))
	fmt.Println(self)

	chk_buffer := rsp[len(rsp) - 2:]

	chk := binary.BigEndian.Uint16(chk_buffer)
	if (chk != 0x9000) {
		panic("chk wrong")
	}

	rsp = rsp[:len(rsp) - 2]
	return rsp, err
}
var GP_INS_SELECT byte = 0xA4

func (self YubiKey) selectAid(aid []byte) ([]byte, error) {
	resp, err := self.send_apdu(0, GP_INS_SELECT, 0x04, 0, aid)
	return resp, err
}

var SLOT_DEVICE_SERIAL byte = 0x10
var OTP_INS_YK2_REQ byte = 0x01

func (self YubiKey) read_serial() (uint32, error) {
	resp, err := self.send_apdu(0, OTP_INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0, []byte {})
	serial := binary.BigEndian.Uint32(resp)
	return serial, err
}

type Tlv struct {
	tag byte
	value []byte
}

func (self YubiKey) parse_tlvs(response []byte) (map[byte]Tlv, error) {
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

func parse_truncated(data []byte) uint32 {
	res := binary.BigEndian.Uint32(data) & 0x7fffffff
	return res
}

func main() {

	// Establish a PC/SC context
	scardCtx, err := scard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return
	}

	// Release the PC/SC context (when needed)
	defer scardCtx.Release()

	// List available readers
	readers, err := scardCtx.ListReaders()
	if err != nil {
		fmt.Println("Error ListReaders:", err)
		return
	}

	// Use the first reader
	reader := readers[0]
	fmt.Println("Using reader:", reader)

	// Connect to the card
	card, err := scardCtx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fmt.Println("Error Connect:", err)
		return
	}

	// Disconnect (when needed)
	defer card.Disconnect(scard.LeaveCard)

	yubikey := YubiKey{card: *card}

	AID_OTP := []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}
	AID_OATH := []byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}
	AID_MGR := []byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}


	//var cmd_select_otp = append(append([]byte{0x00, GP_INS_SELECT, 0x04, 0x00}, byte(len(AID_OTP))), AID_OTP...)

	rsp, err := yubikey.selectAid(AID_OTP)

	serial, err := yubikey.read_serial()
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return
	}
	fmt.Printf("% 0x \n", rsp)
	fmt.Printf("serial %d\n", serial)

	rsp_mgr, err := yubikey.selectAid(AID_MGR)
	fmt.Printf("rsp_oath: % 0x \n", rsp_mgr)

	var cmd_3 = []byte{0x00, 0x1D, 0x00, 0x00, 0x00}
	rsp_3, err := card.Transmit(cmd_3)
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return
	}
	fmt.Printf("% 0x\n", rsp_3)

	resp_oath, err := yubikey.selectAid(AID_OATH)

	tlvs, err := yubikey.parse_tlvs(resp_oath)

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

	pwd := "abc"
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

	verify_tlvs, err := yubikey.parse_tlvs(verify_resp)

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
		return
	}
	fmt.Printf("% 0x\n", rsp_5)

	creds_tlvs, err := yubikey.parse_tlvs(rsp_5)

	TRUNCATED_RESPONSE := byte(0x76)

	fmt.Printf("code is in: % 0x\n", creds_tlvs[TRUNCATED_RESPONSE].value)

	code := parse_truncated(creds_tlvs[TRUNCATED_RESPONSE].value[1:])


	//code := binary.BigEndian.Uint32(codeBuffer)
	fmt.Printf("code: %06d\n", code)

	println("hello world")
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
				var code string

				for i := 0; i < 100; i++ {

					names, err := ykman.List()
					if len(names) == 0 {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					fmt.Println("names:", names, err)

					for _, name := range names {
						fmt.Printf("Found code named: %s\n", name)
						// Found code named: aws-mfa
					}

					tmp, err := ykman.Generate("foo:vpn")
					code = tmp
					if err != nil {
						panic(err.Error())
					}
					fmt.Println("code:", code, err)
					break
				}

				fmt.Println("code:", code)

				// Establish a PC/SC context
				context, err := scard.EstablishContext()
				if err != nil {
					fmt.Println("Error EstablishContext:", err)
					return
				}

				// Release the PC/SC context (when needed)
				defer context.Release()

				// List available readers
				readers, err := context.ListReaders()
				if err != nil {
					fmt.Println("Error ListReaders:", err)
					return
				}

				// Use the first reader
				reader := readers[0]
				fmt.Println("Using reader:", reader)

				// Connect to the card
				card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
				if err != nil {
					fmt.Println("Error Connect:", err)
					return
				}

				// Disconnect (when needed)
				defer card.Disconnect(scard.LeaveCard)
				if err != nil {
					fmt.Println("Error Transmit:", err)
					return
				}
				fmt.Println(rsp)

			}
		}
		fmt.Println("Channel closed")
		wg.Done()
	}()
	go func() {
		wg.Done()
	}()
	go func() {
		fmt.Println("Starting timer to signal done")
		<-time.After(20 * time.Second)
		fmt.Println("Signalling done")
		cancel()
		wg.Done()
	}()
	wg.Wait()
}
