package scard

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/MeneDev/yubi-oath-vpn/yubierror"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	"github.com/ebfe/scard"
	"golang.org/x/crypto/pbkdf2"
	"math/rand"
	"reflect"
	"time"
)

var _ yubikey.YubiKey = (*scardYubiKey)(nil)

type scardYubiKey struct {
	ctx    context.Context
	cancel context.CancelFunc
	card   *scard.Card
}

func YubiKeyNew(ctx context.Context, scardCtx *scard.Context, reader string) (yubikey.YubiKey, error) {

	ctx, cancel := context.WithCancel(ctx)
	key := &scardYubiKey{ctx: ctx, cancel: cancel}

	card, err := scardCtx.Connect(reader, scard.ShareShared, scard.ProtocolAny)

	if err != nil {
		return nil, err
	}

	key.card = card
	go func() {
		defer func() {
			println("Disconnect YubiKey " + reader)
			cancel()
			card.Disconnect(scard.LeaveCard)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return key, nil
}

func (key *scardYubiKey) Context() context.Context {
	return key.ctx
}

func (key *scardYubiKey) GetCodeWithPassword(pwd string, slotName string) (string, error) {

	card := key.card

	rsp, err := key.selectAid(AID_OTP)
	if err != nil {
		fmt.Printf("Error setting 'AID_OTP': %s\n", err)
	}

	serial, err := key.readSerial()
	if err != nil {
		fmt.Printf("Error reading serial: %s\n", err)
	}
	fmt.Printf("% 0x \n", rsp)
	fmt.Printf("serial %d\n", serial)

	rsp_mgr, err := key.selectAid(AID_MGR)
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

	resp_oath, err := key.selectAid(AID_OATH)
	if err != nil {
		return "", err
	}

	tlvsList, err := key.parseTlvs(resp_oath)
	if err != nil {
		return "", err
	}
	tlvs := tlvsToMap(tlvsList)

	OATH_TAG_NAME := byte(0x71)
	OATH_TAG_CHALLENGE := byte(0x74)
	OATH_TAG_ALGORITHM := byte(0x7b)
	OATH_TAG_VERSION := byte(0x79)
	OATH_TAG_RESPONSE := byte(0x75)
	OATH_TAG_TRUNCATED_RESPONSE := byte(0x76)

	name := binary.BigEndian.Uint64(tlvs[OATH_TAG_NAME].value)

	fmt.Printf("name: % 0x\n", tlvs[OATH_TAG_NAME].value)
	fmt.Printf("name: %d\n", name)

	fmt.Printf("algorithm: % 0x\n", tlvs[OATH_TAG_ALGORITHM])
	fmt.Printf("version: % 0x\n", tlvs[OATH_TAG_VERSION])

	if err != nil {
		return "", err
	}

	pbkdf2Key := pbkdf2.Key([]byte(pwd), tlvs[OATH_TAG_NAME].value, 1000, 16, sha1.New)

	h := hmac.New(sha1.New, pbkdf2Key)
	h.Write(tlvs[OATH_TAG_CHALLENGE].value)
	response := h.Sum(nil)
	challenge := make([]byte, 8)
	rand.Read(challenge)

	h = hmac.New(sha1.New, pbkdf2Key)
	h.Write(challenge)
	verification := h.Sum(nil)

	response_tlv := Tlv{tag: OATH_TAG_RESPONSE, value: response}
	challenge_tlv := Tlv{tag: OATH_TAG_CHALLENGE, value: challenge}

	validate_data := append(response_tlv.buffer(), challenge_tlv.buffer()...)
	INS_VALIDATE := byte(0xa3)

	verify_resp, err := key.send_apdu(0, INS_VALIDATE, 0, 0, validate_data)
	if err, ok := err.(yubierror.YubiKeyError); ok && err == yubierror.ErrorChkWrong {
		if reflect.DeepEqual(verify_resp, []byte{0x6A, 0x80}) {
			return "", yubierror.ErrorWrongPassword
		}
	}
	if err != nil {
		return "", err
	}

	verifyTlvsList, err := key.parseTlvs(verify_resp)
	if err != nil {
		return "", err
	}
	verifyTlvs := tlvsToMap(verifyTlvsList)

	println(verifyTlvs)
	fmt.Printf("verification: % 0x\n", verification)
	fmt.Printf("verification: % 0x\n", verifyTlvs[OATH_TAG_RESPONSE].value)

	if !reflect.DeepEqual(verification, verifyTlvs[OATH_TAG_RESPONSE].value) {
		panic("Verification failed")
	}

	var cmd_5 = []byte{0x00, byte(CALCULATE_ALL), 0x00, 0x01, 0x0A, 0x74, 0x08}

	timeBuffer := make([]byte, 8)

	binary.BigEndian.PutUint64(timeBuffer, uint64(time.Now().UTC().Unix()/30))

	cmd_5 = append(cmd_5, timeBuffer...)

	rsp_5, err := card.Transmit(cmd_5)
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return "", err
	}
	fmt.Printf("% 0x\n", rsp_5)

	credsTlvs, err := key.parseTlvs(rsp_5)
	if err != nil {
		return "", err
	}

	foundSlot := false
	var strCode string
	for _, tlv := range credsTlvs {
		if tlv.tag == OATH_TAG_NAME {
			keySlotName := string(tlv.value)

			if slotName == "" || keySlotName == slotName {
				foundSlot = true
				fmt.Printf("slot %s matched\n", keySlotName)
			} else {
				fmt.Printf("found non-matching slot %s\n", keySlotName)
			}
		}

		if foundSlot && tlv.tag == OATH_TAG_TRUNCATED_RESPONSE {
			fmt.Printf("code is in: % 0x\n", tlv.value)

			code := parseTruncated(tlv.value[1:])

			fmt.Printf("code: %06d\n", code)
			strCode = fmt.Sprintf("%06d", code)

			break
		}
	}

	if !foundSlot {
		return "", yubierror.ErrorSlotNotFound
	}

	return strCode, err
}

type AID []byte

var AID_OTP = AID{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}
var AID_OATH = AID{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}
var AID_MGR = AID{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}

type INS byte

const (
	PUT            INS = 0x01
	DELETE         INS = 0x02
	SET_CODE       INS = 0x03
	RESET          INS = 0x04
	LIST           INS = 0xa1
	CALCULATE      INS = 0xa2
	VALIDATE       INS = 0xa3
	CALCULATE_ALL  INS = 0xa4
	SEND_REMAINING INS = 0xa5
)

const GP_INS_SELECT byte = 0xA4

func (self *scardYubiKey) selectAid(aid AID) ([]byte, error) {
	resp, err := self.send_apdu(0, GP_INS_SELECT, 0x04, 0, aid)
	return resp, err
}

func (self *scardYubiKey) send_apdu(cl byte, ins byte, p1 byte, p2 byte, data []byte) ([]byte, error) {
	card := self.card
	header := []byte{cl, ins, p1, p2, byte(len(data))}
	telegram := append(header, data...)

	fmt.Printf("sending: % 0x\n", telegram)

	rsp, err := card.Transmit(telegram)

	if err != nil {
		return rsp, err
	}

	fmt.Printf("received %d bytes: % 0x\n", len(rsp), rsp)

	chk_buffer := rsp[len(rsp)-2:]

	chk := binary.BigEndian.Uint16(chk_buffer)
	if chk != 0x9000 {
		return rsp, yubierror.ErrorChkWrong
	}

	rsp = rsp[:len(rsp)-2]
	return rsp, err
}

const SLOT_DEVICE_SERIAL byte = 0x10
const OTP_INS_YK2_REQ byte = 0x01

func (self *scardYubiKey) readSerial() (uint32, error) {
	resp, err := self.send_apdu(0, OTP_INS_YK2_REQ, SLOT_DEVICE_SERIAL, 0, []byte{})
	if err != nil {
		return 0, err
	}
	serial := binary.BigEndian.Uint32(resp)
	return serial, err
}

type Tlv struct {
	tag   byte
	value []byte
}

func (self *scardYubiKey) parseTlvs(response []byte) ([]Tlv, error) {
	var tlvs []Tlv
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

		tlvs = append(tlvs, tlv)
	}

	return tlvs, nil
}

func tlvsToMap(tlvs []Tlv) map[byte]Tlv {
	result := make(map[byte]Tlv)

	for _, tlv := range tlvs {
		result[tlv.tag] = tlv
	}

	return result
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
