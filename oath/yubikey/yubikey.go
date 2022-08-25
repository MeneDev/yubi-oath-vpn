package yubikey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MeneDev/yubi-oath-vpn/oath"
	"github.com/MeneDev/yubi-oath-vpn/yubierror"
	"github.com/ebfe/scard"
	"github.com/google/gousb"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"
)

type yubiKeyReader struct {
	card     scard.Card
	tlvs     []Tlv
	scardCtx *scard.Context
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

func (self yubiKeyReader) send_apdu(cl byte, ins byte, p1 byte, p2 byte, data []byte) ([]byte, error) {
	card := self.card
	header := []byte{cl, ins, p1, p2, byte(len(data))}
	telegram := append(header, data...)

	log.Debug().Hex("value", telegram).Msg("sending apdu")

	rsp, err := card.Transmit(telegram)

	if err != nil {
		return rsp, err
	}

	log.Debug().Hex("value", rsp).Msg("received response")

	chk_buffer := rsp[len(rsp)-2:]

	chk := binary.BigEndian.Uint16(chk_buffer)
	if chk != 0x9000 {
		return rsp, yubierror.ErrorChkWrong
	}

	rsp = rsp[:len(rsp)-2]
	return rsp, err
}

var GP_INS_SELECT byte = 0xA4

func (self yubiKeyReader) selectAid(aid AID) ([]byte, error) {
	resp, err := self.send_apdu(0, GP_INS_SELECT, 0x04, 0, aid)
	return resp, err
}

var SLOT_DEVICE_SERIAL byte = 0x10
var OTP_INS_YK2_REQ byte = 0x01

func (self yubiKeyReader) readSerial() (uint32, error) {
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

func (self yubiKeyReader) parseTlvs(response []byte) (map[byte]Tlv, error) {
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

func (yubikey yubiKeyReader) getCode(pwd string) (string, error) {
	scardCtx := yubikey.scardCtx

	log.Debug().Msg("ListReaders... ")
	// List available readers
	readers, err := scardCtx.ListReaders()
	if err != nil {
		log.Error().Err(err).Msg("ListReaders failed")
		return "", err
	}
	log.Debug().Msg("done")

	// Use the first reader with "yubi" in its name
	var reader string
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), "yubi") {
			reader = r
			break
		}
	}

	log.Debug().Msg("using reader " + reader)

	// Connect to the card
	card, err := scardCtx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		log.Error().Err(err).Msg("error connecting to card")
		return "", err
	}

	// Disconnect (when needed)
	defer card.Disconnect(scard.LeaveCard)

	rsp, err := yubikey.selectAid(AID_OTP)
	if err != nil {
		log.Error().Err(err).Msg("Error setting 'AID_OTP'")
		return "", err
	}

	serial, err := yubikey.readSerial()
	if err != nil {
		log.Error().Err(err).Msg("Error reading serial")
		return "", err
	}

	log.Debug().
		Uint32("serial", serial).
		Hex("rsp", rsp).
		Msg("serial")

	rsp_mgr, err := yubikey.selectAid(AID_MGR)
	if err != nil {
		return "", err
	}

	log.Debug().Hex("value", rsp_mgr).Msg("rsp_oath")

	var cmd_3 = []byte{0x00, 0x1D, 0x00, 0x00, 0x00}
	rsp_3, err := card.Transmit(cmd_3)
	if err != nil {
		log.Error().Err(err).Msg("error transmitting")
		return "", err
	}
	log.Debug().Hex("value", rsp_3).Msg("rsp_3")

	resp_oath, err := yubikey.selectAid(AID_OATH)
	if err != nil {
		log.Error().Err(err).Msg("Error setting 'AID_OATH'")
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

	log.Debug().
		Uint64("name_id", name).
		Hex("raw_name", tlvs[OATH_TAG_NAME].value).
		Hex("algorithm", tlvs[OATH_TAG_ALGORITHM].value).
		Hex("version", tlvs[OATH_TAG_VERSION].value).
		Msg("response")

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
	if err, ok := err.(yubierror.YubiKeyError); ok && err == yubierror.ErrorChkWrong {
		if bytes.Equal(verify_resp, []byte{0x6A, 0x80}) {
			return "", yubierror.ErrorWrongPassword
		}
	}
	if err != nil {
		return "", err
	}

	verify_tlvs, err := yubikey.parseTlvs(verify_resp)
	if err != nil {
		return "", err
	}

	log.Debug().
		Hex("expected", verification).
		Hex("received", verify_tlvs[OATH_TAG_RESPONSE].value).
		Msg("verification")

	if !bytes.Equal(verification, verify_tlvs[OATH_TAG_RESPONSE].value) {
		panic("Verification failed")
	}

	var cmd_5 = []byte{0x00, byte(CALCULATE_ALL), 0x00, 0x01, 0x0A, 0x74, 0x08}

	timeBuffer := make([]byte, 8)

	binary.BigEndian.PutUint64(timeBuffer, uint64(time.Now().UTC().Unix()/30))

	cmd_5 = append(cmd_5, timeBuffer...)

	rsp_5, err := card.Transmit(cmd_5)
	if err != nil {
		log.Error().Err(err).Msg("error transmitting")
		return "", err
	}
	log.Debug().Hex("value", rsp_5).Msg("rsp_5")

	creds_tlvs, err := yubikey.parseTlvs(rsp_5)
	if err != nil {
		log.Error().Err(err).Msg("error parsing TLVs")
		return "", err
	}

	TRUNCATED_RESPONSE := byte(0x76)

	code := parseTruncated(creds_tlvs[TRUNCATED_RESPONSE].value[1:])

	log.Debug().Hex("raw_code", creds_tlvs[TRUNCATED_RESPONSE].value).Uint32("code", code).Msg("code message received")

	strCode := fmt.Sprintf("%06d", code)

	return strCode, err
}

type DevicePresence int

type UsbEvent struct {
}

type UsbMonitor interface {
}

var _ oath.ReaderDiscoverer = (*yubiReaderDiscoverer)(nil)

func YubiReaderDiscovererNew(ctx context.Context, eventChanel chan DeviceChangeEvent) (oath.ReaderDiscoverer, error) {
	discoverer := &yubiReaderDiscoverer{ctx: ctx, eventChanel: eventChanel, initialized: 0}
	return discoverer, nil
}

type yubiReaderDiscoverer struct {
	ctx           context.Context
	statusChannel chan oath.ReaderStatus
	initialized   int32
	eventChanel   chan DeviceChangeEvent
}

func (discoverer *yubiReaderDiscoverer) StatusChannel() (chan oath.ReaderStatus, error) {
	if atomic.CompareAndSwapInt32(&discoverer.initialized, 0, 1) {
		ctx, cancel := context.WithCancel(discoverer.ctx)

		discoverer.statusChannel = make(chan oath.ReaderStatus)

		go func() {
			defer cancel()
			defer close(discoverer.statusChannel)

			for {
				select {
				case <-ctx.Done():
					discoverer.Close()
					break
				case ev := <-discoverer.eventChanel:
					discoverer.checkYubi(ev)
				}
			}
		}()

		return discoverer.statusChannel, nil
	}

	return nil, errors.New("called StatusChannel twice")
}

func (discoverer *yubiReaderDiscoverer) Close() {

}

var _ oath.ReaderStatus = (*YubikeyReaderStatus)(nil)

type YubikeyReaderStatus struct {
	presence oath.ReaderPresence
	id       string
}

func (yrs YubikeyReaderStatus) Availability() oath.ReaderPresence {
	return yrs.presence
}

func (yrs YubikeyReaderStatus) Id() string {
	return yrs.id
}

func (YubikeyReaderStatus) Get() oath.Reader {
	panic("implement me")
}

func (discoverer *yubiReaderDiscoverer) checkYubi(event DeviceChangeEvent) {
	vendor := gousb.ID(0x1050)
	product := gousb.ID(0x0407)

	if event.Vendor() == vendor && event.Product() == product {
		presence := oath.Available
		if event.Presence() == Removed {
			presence = oath.Unavailable
		}

		discoverer.statusChannel <- &YubikeyReaderStatus{
			presence: presence,
			id:       event.Id(),
		}
	}
}
