package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

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

func NewBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	//
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
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

func Decrypt(data []byte, entropy []byte) ([]byte, error) {
	var outblob DataBlob
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, uintptr(unsafe.Pointer(NewBlob(entropy))), 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func main() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\OpenVPN-GUI\configs\client`, registry.QUERY_VALUE|registry.WRITE)
	if err != nil {
		log.Fatal().Err(err).Int("state", 1).Msg("error")
	}
	defer k.Close()

	entropy, _, err := k.GetBinaryValue("entropy")
	if err != nil {
		log.Fatal().Err(err).Int("state", 2).Msg("error")
	}
	entropy = entropy[:len(entropy)-1]

	authData, _, err := k.GetBinaryValue("auth-data")
	if err != nil {
		log.Fatal().Err(err).Int("state", 3).Msg("error")
	}

	encData, err := Decrypt(authData, entropy)
	log.Debug().Hex("entropy", entropy).Hex("auth-data", authData).Hex("enc-data", encData).Msg("")

	out := make([]uint16, len(encData)/2)
	err = binary.Read(bytes.NewReader(encData), binary.LittleEndian, out)
	if err != nil {
		log.Fatal().Err(err).Int("state", 5).Msg("error")
	}

	s := windows.UTF16ToString(out)
	if err != nil {
		log.Fatal().Err(err).Int("state", 4).Msg("error")
	}

	fmt.Printf("encData=%s\n", s)

	code := "123456"

	utfCode, err := windows.UTF16FromString(code)

	buffer := bytes.NewBuffer(nil)

	err = binary.Write(buffer, binary.LittleEndian, utfCode)
	if err != nil {
		log.Fatal().Err(err).Int("state", 5).Msg("error")
	}

	byteCode := buffer.Bytes()
	encrypt, err := Encrypt(byteCode, entropy)
	if err != nil {
		log.Fatal().Err(err).Int("state", 6).Msg("error")
	}

	err = k.SetBinaryValue("auth-data", encrypt)
	if err != nil {
		log.Fatal().Err(err).Int("state", 7).Msg("error")
	}

}
