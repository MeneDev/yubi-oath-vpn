package oath

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"reflect"
	"testing"
)

func TestChallenge(t *testing.T) {
	// ch: D3 47 6C C6 00 52 4A 5C
	ch := []byte{0xD3, 0x47, 0x6C, 0xC6, 0x00, 0x52, 0x4A, 0x5C}
	// pwd: abc
	pwd := "abc"

	salt := []byte{0x5b, 0x1c, 0xcc, 0x20, 0xd4, 0xab, 0x2f, 0xdf}

	key := pbkdf2.Key([]byte(pwd), salt, 1000, 16, sha1.New)

	// resp: 55 C0 1A 95 A6 8F BD 54 4A AF 4A 4A 51 52 5B 91 F2 6A 39 8B

	h := hmac.New(sha1.New, key)
	h.Write(ch)
	response := h.Sum(nil)

	fmt.Printf("% 0x\n", response)
	fmt.Println(len(response))

	expected_response := []byte{0x55, 0xC0, 0x1A, 0x95, 0xA6, 0x8F, 0xBD, 0x54, 0x4A, 0xAF, 0x4A, 0x4A, 0x51, 0x52, 0x5B, 0x91, 0xF2, 0x6A, 0x39, 0x8B}

	if !reflect.DeepEqual(response, expected_response) {
		t.Errorf("Expected\n% 0x\nbut was\n% 0x", response, expected_response)
	}
}
