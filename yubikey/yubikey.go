package yubikey

import "context"

type YubiKey interface {
	Context() context.Context
	GetCodeWithPassword(password string, slotName string) (string, error)
}
