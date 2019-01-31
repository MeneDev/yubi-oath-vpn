package yubikey

import "context"

type YubiKey interface {
	Context() context.Context
	GetCodeWithPassword(password string) (string, error)
}
