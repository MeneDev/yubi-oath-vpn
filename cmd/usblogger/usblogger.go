package main

import (
	"context"

	"github.com/MeneDev/yubi-oath-vpn/oath/yubikey"
	"github.com/rs/zerolog/log"
)

func main() {
	ctx := context.Background()
	monitor, _ := yubikey.UdevDeviceMonitorNew(ctx)

	events, _ := monitor.Monitor()

	for e := range events {
		evt := log.Debug().
			Str("device", e.Id()).
			Str("vendor", e.Vendor().String()).
			Str("product", e.Product().String())

		switch e.Presence() {
		case yubikey.Present:
			evt.Msg("device present")
		case yubikey.Removed:
			evt.Msg("device removed")
		}
	}
}
