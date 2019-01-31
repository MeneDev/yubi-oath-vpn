package main

import (
	"context"
	"fmt"
	"github.com/MeneDev/yubi-oath-vpn/oath/yubikey"
)

func main() {
	ctx := context.Background()
	monitor, _ := yubikey.UdevDeviceMonitorNew(ctx)

	events, _ := monitor.Monitor()

	for e := range events {
		msg := fmt.Sprintf(" Vendor=%d Product=%d", e.Vendor(), e.Product())

		switch e.Presence() {
		case yubikey.Present:
			println(e.Id() + msg + ": present")
		case yubikey.Removed:
			println(e.Id() + msg + ": removed")
		}
	}
}
