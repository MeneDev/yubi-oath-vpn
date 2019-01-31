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

	discoverer, _ := yubikey.YubiReaderDiscovererNew(ctx, events)

	channel, _ := discoverer.StatusChannel()

	for v := range channel {
		fmt.Printf("%s: %#v\n", v.Id(), v.Availability())
	}
}
