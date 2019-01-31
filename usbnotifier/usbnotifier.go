package usbnotifier

import "context"

type UsbDeviceEvent struct {
	id     string
	action string
}

type UsbNotifier interface {
	NotifyOn(ctx context.Context, eventChannel chan UsbDeviceEvent)
}
