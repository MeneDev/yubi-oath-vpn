package yubikey

import (
	"context"
	"fmt"

	"github.com/google/gousb"
	"github.com/jochenvg/go-udev"
)

const (
	_                      = iota
	Present DevicePresence = iota
	Removed DevicePresence = iota
)

type DeviceChangeEvent interface {
	Presence() DevicePresence
	Id() string
	Vendor() gousb.ID
	Product() gousb.ID
}

var _ DeviceChangeEvent = (*udevDeviceChangeEvent)(nil)

type udevDeviceChangeEvent struct {
	presence DevicePresence
	id       string
	vendor   gousb.ID
	product  gousb.ID
}

func (ev udevDeviceChangeEvent) Presence() DevicePresence {
	return ev.presence
}

func (ev udevDeviceChangeEvent) Id() string {
	return ev.id
}

func (ev udevDeviceChangeEvent) Vendor() gousb.ID {
	return ev.vendor
}

func (ev udevDeviceChangeEvent) Product() gousb.ID {
	return ev.product
}

type UsbDeviceMonitor interface {
	Monitor() (chan DeviceChangeEvent, error)
}

var _ UsbDeviceMonitor = (*udevDeviceMonitor)(nil)

type udevDeviceMonitor struct {
	ctx      context.Context
	inChanel <-chan *udev.Device

	knownDevices map[string]*gousb.DeviceDesc
	usbContext   *gousb.Context
	outChan      chan DeviceChangeEvent
	cancel       context.CancelFunc
}

func (mon *udevDeviceMonitor) Close() error {
	if mon.cancel != nil {
		mon.cancel()
	}

	if mon.usbContext != nil {
		return mon.usbContext.Close()
	}

	return nil
}

func (mon *udevDeviceMonitor) Monitor() (chan DeviceChangeEvent, error) {
	mon.outChan = make(chan DeviceChangeEvent)

	ch := mon.inChanel
	go func() {
		mon.checkDevices()

		//log.Debug().Msg("Started listening on statusChannel")
		for d := range ch {
			action := d.Action()

			if action == "add" || action == "remove" {
				mon.checkDevices()
			}
		}
	}()

	return mon.outChan, nil
}

func (mon *udevDeviceMonitor) checkDevices() error {
	usbContext := mon.usbContext
	outChan := mon.outChan

	foundDevices := make(map[string]*gousb.DeviceDesc)
	_, e := usbContext.OpenDevices(func(d *gousb.DeviceDesc) bool {
		id := fmt.Sprintf("%d.%d", d.Bus, d.Address)

		if _, known := foundDevices[id]; !known {
			foundDevices[id] = d
		}

		return false
	})

	if e != nil {
		return e
	}

	for k, d := range foundDevices {
		if _, known := mon.knownDevices[k]; !known {
			// new

			outChan <- udevDeviceChangeEvent{
				id:       k,
				presence: Present,
				vendor:   d.Vendor,
				product:  d.Product,
			}
		}
	}

	for k, d := range mon.knownDevices {
		if _, known := foundDevices[k]; !known {
			// removed

			outChan <- udevDeviceChangeEvent{
				id:       k,
				presence: Removed,
				vendor:   d.Vendor,
				product:  d.Product,
			}
		}
	}

	mon.knownDevices = foundDevices

	return nil
}

func UdevDeviceMonitorNew(ctx context.Context) (UsbDeviceMonitor, error) {

	ctx, cancel := context.WithCancel(ctx)

	u := udev.Udev{}
	m := u.NewMonitorFromNetlink("udev")

	// Add filters to monitor
	m.FilterAddMatchSubsystem("usb")

	ch, _ := m.DeviceChan(ctx)

	deviceMonitor := &udevDeviceMonitor{ctx: ctx, cancel: cancel, inChanel: ch, usbContext: gousb.NewContext()}

	return deviceMonitor, nil
}
