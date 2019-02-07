package yubimonitor

import (
	"context"
	"github.com/MeneDev/yubi-oath-vpn/scardmonitor"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	scardyubi "github.com/MeneDev/yubi-oath-vpn/yubikey/scard"
	"github.com/ebfe/scard"
	"log"
)

type InsertionEvent interface {
	Id() string
	Open() (yubikey.YubiKey, error)
}

var _ InsertionEvent = (*scardYubiMonitorInsertedEvent)(nil)

type scardYubiMonitorInsertedEvent struct {
	ctx      context.Context
	scardCtx *scard.Context
	id       string
}

func (s scardYubiMonitorInsertedEvent) Id() string {
	return s.id
}

func (s scardYubiMonitorInsertedEvent) Open() (yubikey.YubiKey, error) {
	log.Printf("Creating yubikey.YubiKey for device: %s", s.id)
	scardCtx, err := scard.EstablishContext()
	if err != nil {
		log.Printf("Creating yubikey.YubiKey for device %s: %s", s.id, err.Error())
	}
	return scardyubi.YubiKeyNew(s.ctx, scardCtx, s.id)
}

type YubiMonitor interface {
	InsertionChannel() <-chan InsertionEvent
}

func YubiMonitorNew(ctx context.Context) (YubiMonitor, error) {
	ctx, cancel := context.WithCancel(ctx)
	yubiMon := &yubiMonitor{ctx: ctx, cancel: cancel}

	scardMon, _ := scardmonitor.ScardMonNew(ctx)
	scardStatusChan := scardMon.StatusChannel()

	log.Printf("scardStatusChan: %v", scardStatusChan)

	yubiMon.insertedEvent = make(chan InsertionEvent)
	go func() {
		defer func() {
			log.Printf("Stopping YubiMonitor")
			cancel()
			close(yubiMon.insertedEvent)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case s := <-scardStatusChan:
				log.Printf("Reveiced: %v", s)
				if s.Presence() == scardmonitor.Available {
					yubiMon.insertedEvent <- scardYubiMonitorInsertedEvent{ctx: s.Context(), scardCtx: s.ScardContext(), id: s.Id()}
				}
			}
		}
	}()

	return yubiMon, nil
}

var _ YubiMonitor = (*yubiMonitor)(nil)

type yubiMonitor struct {
	ctx           context.Context
	cancel        context.CancelFunc
	insertedEvent chan InsertionEvent
}

func (y yubiMonitor) InsertionChannel() <-chan InsertionEvent {
	return y.insertedEvent
}

func (monitor yubiMonitor) handleScardEvent(event scardmonitor.ScardChangeEvent) {
	if event.Presence() == scardmonitor.Available {

	}
}
