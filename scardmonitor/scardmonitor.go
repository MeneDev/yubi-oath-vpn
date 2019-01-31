// +build linux windows

package scardmonitor

import "C"
import (
	"context"
	"github.com/ebfe/scard"
	"log"
	"time"
)

type ReaderPresence int

const (
	_                          = iota
	Available   ReaderPresence = iota
	Unavailable ReaderPresence = iota
)

type ScardChangeEvent interface {
	Presence() ReaderPresence
	Id() string
	ScardContext() *scard.Context
	Context() context.Context
}

var _ ScardChangeEvent = (*scardChangeEvent)(nil)

type scardChangeEvent struct {
	presence ReaderPresence
	id       string
	scardCtx *scard.Context
	ctx      context.Context
}

func (ev scardChangeEvent) Context() context.Context {
	return ev.ctx
}

func (ev scardChangeEvent) ScardContext() *scard.Context {
	return ev.scardCtx
}

func (ev scardChangeEvent) Presence() ReaderPresence {
	return ev.presence
}

func (ev scardChangeEvent) Id() string {
	return ev.id
}

type ScardMon interface {
	Close()
	StatusChannel() chan ScardChangeEvent
}

var _ ScardMon = (*scardMon)(nil)

type readyReaderInfo struct {
	reader string
	cancel context.CancelFunc
}
type scardMon struct {
	scardContext       *scard.Context
	scardContextErr    error
	readyReaders       map[string]readyReaderInfo
	ctx                context.Context
	cancel             context.CancelFunc
	readerPresenceChan chan ScardChangeEvent
	scardChangeCtx     *scard.Context
}

func (mon *scardMon) StatusChannel() chan ScardChangeEvent {
	return mon.readerPresenceChan
}

func (mon *scardMon) Close() {
	if mon.cancel != nil {
		mon.cancel()
	}
}

func ScardMonNew(ctx context.Context) ScardMon {
	ctx, cancel := context.WithCancel(ctx)

	mon := &scardMon{
		ctx:                ctx,
		cancel:             cancel,
		readerPresenceChan: make(chan ScardChangeEvent),
	}

	go func() {
		defer log.Printf("Stopping ScardMon")
		defer cancel()
		defer func() {
			log.Printf("Closing readerPresenceChan")
			close(mon.readerPresenceChan)
		}()

		scardCtx, err := scard.EstablishContext()
		if err != nil {
			log.Printf("Could not establish scard context, %s", err.Error())
			return
		} else {
			defer scardCtx.Cancel()
			defer scardCtx.Release()
		}
		scardChangeCtx, err := scard.EstablishContext()
		if err != nil {
			return
		} else {
			defer scardChangeCtx.Cancel()
			defer scardChangeCtx.Release()
		}

		mon.scardContext = scardCtx
		mon.scardChangeCtx = scardChangeCtx

		mon.updateStates()

		go func() {
			for {
				err := mon.waitAndUpdate()
				if err != nil {
					return
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return mon
}

func (mon *scardMon) updateStates() {
	ctx := mon.scardContext
	readers, _ := ctx.ListReaders()

	states := make([]scard.ReaderState, len(readers))
	for i := range states {
		states[i].Reader = readers[i]
		states[i].CurrentState = scard.StateUnaware
	}

	statusChanged := false
	for !statusChanged {
		readers, _ = ctx.ListReaders()

		states = make([]scard.ReaderState, len(readers))
		for i := range states {
			states[i].Reader = readers[i]
			states[i].CurrentState = scard.StateUnaware
		}

		func() {
			defer func() {
				// needed on windows
				recover()
			}()
			_ = ctx.GetStatusChange(states, 0)
			statusChanged = true
			time.Sleep(100 * time.Millisecond)
		}()
	}

	readersMap := make(map[string]readyReaderInfo)
	for _, state := range states {
		if state.EventState&scard.StatePresent != 0 {
			readersMap[state.Reader] = readyReaderInfo{reader: state.Reader}
		}
	}

	mon.updateReadyReaders(readersMap)
}

func (mon *scardMon) waitAndUpdate() error {
	ctx := mon.scardChangeCtx
	magicNotificationDevice := "\\\\?PnP?\\Notification"
	rs := append([]scard.ReaderState{}, scard.ReaderState{Reader: magicNotificationDevice, CurrentState: scard.StateUnaware})
	err := ctx.GetStatusChange(rs, -1)
	log.Printf("waitAndUpdate detected a change")
	mon.updateStates()
	return err
}

func (mon *scardMon) updateReadyReaders(newReadyReaders map[string]readyReaderInfo) {
	for k, s := range newReadyReaders {
		if _, known := mon.readyReaders[k]; !known {
			// new

			ctx, cancel := context.WithCancel(mon.ctx)
			s.cancel = cancel

			newReadyReaders[k] = s
			log.Printf("Send available")
			mon.readerPresenceChan <- scardChangeEvent{
				id:       s.reader,
				presence: Available,
				scardCtx: mon.scardContext,
				ctx:      ctx,
			}
		}
	}

	for k, s := range mon.readyReaders {
		if _, known := newReadyReaders[k]; !known {
			// removed

			log.Printf("Send removed")
			mon.readerPresenceChan <- scardChangeEvent{
				id:       s.reader,
				presence: Unavailable,
				scardCtx: mon.scardContext,
			}
			s.cancel()
		}
	}

	mon.readyReaders = newReadyReaders
}
