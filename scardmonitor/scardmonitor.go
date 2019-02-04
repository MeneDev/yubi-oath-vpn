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

func ScardMonNew(ctx context.Context) (ScardMon, error) {
	ctx, cancel := context.WithCancel(ctx)

	mon := &scardMon{
		ctx:                ctx,
		cancel:             cancel,
		readerPresenceChan: make(chan ScardChangeEvent),
	}

	scardCtx, err := scard.EstablishContext()
	if err != nil {
		log.Printf("Could not establish scard context, %s", err.Error())
		return nil, err
	}

	scardChangeCtx, err := scard.EstablishContext()
	if err != nil {
		defer func() {
			scardCtx.Cancel()
			scardCtx.Release()
		}()

		log.Printf("Could not establish scard context, %s", err.Error())
		return nil, err
	}

	mon.scardContext = scardCtx
	mon.scardChangeCtx = scardChangeCtx

	go func() {
		defer func() {
			scardCtx.Cancel()
			scardCtx.Release()
		}()
		defer func() {
			scardChangeCtx.Cancel()
			scardChangeCtx.Release()
		}()
		defer log.Printf("Stopping ScardMon")
		defer cancel()
		defer func() {
			log.Printf("Closing readerPresenceChan")
			close(mon.readerPresenceChan)
		}()

		mon.updateStates()

		//go func() {
		//	for {
		//		err := mon.waitAndUpdate()
		//		if err != nil {
		//			return
		//		}
		//	}
		//}()

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return mon, nil
}

func (mon *scardMon) updateStates() {
	ctx := mon.scardContext
	readers, _ := ctx.ListReaders()

	states := make([]scard.ReaderState, len(readers))

	magicNotificationDevice := "\\\\?PnP?\\Notification"

	for i := range states {
		states[i].Reader = readers[i]
		states[i].CurrentState = scard.StateUnaware
	}

	states = append(states, scard.ReaderState{
		Reader:       magicNotificationDevice,
		CurrentState: scard.StateUnaware,
	})

	for {
		log.Printf("Start GetStatusChange with %d readers", len(states))
		log.Printf("%#v", states)
		err := ctx.GetStatusChange(states, -1)
		if err != nil {
			log.Printf("GetStatusChange error: %s", err.Error())
		}

		if err != nil {
			log.Printf("EstablishContext")

			// TODO remove all cards
			ctx, err = scard.EstablishContext()
			if err != nil {
				log.Printf("EstablishContext error: %s", err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		log.Printf("Finish GetStatusChange with %d readers", len(states))
		log.Printf("%#v", states)

		for i := range states {
			states[i].CurrentState = states[i].EventState
			states[i].EventState = scard.StateUnaware
			states[i].Atr = nil
		}

		//readers, _ := ctx.ListReaders()

		//magicNotificationDevice := "\\\\?PnP?\\Notification"

		//readersMap := make(map[string]readyReaderInfo)
		//for _, state := range states {
		//	if state.EventState&scard.StatePresent != 0 {
		//		readersMap[state.Reader] = readyReaderInfo{reader: state.Reader}
		//	}
		//}

		//log.Printf("readersMap: %v", readersMap)

		//readers, _ = ctx.ListReaders()
		//states := make([]scard.ReaderState, len(readers))
		//for i := range states {
		//	states[i].Reader = readers[i]
		//	states[i].CurrentState = scard.StateUnaware
		//	if _, ok := readersMap[readers[i]]; ok {
		//		states[i].CurrentState = scard.StatePresent
		//		log.Printf("Reader %s is known", readers[i])
		//	} else {
		//		log.Printf("Reader %s is unknown", readers[i])
		//	}
		//}
		//
		//states = append(states, scard.ReaderState{
		//	Reader: magicNotificationDevice,
		//	CurrentState: scard.StateUnaware,
		//})

	}

	statusChanged := false
	for !statusChanged {
		readers, _ = ctx.ListReaders()

		states = make([]scard.ReaderState, len(readers))
		for i := range states {
			states[i].Reader = readers[i]
			states[i].CurrentState = scard.StateUnaware
			if _, ok := mon.readyReaders[readers[i]]; ok {
				states[i].CurrentState = scard.StatePresent
			}
		}

		func() {
			defer func() {
				// needed on windows
				recData := recover()
				if recData != nil {
					log.Printf("GetStatusChange recover: %v", recData)
				}
			}()

			if len(states) > 0 {
				log.Printf("Start GetStatusChange with %d readers", len(states))
				err := ctx.GetStatusChange(states, -1)
				if err != nil {
					log.Printf("GetStatusChange error: %s", err.Error())
				}
				log.Printf("Finish GetStatusChange with %d readers", len(states))
			}
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
	log.Printf("Start GetStatusChange with pseudo device")
	err := ctx.GetStatusChange(rs, -1)
	log.Printf("Finish GetStatusChange with pseudo device")
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
