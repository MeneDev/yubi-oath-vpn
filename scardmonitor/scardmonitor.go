// +build linux windows

package scardmonitor

import "C"
import (
	"context"
	"github.com/ebfe/scard"
	"log"
	"strings"
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

	go func() {
		mon.updateLoop()
	}()

	go func() {
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

func (mon *scardMon) updateLoop() {
	var readers []string

	readerStates := make([]scard.ReaderState, 0)

	magicNotificationDevice := "\\\\?PnP?\\Notification"

	listedReaders := make(map[string]int)
	for i := range readerStates {
		listedReaders[readers[i]] = i
		readerStates[i].Reader = readers[i]
		readerStates[i].CurrentState = scard.StateUnaware
	}

	states := []scard.ReaderState{{
		Reader:       magicNotificationDevice,
		CurrentState: scard.StateUnaware,
	}}

	var ctx *scard.Context

	safeCloseContext := func() {
		if ctx != nil {
			errCancel := ctx.Cancel()
			if errCancel != nil {
				log.Printf("Could not cancel scard context: %s", errCancel.Error())
			}
			errRelease := ctx.Release()
			if errRelease != nil {
				log.Printf("Could not release scard context: %s", errRelease.Error())
			}
		}
	}

	go func() {
		<-mon.ctx.Done()
		safeCloseContext()
	}()

	contextBroken := false
	deviceListOutdated := true

	for {
		select {
		case <-mon.ctx.Done():
			break
		default:
		}

		if contextBroken {
			safeCloseContext()
			contextBroken = false
			ctx = nil
		}

		if ctx == nil {
			var err error
			ctx, err = scard.EstablishContext()
			if err != nil {
				log.Printf("Could not establish scard context: %s", err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if deviceListOutdated {
			var err error
			log.Printf("Listing scard readers")
			readers, err = ctx.ListReaders()
			if err != nil {
				log.Printf("Could not list scard readers: %s", err.Error())
				log.Printf("Assuming broken context")
				contextBroken = true
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				deviceListOutdated = false

				for _, reader := range readers {
					if _, ok := listedReaders[reader]; !ok {
						log.Printf("Start observing scard reader %s", reader)
						listedReaders[reader] = len(states)
						states = append(states, scard.ReaderState{
							Reader:       reader,
							CurrentState: scard.StateUnaware,
							EventState:   scard.StateUnaware,
						})
					}
				}
			}
		}

		log.Printf("Start GetStatusChange with %s", readersString(states))
		err := ctx.GetStatusChange(states, -1)
		if err != nil {
			log.Printf("GetStatusChange error: %s", err.Error())
			if err == scard.ErrUnknownReader {
				deviceListOutdated = true
				continue
			}
		}

		log.Printf("Finish GetStatusChange with %s", readersString(states))

		pseudoDevice := states[0]
		if pseudoDevice.EventState&scard.StateChanged != 0 {
			log.Printf("Pseudo device reported change")
			deviceListOutdated = true
		}

		updatedStates := make([]scard.ReaderState, 0)

		for i := range states {
			state := states[i]

			if (state.EventState & ^scard.StateChanged) != state.CurrentState {
				log.Printf("Reader %s changed from (%s) to (%s)", state.Reader, formatStateFlags(state.CurrentState), formatStateFlags(state.EventState & ^scard.StateChanged))
			}

			if state.CurrentState&scard.StatePresent == 0 && state.EventState&scard.StatePresent != 0 {
				log.Printf("Reader %s became available", state.Reader)

				cancelCtx, cancel := context.WithCancel(mon.ctx)
				state.UserData = cancel

				mon.readerPresenceChan <- scardChangeEvent{
					id:       state.Reader,
					presence: Available,
					scardCtx: ctx,
					ctx:      cancelCtx,
				}
			}

			removed := false
			if state.CurrentState&scard.StatePresent != 0 && state.EventState&scard.StatePresent == 0 {
				log.Printf("Reader %s removed", state.Reader)
				removed = true
				//mon.readerPresenceChan <- scardChangeEvent{
				//	id:       state.Reader,
				//	presence: Unavailable,
				//	scardCtx: ctx,
				//	ctx:      mon.ctx,
				//}

				cancel := state.UserData.(context.CancelFunc)
				cancel()
			}

			state.CurrentState = state.EventState & ^scard.StateChanged
			state.EventState = scard.StateUnaware
			state.Atr = nil

			if !removed {
				updatedStates = append(updatedStates, state)
			} else {
				delete(listedReaders, state.Reader)
			}
		}

		states = updatedStates
	}
}

func readersString(states []scard.ReaderState) string {
	readers := make([]string, 0)
	for _, s := range states {
		readers = append(readers, s.Reader)
	}
	return strings.Join(readers, ", ")
}

func formatStateFlags(flags scard.StateFlag) string {

	allFlags := map[scard.StateFlag]string{
		scard.StateUnaware:     "StateUnaware",
		scard.StateIgnore:      "StateIgnore",
		scard.StateChanged:     "StateChanged",
		scard.StateUnknown:     "StateUnknown",
		scard.StateUnavailable: "StateUnavailable",
		scard.StateEmpty:       "StateEmpty",
		scard.StatePresent:     "StatePresent",
		scard.StateAtrmatch:    "StateAtrmatch",
		scard.StateExclusive:   "StateExclusive",
		scard.StateInuse:       "StateInuse",
		scard.StateMute:        "StateMute",
		scard.StateUnpowered:   "StateUnpowered",
	}
	usedFlagNames := make([]string, 0)
	for f, s := range allFlags {
		if flags&f != 0 || (flags == f) {
			usedFlagNames = append(usedFlagNames, s)
		}
	}

	return strings.Join(usedFlagNames, " | ")
}

func (mon *scardMon) waitAndUpdate() error {
	ctx := mon.scardChangeCtx
	magicNotificationDevice := "\\\\?PnP?\\Notification"
	rs := append([]scard.ReaderState{}, scard.ReaderState{Reader: magicNotificationDevice, CurrentState: scard.StateUnaware})
	log.Printf("Start GetStatusChange with pseudo device")
	err := ctx.GetStatusChange(rs, -1)
	log.Printf("Finish GetStatusChange with pseudo device")
	mon.updateLoop()
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
