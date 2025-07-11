package scardmonitor

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/ebfe/scard"
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
				log.Warn().Err(errCancel).Msg("Could not cancel scard context")
			}
			errRelease := ctx.Release()
			if errRelease != nil {
				log.Warn().Err(errRelease).Msg("Could not release scard context")
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
				log.Warn().Err(err).Msg("Could not establish scard context")
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if deviceListOutdated {
			var err error
			log.Info().Msg("Listing scard readers")
			readers, err = ctx.ListReaders()
			if err != nil && err != scard.ErrNoReadersAvailable {
				log.Error().Err(err).Msg("Could not list scard readers, assuming broken context")
				contextBroken = true
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				deviceListOutdated = false

				for _, reader := range readers {
					if _, ok := listedReaders[reader]; !ok {
						log.Info().Str("reader", reader).Msg("Start observing scard reader")
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

		log.Debug().Msg("Start GetStatusChange with " + readersString(states))
		err := ctx.GetStatusChange(states, -1)
		if err != nil {
			log.Warn().Err(err).Msg("GetStatusChange error")
			if err == scard.ErrUnknownReader {
				deviceListOutdated = true
				continue
			}
		}

		log.Debug().Msg("Finish GetStatusChange with " + readersString(states))

		pseudoDevice := states[0]
		if pseudoDevice.EventState&scard.StateChanged != 0 {
			log.Debug().Msg("Pseudo device reported change")
			deviceListOutdated = true
		}

		updatedStates := make([]scard.ReaderState, 0)

		for i := range states {
			state := states[i]

			if (state.EventState & ^scard.StateChanged) != state.CurrentState {
				log.Debug().
					Str("old", formatStateFlags(state.CurrentState)).
					Str("new", formatStateFlags(state.EventState & ^scard.StateChanged)).
					Str("reader", state.Reader).
					Msg("Reader state changed")
			}

			if state.CurrentState&scard.StatePresent == 0 && state.EventState&scard.StatePresent != 0 {
				log.Info().Str("reader", state.Reader).Msg("Reader became available")

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
				log.Info().Str("reader", state.Reader).Msg("Reader removed")
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
	log.Debug().Msg("Start GetStatusChange with pseudo device")
	err := ctx.GetStatusChange(rs, -1)
	log.Debug().Msg("Finish GetStatusChange with pseudo device")
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
			log.Debug().Msg("Send available")
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

			log.Debug().Msg("Send removed")
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
