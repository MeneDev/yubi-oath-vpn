package gui2

import (
	"context"
	"errors"

	"github.com/MeneDev/yubi-oath-vpn/yubierror"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	"github.com/gotk3/gotk3/glib"
	"github.com/looplab/fsm"
	"github.com/rs/zerolog/log"
)

const stateHidden = "stateHidden"
const statePrepare = "statePrepare"
const stateAskPass = "stateAskPass"
const stateConnecting = "stateConnecting"
const stateConnected = "stateConnected"

const evKeyRemoved = "evKeyRemoved"
const evKeyInserted = "evKeyInserted"
const evPasswordRequired = "evPasswordRequired"
const evPasswordNotRequired = "evPasswordNotRequired"
const evPasswordEntered = "evPasswordEntered"
const evWrongPassword = "evWrongPassword"
const evConnectionEstablished = "evConnectionEstablished"
const evConnectionError = "evConnectionError"
const evCancel = "evCancel"
const evDone = "evSuccess"

type eventData struct {
	event string
	args  []interface{}
}

func (ctrl *guiController) initFsm() {

	states := fsm.NewFSM(
		stateHidden,
		fsm.Events{
			{Name: evKeyRemoved, Src: []string{statePrepare, stateAskPass}, Dst: stateHidden},
			{Name: evKeyInserted, Src: []string{stateHidden}, Dst: statePrepare},
			{Name: evPasswordRequired, Src: []string{statePrepare}, Dst: stateAskPass},
			{Name: evPasswordNotRequired, Src: []string{statePrepare}, Dst: stateConnecting},
			{Name: evPasswordEntered, Src: []string{stateAskPass}, Dst: stateConnecting},
			{Name: evWrongPassword, Src: []string{stateConnecting}, Dst: stateAskPass},
			{Name: evConnectionEstablished, Src: []string{stateConnecting}, Dst: stateConnected},
			{Name: evConnectionError, Src: []string{stateConnecting}, Dst: stateAskPass},
			{Name: evCancel, Src: []string{stateAskPass, stateConnecting}, Dst: stateHidden},
			{Name: evDone, Src: []string{stateConnected}, Dst: stateHidden},
		},
		fsm.Callbacks{
			"enter_state": func(e *fsm.Event) {
				log.Info().Str("old", e.Src).Str("event", e.Event).Str("new", e.Dst).Msg("transitioning state")
			},
			"enter_" + stateHidden:     ctrl.enterHidden,
			"enter_" + statePrepare:    ctrl.enterPrepare,
			"enter_" + stateAskPass:    ctrl.enterAskPass,
			"enter_" + stateConnecting: ctrl.enterConnecting,
			"enter_" + stateConnected:  ctrl.enterConnected,
			"leave_" + stateHidden:     ctrl.leaveHidden,
			"leave_" + statePrepare:    ctrl.leavePrepare,
			"leave_" + stateAskPass:    ctrl.leaveAskPass,
			"leave_" + stateConnecting: ctrl.leaveConnecting,
			"leave_" + stateConnected:  ctrl.leaveConnected,
		},
	)

	ctrl.states = states
}

func (ctrl *guiController) enterHidden(e *fsm.Event) {
	ctrl.gtkGui.reset()
	ctrl.gtkGui.hide()
}
func (ctrl *guiController) leaveHidden(e *fsm.Event) {

}

func key(e *fsm.Event, idx int) yubikey.YubiKey {
	key := e.Args[idx].(yubikey.YubiKey)
	return key
}

func eventString(e *fsm.Event, idx int) string {
	str := e.Args[idx].(string)
	return str
}

func (ctrl *guiController) enterPrepare(e *fsm.Event) {
	key := key(e, 0)
	connectionId := eventString(e, 1)
	slotName := eventString(e, 2)
	//key.RequiresPassword()
	// TODO password required?
	glib.IdleAdd(func() {
		ctrl.gtkGui.btnConnect.SetSensitive(true)
	})

	ctrl.yubiKey = key
	ctrl.connectionId = connectionId
	ctrl.slotName = slotName
	ctrl.sendEvent(evPasswordRequired, key, connectionId)
}
func (ctrl *guiController) leavePrepare(e *fsm.Event) {

}

func (ctrl *guiController) enterAskPass(e *fsm.Event) {
	args := e.Args
	log.Debug().Interface("args", args).Msg("enterAskPass")
	ctrl.gtkGui.reset()
	if e.Event == evWrongPassword {
		ctrl.gtkGui.SetError(yubierror.ErrorWrongPassword)
	}
	if e.Event == evConnectionError {
		log.Error().Err(e.Err).Msg("enterAskPass evConnectionError")
		if args != nil && len(args) > 0 {
			message := args[0].(string)
			log.Debug().Str("error_message", message).Msg("setting GTK error message")
			ctrl.gtkGui.SetError(errors.New(message))
		} else {
			ctrl.gtkGui.SetError(errors.New("unknown Error"))
		}
	}

	ctrl.gtkGui.show()
	// e.Args contains error to show?
}

func (ctrl *guiController) leaveAskPass(e *fsm.Event) {
}

func (ctrl *guiController) enterConnecting(e *fsm.Event) {
	glib.IdleAdd(func() {
		ctrl.gtkGui.boxConnecting.SetVisible(true)
		ctrl.gtkGui.spnConnecting.Start()
		ctrl.gtkGui.lblConnect.SetLabel("Connecting...")
		ctrl.gtkGui.btnConnect.SetSensitive(false)
	})

	ctrl.gtkGui.HideError()

	password := e.Args[0].(string)
	code, err := ctrl.yubiKey.GetCodeWithPassword(password, ctrl.slotName)

	if err != nil {
		log.Error().Err(err).Msg("error getting code from yubikey")
		if err == yubierror.ErrorWrongPassword {
			ctrl.sendEvent(evWrongPassword)
		}

		// TODO: other cases
		return
	}

	log.Debug().Str("code", code).Msg("code from yubikey")

	ctx, cancel := context.WithCancel(context.Background())

	ctrl.cancelCurrentConnection = cancel
	ctrl.initializeConnectionChan <- ConnectionParameters{Context: ctx, ConnectionId: ctrl.connectionId, Code: code}
}

func (ctrl *guiController) leaveConnecting(e *fsm.Event) {
	glib.IdleAdd(func() {
		ctrl.gtkGui.boxConnecting.SetVisible(false)
		ctrl.gtkGui.spnConnecting.Stop()
		ctrl.gtkGui.lblConnect.SetText("")
	})

	if ctrl.cancelCurrentConnection != nil {
		ctrl.cancelCurrentConnection()
		ctrl.cancelCurrentConnection = nil
	}
}

func (ctrl *guiController) enterConnected(e *fsm.Event) {
	// TODO show indicator
	ctrl.sendEvent(evDone)
}
func (ctrl *guiController) leaveConnected(e *fsm.Event) {

}
