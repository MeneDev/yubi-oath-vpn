package gui2

import (
	"context"

	"github.com/MeneDev/yubi-oath-vpn/githubreleasemon"
	"github.com/MeneDev/yubi-oath-vpn/netctrl"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"
	"github.com/looplab/fsm"
	"github.com/rs/zerolog/log"
)

type ConnectionParameters struct {
	ConnectionId string
	Code         string
	Context      context.Context
}

type GuiController interface {
	ConnectWith(key yubikey.YubiKey, connectionId string, slotName string)
	InitializeConnection() chan ConnectionParameters
	ConnectionResult(events netctrl.ConnectionAttemptResult)
	SetLatestVersion(release githubreleasemon.Release)
}

type guiController struct {
	states                   *fsm.FSM
	ctx                      context.Context
	cancel                   context.CancelFunc
	eventInChan              chan eventData
	gtkGui                   *gtkGui
	yubiKey                  yubikey.YubiKey
	initializeConnectionChan chan ConnectionParameters
	connectionId             string
	slotName                 string
	cancelCurrentConnection  context.CancelFunc
}

func (ctrl *guiController) SetLatestVersion(release githubreleasemon.Release) {
	ctrl.gtkGui.SetVersion(release)
}

func (ctrl *guiController) ConnectionResult(event netctrl.ConnectionAttemptResult) {
	if event.Success() {
		ctrl.sendEvent(evConnectionEstablished)
	} else {
		log.Error().Str("error", event.String()).Msg("evConnectionError error")
		ctrl.sendEvent(evConnectionError, event.String())
	}
}

func (ctrl *guiController) InitializeConnection() chan ConnectionParameters {
	return ctrl.initializeConnectionChan
}

var _ GuiController = (*guiController)(nil)

func GuiControllerNew(ctx context.Context, title string) (GuiController, error) {

	ctx, cancel := context.WithCancel(ctx)
	controller := &guiController{ctx: ctx, cancel: cancel}

	handlers := eventHandlers{
		onDestroy:           controller.onDestroy,
		onBtnConnectClicked: controller.onBtnConnectClicked,
		onPasswordKeyPress:  controller.onPasswordKeyPress,
		onWinKeyPress:       controller.onWinKeyPress,
		onBtnCancelClicked:  controller.onBtnCancelClicked,
	}

	gtkGui, e := gtkGuiNew(ctx, title, handlers)
	if e != nil {
		cancel()
		return nil, e
	}

	controller.gtkGui = gtkGui
	controller.initFsm()

	controller.initializeConnectionChan = make(chan ConnectionParameters)
	controller.eventInChan = make(chan eventData)
	go func() {
		defer cancel()
		defer close(controller.initializeConnectionChan)
		defer close(controller.eventInChan)
		defer log.Debug().Msg("gui controller done")

		for {

			log.Debug().Msg("GUI waiting for events")
			select {
			case <-ctx.Done():
				break
			case ev := <-controller.eventInChan:
				log.Debug().Msg("received")
				controller.dispatchEvent(ev)
				log.Debug().Msg("/received")
			}
			log.Debug().Msg("processed")
		}
	}()
	return controller, nil
}

func (ctrl *guiController) ConnectWith(key yubikey.YubiKey, connectionId string, slotName string) {
	log.Debug().Msg("ConnectWith")
	ctrl.sendEvent(evKeyInserted, key, connectionId, slotName)
	go func() {
		<-key.Context().Done()

		ctrl.sendEvent(evKeyRemoved, key)
	}()
}

func (ctrl *guiController) onDestroy() {
	ctrl.sendEvent(evCancel)
}

func (ctrl *guiController) onWinKeyPress(win *gtk.Window, ev *gdk.Event) {
	keyEvent := &gdk.EventKey{ev}

	if keyEvent.KeyVal() == gdk.KEY_Escape {
		ctrl.sendEvent(evCancel)
	}
}

func (ctrl *guiController) onPasswordKeyPress(entry *gtk.Entry, ev *gdk.Event) {
	keyEvent := &gdk.EventKey{ev}

	if keyEvent.KeyVal() == gdk.KEY_Return {

		text, _ := entry.GetText()
		ctrl.sendEvent(evPasswordEntered, text)
	}
}

func (ctrl *guiController) onBtnConnectClicked(ev *gtk.Button) {
	text, _ := ctrl.gtkGui.txtPassword.GetText()
	ctrl.sendEvent(evPasswordEntered, text)
}

func (ctrl *guiController) onBtnCancelClicked(ev *gtk.Button) {
	ctrl.sendEvent(evCancel)
}

func (ctrl *guiController) sendEvent(event string, args ...interface{}) {
	log.Debug().Msg("sendEvent")
	data := eventData{event: event, args: args}
	go func() {
		ctrl.eventInChan <- data
		log.Debug().Msg("/sendEvent")
	}()
}

func (ctrl *guiController) dispatchEvent(ev eventData) {
	log.Debug().Msg("dispatchEvent")
	err := ctrl.states.Event(ev.event, ev.args...)
	if err != nil {
		log.Error().Err(err).Msg("dispatchEvent error")
	}
}
