package gui2

import (
	"context"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"runtime"
	"sync"
)

type gtkGui struct {
	ctx            context.Context
	wgInit         sync.WaitGroup
	win            *gtk.Window
	lblConnect     *gtk.Label
	spnConnecting  *gtk.Spinner
	btnConnect     *gtk.Button
	txtPassword    *gtk.Entry
	cancel         context.CancelFunc
	boxError       *gtk.Box
	txtError       *gtk.TextBuffer
	boxConnecting  *gtk.Box
	boxErrorHeader *gtk.Box
	btnCancel      *gtk.Button
	boxRoot        *gtk.Box
}

func (g gtkGui) hide() {
	glib.IdleAdd(func() {
		g.win.Hide()
	})
}

func (g gtkGui) show() {
	glib.IdleAdd(func() {
		g.win.ShowAll()
		g.win.Present()
		g.win.SetKeepAbove(true)
		g.win.GrabFocus()
	})
}

func (g gtkGui) _reset() {
	g.boxConnecting.SetVisible(false)
	g.spnConnecting.Stop()
	g.btnConnect.SetSensitive(true)

	g.txtPassword.SetText("")

	g.boxRoot.Remove(g.boxError)
}

func (g gtkGui) reset() {
	glib.IdleAdd(func() {
		g._reset()
	})
}

func (g gtkGui) SetError(err error) {
	glib.IdleAdd(func() {
		g.spnConnecting.Stop()
		g.lblConnect.SetText("")

		g.txtError.SetText(err.Error())

		g.boxRoot.Add(g.boxError)
	})
}

func (g gtkGui) HideError() {
	glib.IdleAdd(func() {
		g.boxRoot.Remove(g.boxError)
	})
}

type eventHandlers struct {
	onDestroy           func()
	onWinKeyPress       func(win *gtk.Window, ev *gdk.Event)
	onPasswordKeyPress  func(win *gtk.Entry, ev *gdk.Event)
	onBtnConnectClicked func(btn *gtk.Button)
	onBtnCancelClicked  func(btn *gtk.Button)
}

func gtkGuiNew(ctx context.Context, handlers eventHandlers) (*gtkGui, error) {
	ctx, cancel := context.WithCancel(ctx)
	g := &gtkGui{ctx: ctx, cancel: cancel}

	errCh := make(chan error)

	go func() {
		runtime.LockOSThread()

		// Initialize GTK without parsing any command line arguments.
		gtk.Init(nil)

		//builder, err := gtk.BuilderNewFromFile("/home/marndt/go/src/github.com/MeneDev/yubi-oath-vpn/ConnectDialog.gtk")
		builder, err := gtk.BuilderNew()

		if err != nil {
			errCh <- err
			return
		}

		err = builder.AddFromString(gtkGuiString)
		if err != nil {
			errCh <- err
			return
		}

		objDlg, err := builder.GetObject("Dialog")
		if err != nil {
			errCh <- err
			return
		}
		win := objDlg.(*gtk.Window)
		win.SetTitle("Yubi Monitor")

		objPassword, err := builder.GetObject("txtPassword")
		if err != nil {
			errCh <- err
			return
		}

		txtPassword := objPassword.(*gtk.Entry)
		txtPassword.SetInputPurpose(gtk.INPUT_PURPOSE_PASSWORD)
		txtPassword.SetVisibility(false)

		objConnect, err := builder.GetObject("btnConnect")
		if err != nil {
			errCh <- err
			return
		}

		btnConnect := objConnect.(*gtk.Button)

		objCancel, err := builder.GetObject("btnCancel")
		if err != nil {
			errCh <- err
			return
		}

		btnCancel := objCancel.(*gtk.Button)

		objConnecting, err := builder.GetObject("lblConnecting")
		if err != nil {
			errCh <- err
			return
		}

		lblConnect := objConnecting.(*gtk.Label)

		objConnectingSpinner, err := builder.GetObject("spnConnecting")
		if err != nil {
			errCh <- err
			return
		}

		spnConnecting := objConnectingSpinner.(*gtk.Spinner)
		spnConnecting.Stop()
		lblConnect.SetLabel("")

		_, err = win.Connect("destroy", handlers.onDestroy)
		if err != nil {
			errCh <- err
			return
		}

		_, err = win.Connect("key-press-event", handlers.onWinKeyPress)
		if err != nil {
			errCh <- err
			return
		}

		_, err = btnConnect.Connect("clicked", handlers.onBtnConnectClicked)
		if err != nil {
			errCh <- err
			return
		}

		_, err = txtPassword.Connect("key-press-event", handlers.onPasswordKeyPress)
		if err != nil {
			errCh <- err
			return
		}

		_, err = btnCancel.Connect("clicked", handlers.onBtnCancelClicked)
		if err != nil {
			errCh <- err
			return
		}

		objBoxRoot, err := builder.GetObject("boxRoot")
		if err != nil {
			errCh <- err
			return
		}
		boxRoot := objBoxRoot.(*gtk.Box)

		objBoxError, err := builder.GetObject("boxError")
		if err != nil {
			errCh <- err
			return
		}
		boxError := objBoxError.(*gtk.Box)

		objBoxErrorHeader, err := builder.GetObject("boxErrorHeader")
		if err != nil {
			errCh <- err
			return
		}
		boxErrorHeader := objBoxErrorHeader.(*gtk.Box)

		objBoxConnecting, err := builder.GetObject("boxConnecting")
		if err != nil {
			errCh <- err
			return
		}
		boxConnecting := objBoxConnecting.(*gtk.Box)

		objTxtError, err := builder.GetObject("txtError")
		if err != nil {
			errCh <- err
			return
		}
		txtError := objTxtError.(*gtk.TextView)

		buffer, err := gtk.TextBufferNew(nil)
		txtError.SetBuffer(buffer)

		g.win = win
		g.lblConnect = lblConnect
		g.spnConnecting = spnConnecting
		g.btnConnect = btnConnect
		g.txtPassword = txtPassword
		g.boxError = boxError
		g.txtError = buffer
		g.boxConnecting = boxConnecting
		g.boxErrorHeader = boxErrorHeader
		g.btnCancel = btnCancel
		g.boxRoot = boxRoot

		g._reset()

		errCh <- nil
		gtk.Main()
	}()

	e := <-errCh
	if e != nil {
		return nil, e
	}

	go func() {
		defer cancel()
		defer gtk.MainQuit()

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return g, nil
}
