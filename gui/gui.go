package gui

import (
	"context"
	"github.com/MeneDev/yubi-oath-vpn/yubierror"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"sync"
)

type Gui interface {
	Init() error
	AskPassword(additionalMessage string) (string, context.Context, error)
	InformFinishedConnecting()
	SetError(err error)
}

type gtkGui struct {
	ctx           context.Context
	wgInit        sync.WaitGroup
	results       chan passwordError
	win           *gtk.Window
	lblConnect    *gtk.Label
	spnConnecting *gtk.Spinner
}

type passwordError struct {
	password string
	err      error
}

func (g *gtkGui) Init() error {

	errCh := make(chan error)

	go func() {

		// Initialize GTK without parsing any command line arguments.
		gtk.Init(nil)

		builder, err := gtk.BuilderNewFromFile("/home/marndt/go/src/github.com/MeneDev/yubi-oath-vpn/ConnectDialog.gtk")
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
		win.Connect("destroy", func() {
			win.Hide()
			g.results <- passwordError{
				password: "",
				err:      yubierror.ErrorUserCancled,
			}
		})

		win.Connect("key-press-event", func(win *gtk.Window, ev *gdk.Event) {
			keyEvent := &gdk.EventKey{ev}

			if keyEvent.KeyVal() == gdk.KEY_Escape {
				win.Hide()
				g.results <- passwordError{
					password: "",
					err:      yubierror.ErrorUserCancled,
				}
			}
		})

		setPassword := func() {
			text, e := txtPassword.GetText()

			spnConnecting.Start()
			lblConnect.SetLabel("Connecting...")

			g.results <- passwordError{
				password: text,
				err:      e,
			}
		}

		btnConnect.Connect("clicked", setPassword)
		txtPassword.Connect("key-press-event", func(win *gtk.Entry, ev *gdk.Event) {
			keyEvent := &gdk.EventKey{ev}

			if keyEvent.KeyVal() == gdk.KEY_Return {
				setPassword()
			}
		})

		//for gtk.MainIterationDo(false) {
		//}

		g.win = win
		g.lblConnect = lblConnect
		g.spnConnecting = spnConnecting

		g.wgInit.Done()

		errCh <- nil
		gtk.Main()
	}()

	select {
	case e := <-errCh:
		return e
	case <-g.ctx.Done():
		glib.IdleAdd(func() {
			gtk.MainQuit()
			g.wgInit.Done()
		})
		return yubierror.ErrorUserCancled
	}

}

func (g *gtkGui) AskPassword(additionalMessage string) (string, context.Context, error) {
	g.wgInit.Wait()

	g.show()

	select {
	case <-g.ctx.Done():
		glib.IdleAdd(func() {
			gtk.MainQuit()
			g.wgInit.Done()
		})
		return "", context.TODO(), yubierror.ErrorUserCancled
	case r := <-g.results:
		return r.password, context.TODO(), r.err
	}
}

func (g *gtkGui) show() {
	glib.IdleAdd(func() {
		g.win.ShowAll()
	})
}

func (g *gtkGui) InformFinishedConnecting() {
	glib.IdleAdd(func() {
		g.spnConnecting.Stop()
		g.lblConnect.SetText("")
		g.win.Hide()
	})
}

func (g *gtkGui) SetError(err error) {
	glib.IdleAdd(func() {
		g.spnConnecting.Stop()
		g.lblConnect.SetText(err.Error())
	})
}

func GtkGui(ctx context.Context) Gui {
	gui := &gtkGui{
		ctx:     ctx,
		results: make(chan passwordError),
	}

	gui.wgInit.Add(1)

	return gui
}
