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
	Cancel()
}

type gtkGui struct {
	ctx           context.Context
	wgInit        sync.WaitGroup
	results       chan passwordError
	win           *gtk.Window
	lblConnect    *gtk.Label
	spnConnecting *gtk.Spinner
	btnConnect    *gtk.Button
	txtPassword   *gtk.Entry
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

		//builder, err := gtk.BuilderNewFromFile("/home/marndt/go/src/github.com/MeneDev/yubi-oath-vpn/ConnectDialog.gtk")
		builder, err := gtk.BuilderNew()

		if err != nil {
			errCh <- err
			return
		}

		err = builder.AddFromString(`<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated with glade 3.22.1 -->
<interface>
  <requires lib="gtk+" version="3.20"/>
  <object class="GtkWindow" id="Dialog">
    <property name="can_focus">False</property>
    <property name="window_position">center</property>
    <property name="urgency_hint">True</property>
    <child>
      <object class="GtkBox">
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <child>
          <object class="GtkBox">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="spacing">7</property>
            <child>
              <object class="GtkImage">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="stock">gtk-dialog-authentication</property>
                <property name="icon_size">6</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Enter Yubikey Password</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkEntry" id="txtPassword">
            <property name="visible">True</property>
            <property name="can_focus">True</property>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child>
          <object class="GtkBox">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="halign">center</property>
            <property name="spacing">10</property>
            <child>
              <object class="GtkSpinner" id="spnConnecting">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="lblConnecting">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Connecting...</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">False</property>
            <property name="position">2</property>
          </packing>
        </child>
        <child>
          <object class="GtkButtonBox">
            <property name="can_focus">False</property>
            <property name="hexpand">True</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="btnConnect">
                <property name="label">gtk-connect</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_stock">True</property>
                <property name="always_show_image">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <!-- <child>
              <object class="GtkButton">
                <property name="label">gtk-cancel</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_stock">True</property>
                <property name="always_show_image">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child> -->
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">3</property>
          </packing>
        </child>
      </object>
    </child>
  </object>
</interface>
`)
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
			btnConnect.SetSensitive(false)
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
		g.btnConnect = btnConnect
		g.txtPassword = txtPassword

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
		g.txtPassword.SetText("")
		g.btnConnect.SetSensitive(true)
		g.win.ShowAll()
		g.win.Present()
		g.win.SetKeepAbove(true)
		g.win.GrabFocus()
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
func (g *gtkGui) Cancel() {
	glib.IdleAdd(func() {
		g.spnConnecting.Stop()
		g.win.Hide()
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
