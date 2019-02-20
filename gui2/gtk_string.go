package gui2

const gtkGuiString = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated with glade 3.22.1 -->
<interface>
  <requires lib="gtk+" version="3.20"/>
  <object class="GtkWindow" id="Dialog">
    <property name="can_focus">False</property>
    <property name="window_position">center</property>
    <property name="default_width">500</property>
    <property name="urgency_hint">True</property>
    <child type="titlebar">
      <placeholder/>
    </child>
    <child>
      <object class="GtkBox" id="boxRoot">
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <property name="margin_left">10</property>
        <property name="margin_right">10</property>
        <property name="margin_top">10</property>
        <property name="margin_bottom">10</property>
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
            <property name="margin_top">7</property>
            <property name="margin_bottom">7</property>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child>
          <object class="GtkBox" id="boxConnecting">
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
          <object class="GtkBox" id="boxError">
            <property name="can_focus">False</property>
            <property name="orientation">vertical</property>
            <child>
              <object class="GtkBox" id="boxErrorHeader">
                <property name="can_focus">False</property>
                <child>
                  <object class="GtkImage">
                    <property name="can_focus">False</property>
                    <property name="stock">gtk-dialog-error</property>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel">
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Error</property>
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
              <object class="GtkScrolledWindow" id="svError">
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTextView" id="txtError">
                    <property name="can_focus">True</property>
                    <property name="editable">False</property>
                    <property name="monospace">True</property>
                  </object>
                </child>
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
            <property name="position">3</property>
          </packing>
        </child>
        <child>
          <object class="GtkBox">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkLinkButton" id="lnkUpdate">
                <property name="label" translatable="yes">button</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="relief">none</property>
                <property name="uri">http://glade.gnome.org</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButtonBox">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="margin_top">10</property>
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
                <child>
                  <object class="GtkButton" id="btnCancel">
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
                </child>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">4</property>
          </packing>
        </child>
      </object>
    </child>
  </object>
</interface>
`
