# yubi-oath-vpn monitor [![CircleCI](https://circleci.com/gh/MeneDev/yubi-oath-vpn.svg?style=svg)](https://circleci.com/gh/MeneDev/yubi-oath-vpn) [![Follow @MeneDev on Twitter](https://img.shields.io/twitter/follow/MeneDev.svg?style=social&label=%40MeneDev)](https://twitter.com/MeneDev)

Simply insert your Yubikey to an USB-slot and connect to your 2FA-VPN. 

## Usage
Windows (experimental, see below)  
`yubi-oath-vpn /connection=<OpenVPN configuration name> [/slot=user@example.com]`

Linux  
`yubi-oath-vpn --connection=<connection name> [--slot=user@example.com]`

Will start the program and connect as soon as the Yubikey is inserted (and not already connected)

If the `slot` argument is omitted, the first slot is used.

### Autostart Startmenu entry (Windows)

* Extract all files to a single directory in you User directory
* Press `Win+R`, type `shell:startup`, hit enter.
* Right-click inside the folder, select `New` \> `Shortcut` and enter the path to the extracted executable (yubi-oath-vpn-win_amd64.exe)
* Edit the location and add ` /connection <OpenVPN configuration name>` to the target

You can locate your OpenVPN configurations in `%USERPROFILE%\OpenVPN\config\`.
The configurations must have the extension `ovpn`, use the filename **without** extension as `<OpenVPN configuration name>`

Example:
`client.ovpn` becomes `/connection client`

### Autostart via systemd (Linux)

* Copy yubi-oath-vpn binary to $HOME/Apps/yubi-oath-vpn, make sure it's executable
* Adjust and copy the file yubi-oath-vpn.service to $HOME/.config/systemd/user/yubi-oath-vpn.service

### Autostart via XDG autostart (KDE, Gnome, LXDE)

* Copy yubi-oath-vpn binary to $HOME/Apps/yubi-oath-vpn, make sure it's executable
* Adjust and copy the file yubi-oath-vpn.desktop to $HOME/.config/autostart/yubi-oath-vpn.desktop

## Limitations
 * The Yubikey must have a password
 * Only works with OpenVPN
 * VPN must use tun device
 * Must be the only tun device
 * VPN must use TOTP

## Limitations on Linux
 * nmcli is required to bring up the VPN

## Limitations on Windows
 * Consider the current version experimental
 * OpenVPN GUI must be installed
 * Make sure you connected at least once manually and save the credentials
 * Log files must be written to `%USERPROFILE%\OpenVPN\config`
 * Log files must not be appended to
 * Storing passwords must be allowed (this is asked during installation)
 * The connection status is currently not checked, thus the connection window is always presented when plugin in the YubiKey

## Background
We use Yubikeys for two factor authentication against our VPN.
We have a Bash script with similar functionality, but the tools (ykman, yubioath) keep changing and dbus-monitor was behaving differently depending on Linux distribution.

## Disclaimer
Only tested against one Yubikey 4 and one Yubikey 5 version.
It's my first go project. Expect bugs and low code quality.
That being said it's in active use for several years on different systems and seems to work just fine.
