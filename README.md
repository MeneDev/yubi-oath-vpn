# yubi-oath-vpn monitor [![CircleCI](https://circleci.com/gh/MeneDev/yubi-oath-vpn.svg?style=svg)]

Simply insert your Yubikey to an USB-slot and connect to your 2FA-VPN. 

## Usage
`yubi-oath-vpn --connection=<connection name>`

Will start the program and connect as soon as the Yubikey is inserted (and not already connected)

### Autostart via systemd

* Copy yubi-oath-vpn binary to $HOMR/Apps/yubi-oath-vpn, make sure it's executable
* Adjust and copy the file yubi-oath-vpn.service to $HOME/.config/systemd/user/yubi-oath-vpn.service

## Limitations
 * The Yubikey must have a password
 * nmcli is required to bring up the VPN (so Linux only?)
 * Only works with OpenVPN
 * VPN must use tun device
 * Must be the only tun device
 * VPN must use TOTP
 
## Background
We use Yubikeys for two factor authentication against our VPN.
We have a Bash script with similar functionality, but the tools (ykman, yubioath) keep changing and dbus-monitor was behaving differently depending on distro.

## Disclaimer
Only tested against a single Yubikey version.
It's my first go project. Expect bugs and low code quality.
