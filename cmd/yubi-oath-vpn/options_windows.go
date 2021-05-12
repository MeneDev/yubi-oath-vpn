package main

type Options struct {
	ConnectionName string `required:"yes" short:"c" long:"connection" description:"The name of the OpenVPN connection without extension'"`
	SlotName       string `required:"no" short:"s" long:"slot" description:"The name of the YubiKey slot to use (typically of the form user@example.com)"`
	ShowVersion    bool   `required:"no" short:"v" long:"version" description:"Show version and exit"`
}
