package main

type Options struct {
	ConnectionName string `required:"yes" short:"c" long:"connection" description:"The name of the OpenVPN connection without extension'"`
	ShowVersion    bool   `required:"no" short:"v" long:"version" description:"Show version and exit"`
}
