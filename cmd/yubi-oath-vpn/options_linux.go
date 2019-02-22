package main

type Options struct {
	ConnectionName string `required:"yes" short:"c" long:"connection" description:"The name of the connection as shown by 'nmcli c show'"`
	ShowVersion    bool   `required:"no" short:"v" long:"version" description:"Show version and exit"`
}
