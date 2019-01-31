package main

import (
	"log"
	"net"
)

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, i := range ifaces {
		println(i.Name)
		i.HardwareAddr.String()
	}
}
