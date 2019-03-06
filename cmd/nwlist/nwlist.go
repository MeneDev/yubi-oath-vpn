package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, i := range ifaces {
		fmt.Printf("%s\t%s\n", i.Name, fragsString(i.Flags))
		i.HardwareAddr.String()
	}
}

func fragsString(flags net.Flags) string {
	strs := make([]string, 0)

	if flags&net.FlagUp != 0 {
		strs = append(strs, "Up")
	}

	if flags&net.FlagBroadcast != 0 {
		strs = append(strs, "Broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		strs = append(strs, "Loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		strs = append(strs, "PointToPoint")
	}
	if flags&net.FlagMulticast != 0 {
		strs = append(strs, "Multicast")
	}

	return strings.Join(strs, "|")
}
