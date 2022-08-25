package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/MeneDev/yubi-oath-vpn/scardmonitor"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	scardMon, _ := scardmonitor.ScardMonNew(ctx)
	scardStatusChan := scardMon.StatusChannel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	defer cancel()

	for {
		log.Printf("Waiting for scardStatusChan or signalChan")
		select {
		case s := <-scardStatusChan:
			log.Printf("scard id: %s, %v\n", s.Id(), s.Presence())
		case <-signalChan:
			log.Printf("Crtl+C")
			return
		}
	}
}
