package main

import (
	"context"
	"fmt"
	"github.com/MeneDev/yubi-oath-vpn/scardmonitor"
)

func main() {
	ctx := context.Background()
	scardMon := scardmonitor.ScardMonNew(ctx)
	scardStatusChan := scardMon.StatusChannel()
	for {
		select {
		case s := <-scardStatusChan:
			fmt.Printf("scard id: %s, %v\n", s.Id(), s.Presence())
		}
	}
}
