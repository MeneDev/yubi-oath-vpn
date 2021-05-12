package main

import (
	"context"
	"fmt"
	"github.com/MeneDev/yubi-oath-vpn/githubreleasemon"
	"github.com/MeneDev/yubi-oath-vpn/gui2"
	"github.com/MeneDev/yubi-oath-vpn/netctrl"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	"github.com/MeneDev/yubi-oath-vpn/yubimonitor"
	"github.com/jessevdk/go-flags"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANICED: %v", r)
		}
	}()

	var opts Options
	_, err := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash).Parse()
	if opts.ShowVersion {
		showVersion()
		os.Exit(0)
	}

	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		log.Printf("Canceling root context")
		cancel()
	}()

	yubiMon, _ := yubimonitor.YubiMonitorNew(ctx)

	yubiChan := yubiMon.InsertionChannel()

	title := fmt.Sprintf("Yubi VPN Mon %s", Version)
	controller, e := gui2.GuiControllerNew(ctx, title)
	if e != nil {
		println(e)
		return
	}

	networkController := netctrl.DefaultNetworkController(ctx)

	releaseMon, err := githubreleasemon.GithubReleaseMonNew(ctx, "MeneDev", "yubi-oath-vpn")
	if err != nil {
		log.Printf("Error checking version: %s", err.Error())
	}

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context.Done()")
			return
		case yubiEvent := <-yubiChan:
			log.Printf("yov.yubiChan %v", yubiEvent)
			if yubiEvent == nil {
				log.Printf("yubiChan is nil")
				return
			}

			key, err := yubiEvent.Open()
			log.Printf("yubiEvent.Open: %v, %v", key, err)

			if err != nil {
				log.Printf("Error opening YubiKey: %s", err.Error())
			}

			if applicableYubiKey(key) {
				connectedToTun, _ := isConnectedToTun()
				if !connectedToTun {
					controller.ConnectWith(key, opts.ConnectionName, opts.SlotName)
				} else {
					log.Printf("Connected TUN device found, not trying to connect")
				}
			}

		case conParams := <-controller.InitializeConnection():
			networkController.Connect(conParams.Context, conParams.ConnectionId, conParams.Code)

		case ev := <-networkController.ConnectionResults():
			log.Printf("networkController.ConnectionResults: %v", ev)
			controller.ConnectionResult(ev)

		case release := <-releaseMon.ReleaseChan():
			if release.Error != nil {
				log.Printf("Error checking release: %s", release.Error.Error())
			} else {
				log.Printf("Latest release: %v", release.Release.TagName)
				controller.SetLatestVersion(release.Release)
			}

		case <-interruptChan:
			log.Printf("Received Interrupt, shutting down")
			return
		}
	}
}

func applicableYubiKey(key yubikey.YubiKey) bool {
	return true
}

func isConnectedToTun() (bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("net.Interfaces(): %v\n", err.Error()))
		return false, err
	}

	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}

		log.Printf("Found interface in up state %s", iface.Name)
		if strings.HasPrefix(iface.Name, "tun") {
			return true, nil
		}
	}

	return false, nil
}

var Version string = "<unknown>"
var BuildDate string = "<unknown>"
var BuildNumber string = "<unknown>"
var BuildCommit string = "<unknown>"

func showVersion() {
	format := "%-13s%s\n"
	fmt.Printf(format, "Version:", Version)
	fmt.Printf(format, "BuildDate:", BuildDate)
	fmt.Printf(format, "BuildNumber:", BuildNumber)
	fmt.Printf(format, "BuildCommit:", BuildCommit)
	fmt.Printf(format, "Compiler:", runtime.Compiler)
	fmt.Printf(format, "Arcitecture:", runtime.GOARCH)
	fmt.Printf(format, "OS:", runtime.GOOS)
	fmt.Printf(format, "Go version:", runtime.Version())
}
