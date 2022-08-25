package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/MeneDev/yubi-oath-vpn/githubreleasemon"
	"github.com/MeneDev/yubi-oath-vpn/gui2"
	"github.com/MeneDev/yubi-oath-vpn/netctrl"
	"github.com/MeneDev/yubi-oath-vpn/yubikey"
	"github.com/MeneDev/yubi-oath-vpn/yubimonitor"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			evt := log.Error()

			switch v := r.(type) {
			case string:
				evt.Str("error", v)
			case error:
				evt.Err(v)
			default:
				evt.Str("error", fmt.Sprintf("%v", v))
			}

			evt.Msg("panicked")
		}
	}()

	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		NoColor:    true,
		TimeFormat: "2006/01/02 15:04:05", // mimic golang log output
	})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	var opts Options
	_, err := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash).Parse()
	if opts.ShowVersion {
		showVersion()
		os.Exit(0)
	}

	if err != nil {
		log.Fatal().Err(err).Msg("cannot parse flags")
	}

	if opts.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		log.Debug().Msg("Canceling root context")
		cancel()
	}()

	yubiMon, _ := yubimonitor.YubiMonitorNew(ctx)

	yubiChan := yubiMon.InsertionChannel()

	title := fmt.Sprintf("Yubi VPN Mon %s", Version)
	controller, e := gui2.GuiControllerNew(ctx, title)
	if e != nil {
		log.Error().Err(e).Msg("cannot creat GUI")
		return
	}

	networkController := netctrl.DefaultNetworkController(ctx)

	releaseMon, err := githubreleasemon.GithubReleaseMonNew(ctx, "MeneDev", "yubi-oath-vpn")
	if err != nil {
		log.Warn().Err(err).Msg("version check failed")
	}

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt)

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("Context.Done()")
			return
		case yubiEvent := <-yubiChan:
			log.Debug().Interface("event", yubiEvent).Msg("yov.yubiChan")
			if yubiEvent == nil {
				log.Debug().Msg("yubiChan is nil")
				return
			}

			key, err := yubiEvent.Open()

			if err != nil {
				log.Error().Err(err).Msg("yubiEvent.Open")
				break
			}
			log.Debug().Interface("key", key).Msg("yubiEvent.Open")

			if applicableYubiKey(key) {
				connectedToTun, _ := isConnectedToTun()
				if !connectedToTun {
					controller.ConnectWith(key, opts.ConnectionName, opts.SlotName)
				} else {
					log.Info().Msg("Connected TUN device found, not trying to connect")
				}
			}

		case conParams := <-controller.InitializeConnection():
			networkController.Connect(conParams.Context, conParams.ConnectionId, conParams.Code)

		case ev := <-networkController.ConnectionResults():
			log.Debug().Str("result", ev.String()).Msg("networkController.ConnectionResults")
			controller.ConnectionResult(ev)

		case release := <-releaseMon.ReleaseChan():
			if release.Error != nil {
				log.Warn().Err(err).Msg("checking release failed")
			} else {
				log.Debug().Str("version", release.Release.TagName).Msg("latest release")
				controller.SetLatestVersion(release.Release)
			}

		case <-interruptChan:
			log.Info().Msg("Received Interrupt, shutting down")
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

		log.Info().Str("interface", iface.Name).Msg("Found interface in up state")
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
