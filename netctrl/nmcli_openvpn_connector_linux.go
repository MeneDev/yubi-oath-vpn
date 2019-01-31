package netctrl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

func DefaultNetworkController(ctx context.Context) NetworkController {
	return NmcliOpenVpnNetworkManagerConnectorNew(ctx)
}

func NmcliOpenVpnNetworkManagerConnectorNew(ctx context.Context) NetworkController {
	ctx, cancel := context.WithCancel(ctx)

	connector := &nmcliOpenVpnConnector{ctx: ctx, canel: cancel}

	connector.resultsChan = make(chan ConnectionAttemptResult)
	go func() {
		defer cancel()
		defer close(connector.resultsChan)

		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}()

	return connector
}

var _ NetworkController = (*nmcliOpenVpnConnector)(nil)

type nmcliOpenVpnConnector struct {
	ctx         context.Context
	canel       context.CancelFunc
	resultsChan chan ConnectionAttemptResult
}

func (ctor *nmcliOpenVpnConnector) Connect(ctx context.Context, connectionName string, code string) {
	go func() {
		subProcess := exec.CommandContext(ctx, "nmcli", "con", "up", connectionName, "passwd-file", "/dev/fd/0")
		stdin, err := subProcess.StdinPipe()
		if err != nil {
			return
		}

		defer stdin.Close()

		stdout := bytes.NewBuffer(nil)
		stderr := bytes.NewBuffer(nil)
		subProcess.Stdout = stdout
		subProcess.Stderr = stderr

		if err = subProcess.Start(); err != nil { //Use start, not run
			fmt.Println("An error occured: ", err) //replace with logger, or anything you want
		}

		io.WriteString(stdin, "vpn.secrets.password:"+code+"\n")
		stdin.Close()
		println("start connecting via nmcli")
		subProcess.Wait()
		println("finished connecting via nmcli")

		stderrStr := stderr.String()
		if stderrStr != "" {
			ctor.resultsChan <- &nmcliResult{message: stderrStr, success: false}
		} else {
			ctor.resultsChan <- &nmcliResult{message: "Done", success: true}
		}
	}()
}

func (ctor *nmcliOpenVpnConnector) ConnectionResults() <-chan ConnectionAttemptResult {
	return ctor.resultsChan
}
