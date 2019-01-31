package netctrl

import (
	"context"
)

type ConnectionAttemptResult interface {
	String() string
	Success() bool
}

type NetworkController interface {
	Connect(ctx context.Context, connectionName string, code string)
	ConnectionResults() <-chan ConnectionAttemptResult
}

var _ ConnectionAttemptResult = (*nmcliResult)(nil)

type nmcliResult struct {
	message string
	success bool
}

func (r *nmcliResult) Success() bool {
	return r.success
}

func (r *nmcliResult) String() string {
	return r.message
}
