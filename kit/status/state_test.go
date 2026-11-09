package status_test

import (
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

func TestWorst(t *testing.T) {
	tests := []struct {
		name   string
		states []status.State
		want   status.State
	}{
		{"nothing reads as off", nil, status.StateOff},
		{"ok beats off", []status.State{status.StateOff, status.StateOK}, status.StateOK},
		{"starting beats ok", []status.State{status.StateOK, status.StateStarting}, status.StateStarting},
		{"warning beats starting", []status.State{status.StateStarting, status.StateWarning}, status.StateWarning},
		{"overdue beats warning", []status.State{status.StateWarning, status.StateOverdue, status.StateOK}, status.StateOverdue},
		{"failed beats overdue", []status.State{status.StateOverdue, status.StateFailed, status.StateWarning}, status.StateFailed},
		{"order does not matter", []status.State{status.StateFailed, status.StateOK}, status.StateFailed},
		{"an unknown state never wins", []status.State{"never", status.StateOff}, status.StateOff},
		{"an empty state reads as off", []status.State{""}, status.StateOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := status.Worst(tt.states...); got != tt.want {
				t.Errorf("Worst(%q) = %q, want %q", tt.states, got, tt.want)
			}
		})
	}
}
