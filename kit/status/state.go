package status

// State is the overall condition of an app. States are ranked so that the
// worst of several parts can stand for the whole, from best to worst: off, ok,
// starting, warning, overdue, failed.
type State string

const (
	// StateOff means the app has nothing switched on that it could report on.
	StateOff State = "off"
	// StateOK means everything the app watches is current.
	StateOK State = "ok"
	// StateStarting means the app runs but is not ready yet.
	StateStarting State = "starting"
	// StateWarning means the app runs, but something wants a look.
	StateWarning State = "warning"
	// StateOverdue means work that should have happened by now has not, such
	// as a backup more than two intervals old.
	StateOverdue State = "overdue"
	// StateFailed means something the app is there for went wrong.
	StateFailed State = "failed"
)

var stateRank = map[State]int{
	StateOff:      0,
	StateOK:       1,
	StateStarting: 2,
	StateWarning:  3,
	StateOverdue:  4,
	StateFailed:   5,
}

// Worst returns the worst of states, or StateOff for none. A state outside the
// contract ranks below StateOff, so it never wins.
func Worst(states ...State) State {
	worst := StateOff
	for _, s := range states {
		if r, ok := stateRank[s]; ok && r > stateRank[worst] {
			worst = s
		}
	}
	return worst
}

// Severity is how urgent a need or a log entry is.
type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

// state is the least an app reports while it shows a need of this severity.
func (s Severity) state() State {
	switch s {
	case SeverityWarn:
		return StateWarning
	case SeverityError:
		return StateFailed
	}
	return StateOff
}
