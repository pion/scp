// Package testcmd defines harness test command configuration and helpers.
package testcmd

import "github.com/pion/scp/internal/scp"

const (
	DefaultPairMode = "adjacent"
	DefaultTimeout  = "2m"
)

type Options struct {
	LockPath      string
	PairMode      string
	IncludeNames  []string
	ExcludeNames  []string
	ExplicitPairs []string
	Cases         []string
	Timeout       string
	Seed          int64
	JUnitPath     string
	Repeat        int
}

func DefaultOptions() Options {
	return Options{
		LockPath:  scp.DefaultLockPath(),
		PairMode:  DefaultPairMode,
		Timeout:   DefaultTimeout,
		JUnitPath: "",
		Repeat:    1,
	}
}
