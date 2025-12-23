// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package harness defines harness test command configuration and helpers.
package harness

import "github.com/pion/scp/internal/scp"

const (
	DefaultPairMode     = "adjacent"
	DefaultTimeout      = "2m"
	DefaultInterleaving = interleavingAuto
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
	OutDir        string
	Interleaving  string
	PprofCPU      string
	PprofHeap     string
	PprofAllocs   string
	Repeat        int
}

func DefaultOptions() Options {
	return Options{
		LockPath:     scp.DefaultLockPath(),
		PairMode:     DefaultPairMode,
		Cases:        []string{caseMaxBurst},
		Timeout:      DefaultTimeout,
		Interleaving: DefaultInterleaving,
		JUnitPath:    "",
		OutDir:       "",
		Repeat:       1,
	}
}
