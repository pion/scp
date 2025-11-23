// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package generate implements the generator CLI that builds multi-version SCTP wrappers and harnesses.
package generate

import (
	"github.com/pion/scp/internal/scp"
)

const (
	DefaultRunnerProtocol = "stdio-json"
	DefaultModuleMode     = "local-cache"
	ModuleModeRemote      = "remote"
	DefaultAPIName        = "sctpapi"
)

type Options struct {
	LockPath       string
	FeaturesPath   string
	OutputDir      string
	APIName        string
	RunnerProtocol string
	ModuleMode     string
	LicensePath    string
	OnlyNames      []string
}

func DefaultOptions() Options {
	return Options{
		LockPath:       scp.DefaultLockPath(),
		FeaturesPath:   scp.DefaultFeaturesPath(),
		OutputDir:      scp.DefaultOutputDir(),
		APIName:        DefaultAPIName,
		RunnerProtocol: DefaultRunnerProtocol,
		ModuleMode:     DefaultModuleMode,
	}
}

func (o Options) WithDefaults() Options {
	def := DefaultOptions()

	if o.LockPath == "" {
		o.LockPath = def.LockPath
	}
	if o.FeaturesPath == "" {
		o.FeaturesPath = def.FeaturesPath
	}
	if o.OutputDir == "" {
		o.OutputDir = def.OutputDir
	}
	if o.APIName == "" {
		o.APIName = def.APIName
	}
	if o.RunnerProtocol == "" {
		o.RunnerProtocol = def.RunnerProtocol
	}
	if o.ModuleMode == "" {
		o.ModuleMode = def.ModuleMode
	}

	return o
}
