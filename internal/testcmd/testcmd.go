// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package testcmd wraps the generated harness runner for scp test.
package testcmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pion/scp/harness"
	"github.com/pion/scp/internal/generate"
	"github.com/pion/scp/internal/scp"
)

// Options matches the harness test configuration.
type Options = harness.Options

// DefaultOptions returns the default test options.
func DefaultOptions() Options {
	return harness.DefaultOptions()
}

// Run generates a multi-version harness and executes it.
func Run(ctx context.Context, opts Options) error {
	genOpts := generate.DefaultOptions()
	genOpts.LockPath = opts.LockPath
	genOpts.OutputDir = scp.DefaultOutputDir()
	if err := generate.Run(ctx, genOpts); err != nil {
		return err
	}
	if err := prepareHarnessModule(ctx, genOpts.OutputDir); err != nil {
		return err
	}

	return runHarness(ctx, genOpts.OutputDir, opts)
}

func runHarness(ctx context.Context, workdir string, opts Options) error {
	args := []string{"run", "./cmd/scp-harness"}
	if opts.LockPath != "" {
		args = append(args, "--lock", absPath(opts.LockPath))
	}
	if opts.PairMode != "" {
		args = append(args, "--pairs", opts.PairMode)
	}
	if joined := joinArgs(opts.IncludeNames); joined != "" {
		args = append(args, "--include", joined)
	}
	if joined := joinArgs(opts.ExcludeNames); joined != "" {
		args = append(args, "--exclude", joined)
	}
	if joined := joinArgs(opts.ExplicitPairs); joined != "" {
		args = append(args, "--explicit", joined)
	}
	if joined := joinArgs(opts.Cases); joined != "" {
		args = append(args, "--cases", joined)
	}
	if opts.Timeout != "" {
		args = append(args, "--timeout", opts.Timeout)
	}
	if opts.Seed != 0 {
		args = append(args, "--seed", strconv.FormatInt(opts.Seed, 10))
	}
	if opts.JUnitPath != "" {
		args = append(args, "--out", absPath(opts.JUnitPath))
	}
	if opts.OutDir != "" {
		args = append(args, "--out-dir", absPath(opts.OutDir))
	}
	if opts.Interleaving != "" {
		args = append(args, "--interleaving", opts.Interleaving)
	}
	if opts.PprofCPU != "" {
		args = append(args, "--pprof-cpu", absPath(opts.PprofCPU))
	}
	if opts.PprofHeap != "" {
		args = append(args, "--pprof-heap", absPath(opts.PprofHeap))
	}
	if opts.PprofAllocs != "" {
		args = append(args, "--pprof-allocs", absPath(opts.PprofAllocs))
	}
	if opts.Repeat > 0 {
		args = append(args, "--repeat", strconv.Itoa(opts.Repeat))
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = workdir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = withGoCacheEnv(os.Environ())

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test: harness run: %w", err)
	}

	return nil
}

func prepareHarnessModule(ctx context.Context, workdir string) error {
	cmd := exec.CommandContext(ctx, "go", "mod", "tidy")
	cmd.Dir = workdir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = withGoCacheEnv(os.Environ())

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test: harness deps: %w", err)
	}

	return nil
}

func joinArgs(values []string) string {
	values = scp.SplitAndTrim(values)
	if len(values) == 0 {
		return ""
	}

	return strings.Join(values, ",")
}

func withGoCacheEnv(env []string) []string {
	cacheDir := filepath.Join(scp.DefaultStateDir, "go-build")
	if abs, err := filepath.Abs(cacheDir); err == nil {
		cacheDir = abs
	}
	_ = os.MkdirAll(cacheDir, 0o750)

	updated := make([]string, 0, len(env)+1)
	updated = append(updated, env...)
	updated = append(updated, "GOCACHE="+cacheDir)

	return updated
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}

	return abs
}
