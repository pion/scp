// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
)

type profiler struct {
	cpuFile    *os.File
	heapPath   string
	allocsPath string
}

func startProfiler(opts Options) (*profiler, error) {
	if opts.PprofCPU == "" && opts.PprofHeap == "" && opts.PprofAllocs == "" {
		return nil, nil
	}

	prof := &profiler{
		heapPath:   opts.PprofHeap,
		allocsPath: opts.PprofAllocs,
	}

	if opts.PprofCPU == "" {
		return prof, nil
	}

	file, err := createProfileFile(opts.PprofCPU)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("test: start cpu profile: %w", err)
	}
	prof.cpuFile = file

	return prof, nil
}

func (p *profiler) Stop() error {
	if p == nil {
		return nil
	}

	var err error
	if p.cpuFile != nil {
		pprof.StopCPUProfile()
		if closeErr := p.cpuFile.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("test: close cpu profile: %w", closeErr))
		}
	}

	if p.heapPath != "" || p.allocsPath != "" {
		runtime.GC()
	}

	if p.heapPath != "" {
		if writeErr := writeProfile(p.heapPath, "heap"); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}
	if p.allocsPath != "" {
		if writeErr := writeProfile(p.allocsPath, "allocs"); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}

	return err
}

func writeProfile(path, name string) error {
	prof := pprof.Lookup(name)
	if prof == nil {
		return fmt.Errorf("test: %s profile unavailable", name)
	}
	file, err := createProfileFile(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := prof.WriteTo(file, 0); err != nil {
		return fmt.Errorf("test: write %s profile: %w", name, err)
	}

	return nil
}

func createProfileFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("test: create profile dir %q: %w", dir, err)
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("test: create profile file %q: %w", path, err)
	}

	return file, nil
}
