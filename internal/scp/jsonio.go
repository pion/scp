// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	errPathOutsideWorkspace = errors.New("state path escapes working directory")
	errEmptyStatePath       = errors.New("state path empty")
)

func ReadManifest(path string) (*Manifest, error) {
	safePath, err := cleanStatePath(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(safePath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	var m Manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	return &m, nil
}

func WriteManifest(path string, m *Manifest) error {
	safePath, err := cleanStatePath(path)
	if err != nil {
		return err
	}

	if parentErr := makeParent(safePath); parentErr != nil {
		return parentErr
	}

	return writeJSON(safePath, m)
}

func ReadLock(path string) (*Lockfile, error) {
	safePath, err := cleanStatePath(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(safePath)
	if err != nil {
		return nil, fmt.Errorf("read lock: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	var l Lockfile
	if err := json.NewDecoder(f).Decode(&l); err != nil {
		return nil, fmt.Errorf("parse lock: %w", err)
	}

	return &l, nil
}

func WriteLock(path string, l *Lockfile) error {
	safePath, err := cleanStatePath(path)
	if err != nil {
		return err
	}

	if parentErr := makeParent(safePath); parentErr != nil {
		return parentErr
	}

	return writeJSON(safePath, l)
}

func CopyJSON(dst string, r io.Reader) error {
	safePath, err := cleanStatePath(dst)
	if err != nil {
		return err
	}

	if parentErr := makeParent(safePath); parentErr != nil {
		return parentErr
	}

	f, err := openWritableFile(safePath, 0o640)
	if err != nil {
		return fmt.Errorf("create %s: %w", safePath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("write %s: %w", safePath, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", safePath, err)
	}

	return nil
}

func makeParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	return os.MkdirAll(dir, 0o750)
}

func writeJSON(path string, value any) (resultErr error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	tmp := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		if removeErr := os.Remove(tmp); removeErr != nil && !os.IsNotExist(removeErr) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temp file: %w", removeErr))
		}
	}()

	enc := json.NewEncoder(tmpFile)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}

	return nil
}

func cleanStatePath(path string) (string, error) {
	if path == "" {
		return "", errEmptyStatePath
	}

	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		return cleaned, nil
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errPathOutsideWorkspace
	}

	return cleaned, nil
}

func openWritableFile(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
}
