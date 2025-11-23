// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Mirror struct {
	URL  string
	Path string
}

func EnsureMirror(ctx context.Context, repoURL, cacheDir string) (*Mirror, error) {
	cacheAbs, err := filepath.Abs(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("git cache abs: %w", err)
	}
	mirrorPath := filepath.Join(cacheAbs, mirrorDirName(repoURL))
	if err := os.MkdirAll(cacheAbs, 0o750); err != nil {
		return nil, fmt.Errorf("git cache: %w", err)
	}

	if _, err := os.Stat(mirrorPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("git mirror stat: %w", err)
		}
		if err := runGit(ctx, cacheAbs, "clone", "--mirror", repoURL, mirrorPath); err != nil {
			return nil, fmt.Errorf("git clone mirror: %w", err)
		}
	} else {
		if err := runGit(ctx, mirrorPath, "remote", "update", "--prune"); err != nil {
			return nil, fmt.Errorf("git remote update: %w", err)
		}
	}

	return &Mirror{
		URL:  repoURL,
		Path: mirrorPath,
	}, nil
}

func (m *Mirror) RevParse(ctx context.Context, rev string) (string, error) {
	out, err := runGitStdout(ctx, m.Path, "rev-parse", rev)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}

func (m *Mirror) ForEachRef(ctx context.Context, pattern string, format string) ([]string, error) {
	args := []string{"for-each-ref"}
	if pattern != "" {
		args = append(args, pattern)
	}
	if format != "" {
		args = append(args, "--format="+format)
	}
	out, err := runGitStdout(ctx, m.Path, args...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}

	return lines, nil
}

func (m *Mirror) ResolveBefore(ctx context.Context, revPattern string, before string) (string, error) {
	if before == "" {
		return m.RevParse(ctx, revPattern)
	}
	out, err := runGitStdout(ctx, m.Path, "rev-list", "-n", "1", "--before="+before, revPattern)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}

func mirrorDirName(repoURL string) string {
	safe := repoURL
	safe = strings.ReplaceAll(safe, "://", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "@", "_")

	return safe + ".git"
}

func runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return gitCommandError(args, err, stderr.String())
	}

	return nil
}

func runGitStdout(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", gitCommandError(args, err, stderr.String())
	}

	return stdout.String(), nil
}

var errGitCommand = errors.New("git command failed")

func gitCommandError(args []string, cmdErr error, stderr string) error {
	summary := strings.Join(args, " ")

	wrapped := fmt.Errorf("git %s: %w", summary, cmdErr)
	stderr = strings.TrimSpace(stderr)
	if stderr != "" {
		wrapped = fmt.Errorf("%w (%s)", wrapped, stderr)
	}

	return errors.Join(errGitCommand, wrapped)
}
