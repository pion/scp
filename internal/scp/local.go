package scp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type LocalInfo struct {
	Commit      string
	BaseCommit  string
	DisplayPath string
}

var (
	errLocalDirty   = errors.New("local path has uncommitted changes")
	errLocalNotRepo = errors.New("path is not a git repository")
)

func InspectLocalPath(ctx context.Context, path string, allowDirty bool) (LocalInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return LocalInfo{}, fmt.Errorf("local path: %w", err)
	}
	if _, statErr := os.Stat(abs); statErr != nil {
		return LocalInfo{}, fmt.Errorf("local path: %w", statErr)
	}

	if repoErr := ensureGitRepo(ctx, abs); repoErr != nil {
		return LocalInfo{}, repoErr
	}

	status, err := gitStatusPorcelain(ctx, abs)
	if err != nil {
		return LocalInfo{}, err
	}

	isDirty := len(status) > 0
	if isDirty && !allowDirty {
		return LocalInfo{}, fmt.Errorf("%w: %s", errLocalDirty, abs)
	}

	head, err := gitRevParse(ctx, abs, "HEAD")
	if err != nil {
		return LocalInfo{}, err
	}

	commit := head
	if isDirty {
		diff, err := gitDiff(ctx, abs)
		if err != nil {
			return LocalInfo{}, err
		}
		sum := sha256.Sum256(diff)
		commit = "dirty:" + hex.EncodeToString(sum[:4])
	}

	return LocalInfo{
		Commit:      commit,
		BaseCommit:  head,
		DisplayPath: abs,
	}, nil
}

func ensureGitRepo(ctx context.Context, dir string) error {
	_, err := gitCommand(ctx, dir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return fmt.Errorf("%w: %s", errLocalNotRepo, dir)
	}

	return nil
}

func gitStatusPorcelain(ctx context.Context, dir string) (string, error) {
	out, err := gitCommand(ctx, dir, "status", "--porcelain")

	return strings.TrimSpace(out), err
}

func gitRevParse(ctx context.Context, dir string, rev string) (string, error) {
	out, err := gitCommand(ctx, dir, "rev-parse", rev)

	return strings.TrimSpace(out), err
}

func gitDiff(ctx context.Context, dir string) ([]byte, error) {
	out, err := gitCommandBytes(ctx, dir, "diff")

	return out, err
}

func gitCommand(ctx context.Context, dir string, args ...string) (string, error) {
	buf, err := gitCommandBytes(ctx, dir, args...)

	return string(buf), err
}

func gitCommandBytes(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, gitCommandError(args, err, stderr.String())
	}

	return stdout.Bytes(), nil
}
