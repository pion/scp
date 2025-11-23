// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type RefInfo struct {
	Name   string
	Object string
}

var errMalformedRefLine = errors.New("git reference line malformed")

func (m *Mirror) ListBranches(ctx context.Context) ([]RefInfo, error) {
	lines, err := m.ForEachRef(ctx, "refs/heads", "%(refname:strip=2) %(objectname)")
	if err != nil {
		return nil, err
	}
	var infos []RefInfo
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("%w: %q", errMalformedRefLine, line)
		}
		infos = append(infos, RefInfo{
			Name:   parts[0],
			Object: parts[1],
		})
	}

	return infos, nil
}

func (m *Mirror) ResolveBranch(ctx context.Context, name string) (RefInfo, error) {
	return m.ResolveRef(ctx, "refs/heads/"+name)
}

func (m *Mirror) ResolveRemoteBranch(ctx context.Context, name string) (RefInfo, error) {
	// Mirrors have local refs/heads entries equivalent to origin/<branch>.
	return m.ResolveBranch(ctx, name)
}

func (m *Mirror) ResolveRemoteBranchBefore(ctx context.Context, name string, before string) (RefInfo, error) {
	sha, err := m.ResolveBefore(ctx, "refs/heads/"+name, before)
	if err != nil {
		return RefInfo{}, err
	}

	return RefInfo{Name: name, Object: sha}, nil
}

func (m *Mirror) ResolvePRHead(ctx context.Context, number int) (RefInfo, error) {
	ref := fmt.Sprintf("refs/pull/%d/head", number)

	return m.ResolveRef(ctx, ref)
}
