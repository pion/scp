package scp

import (
	"context"
	"fmt"
	"strings"
)

func (m *Mirror) ListTags(ctx context.Context) ([]RefInfo, error) {
	lines, err := m.ForEachRef(ctx, "refs/tags", "%(refname:strip=2) %(target)")
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

func (m *Mirror) ResolveRef(ctx context.Context, ref string) (RefInfo, error) {
	sha, err := m.RevParse(ctx, ref)
	if err != nil {
		return RefInfo{}, err
	}

	return RefInfo{Name: ref, Object: sha}, nil
}
