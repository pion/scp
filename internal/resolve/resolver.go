// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package resolve

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/pion/scp/internal/scp"
)

type resolver struct {
	opts   Options
	mirror *scp.Mirror
}

func newResolver(opts Options, mirror *scp.Mirror) *resolver {
	return &resolver{
		opts:   opts,
		mirror: mirror,
	}
}

func (r *resolver) ResolveAll(ctx context.Context, raws []string) ([]resolvedEntry, error) {
	var results []resolvedEntry
	seenNames := map[string]struct{}{}

	for _, raw := range raws {
		sel, err := scp.ParseSelector(raw)
		if err != nil {
			return nil, err
		}

		entries, err := r.resolveSelector(ctx, sel)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", raw, err)
		}
		for _, ent := range entries {
			if _, exists := seenNames[ent.Name]; exists {
				return nil, fmt.Errorf("%w: %q derived from %q", errDuplicateEntry, ent.Name, ent.Selector.Raw)
			}
			seenNames[ent.Name] = struct{}{}
			results = append(results, ent)
		}
	}

	return results, nil
}

func (r *resolver) resolveSelector(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	switch sel.Type {
	case scp.SelectorTag:
		return r.resolveTag(ctx, sel)
	case scp.SelectorBranch:
		return r.resolveBranch(ctx, sel)
	case scp.SelectorCommit:
		return r.resolveCommit(ctx, sel)
	case scp.SelectorPR:
		return r.resolvePR(ctx, sel)
	case scp.SelectorPath:
		return r.resolvePath(ctx, sel)
	case scp.SelectorRange:
		return r.resolveRange(ctx, sel)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedType, sel.Type)
	}
}

func (r *resolver) resolveTag(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	ref := "refs/tags/" + sel.Value
	info, err := r.mirror.ResolveRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	name := scp.NameForSelector(sel.Raw, sel.Type, sel.Value, info.Object)

	return []resolvedEntry{{
		Name:       name,
		Selector:   sel,
		Commit:     info.Object,
		Provenance: "tag",
		Labels: map[string]string{
			"selector": "tag",
			"tag":      sel.Value,
		},
	}}, nil
}

func (r *resolver) resolveBranch(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	names, err := r.matchBranches(ctx, sel.Value)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: %s", errBranchNotFound, sel.Value)
	}
	sort.Strings(names)
	var result []resolvedEntry
	orig := sel.Value
	hasGlob := strings.ContainsAny(orig, "*?[")
	for _, name := range names {
		info, err := r.mirror.ResolveRemoteBranchBefore(ctx, name, r.opts.FreezeAt)
		if err != nil {
			return nil, err
		}
		safeName := scp.NameForSelector(sel.Raw, scp.SelectorBranch, name, info.Object)
		labels := map[string]string{
			"selector": "branch",
			"branch":   name,
		}
		if hasGlob {
			labels["pattern"] = orig
		}
		result = append(result, resolvedEntry{
			Name:       safeName,
			Selector:   selWithValue(sel, name),
			Commit:     info.Object,
			Provenance: provenanceBranch(r.opts.FreezeAt),
			Labels:     labels,
		})
	}

	return result, nil
}

func (r *resolver) resolveCommit(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	sha, err := r.mirror.RevParse(ctx, sel.Value)
	if err != nil {
		return nil, err
	}
	name := scp.NameForSelector(sel.Raw, sel.Type, sel.Value, sha)

	return []resolvedEntry{{
		Name:       name,
		Selector:   sel,
		Commit:     sha,
		Provenance: "commit",
		Labels: map[string]string{
			"selector": "commit",
		},
	}}, nil
}

func (r *resolver) resolvePR(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	num, err := strconv.Atoi(sel.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errInvalidPRNumber, sel.Value)
	}
	info, err := r.mirror.ResolvePRHead(ctx, num)
	if err != nil {
		return nil, err
	}
	name := scp.NameForSelector(sel.Raw, sel.Type, sel.Value, info.Object)

	return []resolvedEntry{{
		Name:       name,
		Selector:   sel,
		Commit:     info.Object,
		Provenance: fmt.Sprintf("pr#%d", num),
		Labels: map[string]string{
			"selector": "pr",
			"pr":       strconv.Itoa(num),
		},
	}}, nil
}

func (r *resolver) resolvePath(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	if sel.Value == "" {
		return nil, errEmptyPathSelector
	}
	info, err := scp.InspectLocalPath(ctx, sel.Value, r.opts.AllowDirtyLocal)
	if err != nil {
		return nil, err
	}
	name := scp.NameForSelector(sel.Raw, sel.Type, sel.Value, info.Commit)

	return []resolvedEntry{{
		Name:       name,
		Selector:   sel,
		Commit:     info.Commit,
		Provenance: "local-path",
		Labels: map[string]string{
			"selector": "path",
			"path":     info.DisplayPath,
			"baseHead": info.BaseCommit,
		},
	}}, nil
}

func (r *resolver) resolveRange(ctx context.Context, sel scp.Selector) ([]resolvedEntry, error) {
	value := sel.Value
	rng, err := semver.NewConstraint(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid semver range %q: %w", value, err)
	}

	tags, err := r.mirror.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	type tagged struct {
		info scp.RefInfo
		ver  *semver.Version
	}
	var matches []tagged
	for _, t := range tags {
		v, err := semver.NewVersion(strings.TrimPrefix(t.Name, "v"))
		if err != nil {
			continue
		}
		if v.Prerelease() != "" && !r.opts.IncludePreRelease {
			// skip prerelease tags unless explicitly allowed
			continue
		}
		if rng.Check(v) {
			matches = append(matches, tagged{info: t, ver: v})
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %s", errRangeNoMatches, value)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].ver.LessThan(matches[j].ver)
	})

	var results []resolvedEntry
	for _, match := range matches {
		tagSel := scp.Selector{
			Raw:        "tag:" + match.info.Name,
			Type:       scp.SelectorTag,
			Value:      match.info.Name,
			IsFloating: false,
		}
		name := scp.NameForSelector(tagSel.Raw, tagSel.Type, tagSel.Value, match.info.Object)
		results = append(results, resolvedEntry{
			Name:       name,
			Selector:   tagSel,
			Commit:     match.info.Object,
			Provenance: "tag",
			Labels: map[string]string{
				"selector": "tag",
				"tag":      match.info.Name,
			},
		})
	}

	return results, nil
}

func (r *resolver) matchBranches(ctx context.Context, pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}, nil
	}
	branches, err := r.mirror.ListBranches(ctx)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, br := range branches {
		ok, err := filepath.Match(pattern, br.Name)
		if err != nil {
			return nil, err
		}
		if ok {
			matches = append(matches, br.Name)
		}
	}

	return matches, nil
}

func provenanceBranch(freeze string) string {
	if freeze == "" {
		return "branch"
	}

	return fmt.Sprintf("branch@%s", freeze)
}

func selWithValue(sel scp.Selector, value string) scp.Selector {
	sel.Value = value
	sel.Raw = string(sel.Type) + ":" + value

	return sel
}
