// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type SelectorType string

const (
	SelectorTag    SelectorType = "tag"
	SelectorBranch SelectorType = "branch"
	SelectorCommit SelectorType = "commit"
	SelectorPR     SelectorType = "pr"
	SelectorPath   SelectorType = "path"
	SelectorRange  SelectorType = "range"
)

type Selector struct {
	Raw        string
	Type       SelectorType
	Value      string
	Flags      map[string]string
	IsFloating bool
}

var (
	errSelectorEmpty       = errors.New("selector empty")
	errSelectorMissingType = errors.New("selector missing type")
	errSelectorUnsupported = errors.New("selector type unsupported")
)

func ParseSelector(raw string) (Selector, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Selector{}, errSelectorEmpty
	}

	prefix, value, err := splitSelector(trimmed)
	if err != nil {
		return Selector{}, err
	}

	sel := Selector{
		Raw:        trimmed,
		Type:       SelectorType(strings.ToLower(prefix)),
		Value:      value,
		Flags:      map[string]string{},
		IsFloating: false,
	}

	if err := normaliseSelector(&sel); err != nil {
		return Selector{}, err
	}

	return sel, nil
}

func splitSelector(raw string) (prefix string, value string, err error) {
	colon := strings.IndexByte(raw, ':')
	if colon <= 0 {
		return "", "", fmt.Errorf("%w: %q", errSelectorMissingType, raw)
	}

	return raw[:colon], raw[colon+1:], nil
}

func normaliseSelector(sel *Selector) error {
	switch sel.Type {
	case SelectorTag:
	case SelectorBranch:
		sel.IsFloating = true
	case SelectorCommit:
	case SelectorPR:
		sel.IsFloating = true
	case SelectorPath:
		cleaned := strings.TrimSpace(sel.Value)
		if cleaned != "" {
			if !filepath.IsAbs(cleaned) {
				cleaned = filepath.Join(".", cleaned)
			}
			sel.Value = filepath.Clean(cleaned)
		}
	case SelectorRange:
		sel.IsFloating = true
	default:
		return fmt.Errorf("%w: %s", errSelectorUnsupported, sel.Type)
	}

	return nil
}
