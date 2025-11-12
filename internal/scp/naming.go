package scp

import (
	"regexp"
	"strings"
)

var (
	nonAlnum      = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	suffixAllowed = regexp.MustCompile(`[a-f0-9]+`)
)

func Slugify(input string) string {
	if input == "" {
		return "entry"
	}
	s := nonAlnum.ReplaceAllString(input, "_")
	s = strings.Trim(s, "_")
	s = strings.ToLower(s)
	if s == "" {
		return "entry"
	}

	return s
}

func WithSuffix(base, sha string) string {
	if len(sha) > 7 {
		sha = sha[:7]
	}
	sha = sanitizeSuffix(sha)
	base = Slugify(base)
	if sha == "" {
		return base
	}
	if strings.HasSuffix(base, sha) {
		return base
	}

	return base + "_" + sha
}

func NameForSelector(raw string, selType SelectorType, value string, commit string) string {
	switch selType {
	case SelectorTag:
		return Slugify(value)
	case SelectorBranch:
		return WithSuffix("branch_"+Slugify(value), commit)
	case SelectorPR:
		return WithSuffix("pr_"+Slugify(value), commit)
	case SelectorCommit:
		return WithSuffix("sha", commit)
	case SelectorPath:
		return WithSuffix("local_"+Slugify(value), commit)
	case SelectorRange:
		return WithSuffix(Slugify(value), commit)
	default:
		return WithSuffix(Slugify(raw), commit)
	}
}

func sanitizeSuffix(sha string) string {
	sha = strings.ToLower(sha)
	if matches := suffixAllowed.FindAllString(sha, -1); len(matches) > 0 {
		return matches[0]
	}

	return ""
}
