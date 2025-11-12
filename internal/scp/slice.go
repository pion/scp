package scp

import "strings"

func SplitAndTrim(fields []string) []string {
	var out []string
	for _, field := range fields {
		for _, part := range strings.Split(field, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}

	return out
}
