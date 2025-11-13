// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

type Lockfile struct {
	Schema      int          `json:"schema"`
	GeneratedAt string       `json:"generatedAt"`
	Entries     []LockEntry  `json:"entries"`
	Version     string       `json:"version,omitempty"`
	Metadata    LockMetadata `json:"metadata,omitempty"`
}

type LockEntry struct {
	Name       string            `json:"name"`
	Selector   string            `json:"selector"`
	Commit     string            `json:"commit"`
	Provenance string            `json:"provenance"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type LockMetadata struct {
	Repository string `json:"repository,omitempty"`
}
