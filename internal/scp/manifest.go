// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

type Manifest struct {
	Schema  int             `json:"schema"`
	Repo    string          `json:"repo"`
	Entries []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Name     string `json:"name"`
	Selector string `json:"selector"`
}
