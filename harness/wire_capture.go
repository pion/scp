// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type packetRecord struct {
	Timestamp        time.Time `json:"timestamp"`
	PacketIndex      int       `json:"packet_index"`
	Source           string    `json:"source"`
	Destination      string    `json:"destination"`
	Length           int       `json:"length"`
	VerificationTag  uint32    `json:"verification_tag"`
	Checksum         uint32    `json:"checksum"`
	ChecksumExpected uint32    `json:"checksum_expected"`
	ChecksumOK       bool      `json:"checksum_ok"`
	ParseError       string    `json:"parse_error,omitempty"`
	DataHex          string    `json:"data_hex"`
}

type packetLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
	err  error
}

func newPacketLogger(path string) (*packetLogger, error) {
	if path == "" {
		return nil, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}

	return &packetLogger{
		file: file,
		enc:  json.NewEncoder(file),
	}, nil
}

func (l *packetLogger) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}

func (l *packetLogger) Log(record packetRecord) error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.err != nil {
		return l.err
	}
	if err := l.enc.Encode(record); err != nil {
		l.err = err
		return err
	}

	return nil
}
