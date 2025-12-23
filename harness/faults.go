// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"encoding/binary"
	"sync"

	"github.com/pion/transport/vnet"
)

type faultMode string

const (
	faultModeChecksum       faultMode = "checksum"
	faultModeBadChunkLen    faultMode = "bad-chunk-len"
	faultModeNonZeroPadding faultMode = "nonzero-padding"
)

type faultSpec struct {
	Mode  faultMode
	Every int
}

type faultInjector struct {
	spec faultSpec
	mu   sync.Mutex
	seen int
}

func newFaultInjector(spec faultSpec) *faultInjector {
	if spec.Every <= 0 || spec.Mode == "" {
		return nil
	}
	return &faultInjector{spec: spec}
}

func (f *faultInjector) Filter(c vnet.Chunk) bool {
	if f == nil || c == nil || c.Network() != "udp" {
		return true
	}
	data := c.UserData()
	chunkType, chunkLen, offset, ok := firstChunkInfo(data)
	if !ok {
		return true
	}
	if chunkType == sctpChunkTypeInit || chunkType == sctpChunkTypeInitAck {
		return true
	}

	f.mu.Lock()
	f.seen++
	shouldFault := f.seen%f.spec.Every == 0
	f.mu.Unlock()
	if !shouldFault {
		return true
	}

	switch f.spec.Mode {
	case faultModeChecksum:
		if len(data) > 0 {
			data[len(data)-1] ^= 0xFF
		}
	case faultModeBadChunkLen:
		binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(sctpChunkHeaderSize-1))
		rewriteChecksum(data)
	case faultModeNonZeroPadding:
		if chunkLen%4 == 0 {
			return true
		}
		padOffset := offset + chunkLen
		if padOffset >= len(data) {
			return true
		}
		data[padOffset] = 0xFF
		rewriteChecksum(data)
	}

	return true
}

func firstChunkInfo(data []byte) (chunkType byte, chunkLen int, offset int, ok bool) {
	if len(data) < sctpHeaderSize+sctpChunkHeaderSize {
		return 0, 0, 0, false
	}
	offset = sctpHeaderSize
	chunkType = data[offset]
	chunkLen = int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	if chunkLen < sctpChunkHeaderSize {
		return 0, 0, 0, false
	}
	if offset+chunkLen > len(data) {
		return 0, 0, 0, false
	}

	return chunkType, chunkLen, offset, true
}

func rewriteChecksum(data []byte) {
	if len(data) < sctpHeaderSize {
		return
	}
	sum := computeSCTPChecksum(data)
	binary.LittleEndian.PutUint32(data[8:12], sum)
}
