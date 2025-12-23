// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"sync"
	"time"

	"github.com/pion/transport/vnet"
)

const (
	sctpHeaderSize       = 12
	sctpChunkHeaderSize  = 4
	sctpChunkTypeData    = 0x00
	sctpChunkTypeInit    = 0x01
	sctpChunkTypeInitAck = 0x02
)

var (
	wireChecksumTable = crc32.MakeTable(crc32.Castagnoli)
	wireZeroes        [4]byte
)

type wireValidator struct {
	mu             sync.Mutex
	totalPackets   int
	checksumErrors int
	parseErrors    int
	shortPackets   int
	logErrors      int
	firstError     string
	logger         *packetLogger
}

type wireSummary struct {
	TotalPackets   int
	ChecksumErrors int
	ParseErrors    int
	ShortPackets   int
	LogErrors      int
	FirstError     string
}

func (w wireSummary) Err() error {
	if w.ChecksumErrors == 0 && w.ShortPackets == 0 && w.ParseErrors == 0 && w.LogErrors == 0 {
		return nil
	}
	if w.FirstError != "" {
		return fmt.Errorf("wire: checksum_errors=%d parse_errors=%d short_packets=%d log_errors=%d first_error=%s", w.ChecksumErrors, w.ParseErrors, w.ShortPackets, w.LogErrors, w.FirstError)
	}
	return fmt.Errorf("wire: checksum_errors=%d parse_errors=%d short_packets=%d log_errors=%d", w.ChecksumErrors, w.ParseErrors, w.ShortPackets, w.LogErrors)
}

func newWireValidator(logger *packetLogger) *wireValidator {
	return &wireValidator{logger: logger}
}

func (v *wireValidator) Filter(c vnet.Chunk) bool {
	if c == nil || c.Network() != "udp" {
		return true
	}

	data := c.UserData()
	index := v.incrementTotal()
	src := c.SourceAddr().String()
	dst := c.DestinationAddr().String()
	record := packetRecord{
		Timestamp:   time.Now().UTC(),
		PacketIndex: index,
		Source:      src,
		Destination: dst,
		Length:      len(data),
		DataHex:     hex.EncodeToString(data),
	}
	if len(data) < sctpHeaderSize {
		msg := fmt.Sprintf("short packet len=%d src=%s dst=%s", len(data), src, dst)
		v.recordShort(msg)
		record.ParseError = msg
		v.logPacket(record)
		return true
	}

	their := binary.LittleEndian.Uint32(data[8:12])
	ours := computeSCTPChecksum(data)
	record.Checksum = their
	record.ChecksumExpected = ours
	record.ChecksumOK = their == ours
	if their != ours {
		v.recordChecksum(fmt.Sprintf("checksum mismatch src=%s dst=%s got=%d want=%d", src, dst, their, ours))
	}
	tag, parseErr := validateSCTP(data)
	record.VerificationTag = tag
	if parseErr != nil {
		v.recordParse(parseErr.Error())
		record.ParseError = parseErr.Error()
	}
	v.logPacket(record)

	return true
}

func (v *wireValidator) Summary() wireSummary {
	v.mu.Lock()
	defer v.mu.Unlock()

	return wireSummary{
		TotalPackets:   v.totalPackets,
		ChecksumErrors: v.checksumErrors,
		ParseErrors:    v.parseErrors,
		ShortPackets:   v.shortPackets,
		LogErrors:      v.logErrors,
		FirstError:     v.firstError,
	}
}

func (v *wireValidator) incrementTotal() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.totalPackets++
	return v.totalPackets
}

func (v *wireValidator) recordChecksum(msg string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checksumErrors++
	if v.firstError == "" {
		v.firstError = msg
	}
}

func (v *wireValidator) recordShort(msg string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.shortPackets++
	if v.firstError == "" {
		v.firstError = msg
	}
}

func (v *wireValidator) recordParse(msg string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.parseErrors++
	if v.firstError == "" {
		v.firstError = msg
	}
}

func (v *wireValidator) recordLog(msg string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.logErrors++
	if v.firstError == "" {
		v.firstError = msg
	}
}

func (v *wireValidator) logPacket(record packetRecord) {
	if v.logger == nil {
		return
	}
	if err := v.logger.Log(record); err != nil {
		v.recordLog(fmt.Sprintf("packet log: %v", err))
	}
}

func computeSCTPChecksum(raw []byte) uint32 {
	sum := crc32.Update(0, wireChecksumTable, raw[0:8])
	sum = crc32.Update(sum, wireChecksumTable, wireZeroes[:])
	if len(raw) > sctpHeaderSize {
		sum = crc32.Update(sum, wireChecksumTable, raw[12:])
	}

	return sum
}

func validateSCTP(raw []byte) (uint32, error) {
	if len(raw) < sctpHeaderSize {
		return 0, fmt.Errorf("short packet len=%d", len(raw))
	}

	tag := binary.BigEndian.Uint32(raw[4:8])
	offset := sctpHeaderSize
	foundInit := false
	seenTSN := map[uint32]struct{}{}

	if offset == len(raw) {
		return tag, fmt.Errorf("missing chunks len=%d", len(raw))
	}

	for offset < len(raw) {
		if len(raw[offset:]) < sctpChunkHeaderSize {
			return tag, fmt.Errorf("short chunk header len=%d offset=%d", len(raw[offset:]), offset)
		}

		chunkType := raw[offset]
		chunkLen := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		if chunkLen < sctpChunkHeaderSize {
			return tag, fmt.Errorf("chunk too short type=%d len=%d offset=%d", chunkType, chunkLen, offset)
		}
		if offset+chunkLen > len(raw) {
			return tag, fmt.Errorf("chunk overruns packet type=%d len=%d offset=%d packet_len=%d", chunkType, chunkLen, offset, len(raw))
		}
		if chunkType == sctpChunkTypeData && chunkLen < 16 {
			return tag, fmt.Errorf("data chunk too short len=%d offset=%d", chunkLen, offset)
		}
		if chunkType == sctpChunkTypeData {
			tsn := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
			if _, exists := seenTSN[tsn]; exists {
				return tag, fmt.Errorf("duplicate tsn=%d offset=%d", tsn, offset)
			}
			seenTSN[tsn] = struct{}{}
		}
		if chunkType == sctpChunkTypeInit || chunkType == sctpChunkTypeInitAck {
			foundInit = true
		}

		offset += chunkLen
		for offset%4 != 0 {
			if offset >= len(raw) {
				return tag, fmt.Errorf("padding overruns packet offset=%d packet_len=%d", offset, len(raw))
			}
			if raw[offset] != 0 {
				return tag, fmt.Errorf("non-zero padding offset=%d value=%d", offset, raw[offset])
			}
			offset++
		}
	}

	if tag == 0 && !foundInit {
		return tag, fmt.Errorf("invalid verification tag=0 without INIT")
	}

	return tag, nil
}
