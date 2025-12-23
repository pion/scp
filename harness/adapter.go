// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"net"
	"time"

	"github.com/pion/logging"
)

// AdapterFactory creates a new SCTP adapter instance.
type AdapterFactory func() Adapter

// Adapter exposes the minimum SCTP surface needed by the harness.
type Adapter interface {
	// Name returns the adapter identifier.
	Name() string
	// Client establishes a client-side association.
	Client(Config) (Association, error)
	// Server establishes a server-side association.
	Server(Config) (Association, error)
}

// Config contains the transport wiring for SCTP.
type Config struct {
	NetConn            net.Conn
	LoggerFactory      logging.LoggerFactory
	EnableInterleaving bool
	MaxMessageSize     uint32
}

// Association represents an SCTP association.
type Association interface {
	OpenStream(streamID uint16, payloadType uint32) (Stream, error)
	AcceptStream() (Stream, error)
	BytesSent() uint64
	BytesReceived() uint64
	Close() error
}

// Stream represents an SCTP stream.
type Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetReliabilityParams(unordered bool, relType byte, relVal uint32)
	Close() error
}

const (
	// PayloadTypeWebRTCBinary matches pion/sctp payload identifier for binary.
	PayloadTypeWebRTCBinary uint32 = 53
	// ReliabilityTypeReliable matches pion/sctp reliable transmission.
	ReliabilityTypeReliable byte = 0
)
