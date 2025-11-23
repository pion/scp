// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
	"github.com/pion/transport/vnet"
	"golang.org/x/sys/unix"
)

const (
	minBurstPackets     = 64
	burstRange          = 512 - minBurstPackets + 1
	burstPayloadOctets  = 1200
	minPacketsPerSecond = 1.0
)

func runMaxBurstCase(ctx context.Context, pairs []pair, baseSeed int64, repeat int) ([]scenarioResult, error) {
	if len(pairs) == 0 {
		return nil, errInsufficientEntries
	}

	resolvedSeed := baseSeed
	if resolvedSeed == 0 {
		resolvedSeed = deriveDefaultSeed(pairs)
	}

	results := make([]scenarioResult, 0, len(pairs)*repeat)
	for idx, pair := range pairs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		for iter := range repeat {
			result := scenarioResult{
				CaseName:  caseMaxBurst,
				Pair:      pair,
				Iteration: iter + 1,
			}

			seq := idx*repeat + iter
			if isSelfPair(pair) {
				seq = iter
			}

			forward, reverse, metrics, err := runBurstTraffic(ctx, pair, resolvedSeed, seq)
			result.ForwardBurst = forward
			result.ReverseBurst = reverse
			result.Metrics = metrics
			result.Passed = forward >= minBurstPackets && reverse >= minBurstPackets
			result.Details = fmt.Sprintf("run=%d %s->%s=%d packets, %s->%s=%d packets",
				iter+1, pair.Left.Name, pair.Right.Name, forward, pair.Right.Name, pair.Left.Name, reverse,
			)
			if err != nil || !result.Passed {
				result.Details += fmt.Sprintf(" err=%v", err)
			}
			if err != nil {
				result.Errored = true
			}
			if metrics.PacketsPerSecond > 0 && metrics.PacketsPerSecond < minPacketsPerSecond {
				result.Passed = false
				result.Details += fmt.Sprintf(" rate=%.2fpps<threshold(%.2f)", metrics.PacketsPerSecond, minPacketsPerSecond)
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func runBurstTraffic(ctx context.Context, p pair, baseSeed int64, idx int) (int, int, resultMetrics, error) {
	return runBurstTrafficProfile(ctx, p, baseSeed, idx, networkProfile{})
}

func runBurstTrafficProfile(ctx context.Context, p pair, baseSeed int64, idx int, profile networkProfile) (int, int, resultMetrics, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	seed := derivePairSeed(baseSeed, p, idx)
	if isSelfPair(p) {
		seed = deriveSelfSeed(baseSeed, idx)
	}
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed>>1))) //nolint:gosec // not cryptographic purpose
	target := minBurstPackets + rng.IntN(burstRange)
	targetForward := target
	targetReverse := target
	payload := make([]byte, burstPayloadOctets)
	for i := range payload {
		payload[i] = byte(rng.IntN(256))
	}
	// ensure payload has room for timestamp + sequence
	if len(payload) < 16 {
		payload = make([]byte, 16)
	}

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "10.0.0.0/24",
		QueueSize:     4096,
		MinDelay:      profile.MinDelay,
		MaxJitter:     profile.MaxJitter,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("burst: router: %w", err)
	}
	if profile.DropPercent > 0 {
		rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed>>1))) //nolint:gosec
		router.AddChunkFilter(func(c vnet.Chunk) bool {
			value := rng.IntN(1000)
			return float64(value)/10.0 >= profile.DropPercent
		})
	}
	leftNet := vnet.NewNet(&vnet.NetConfig{StaticIP: "10.0.0.1"})
	rightNet := vnet.NewNet(&vnet.NetConfig{StaticIP: "10.0.0.2"})
	if err := router.AddNet(leftNet); err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("burst: add left net: %w", err)
	}
	if err := router.AddNet(rightNet); err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("burst: add right net: %w", err)
	}
	if err := router.Start(); err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("burst: start router: %w", err)
	}
	defer func() {
		_ = router.Stop()
	}()

	startCPU := readCPUSeconds()
	startTime := time.Now()

	forward, reverse, latencies, stats, err := runSCTPBurst(ctx, leftNet, rightNet, targetForward, targetReverse, payload, profile.Unordered)

	duration := time.Since(startTime)
	cpu := readCPUSeconds() - startCPU
	packets := forward + reverse
	pps := 0.0
	if duration > 0 {
		pps = float64(packets) / duration.Seconds()
	}

	latP50, latP90, latP99 := computePercentiles(latencies)
	metrics := resultMetrics{
		Duration:         duration,
		PacketsPerSecond: pps,
		CPUSeconds:       cpu,
		LatencyP50:       latP50,
		LatencyP90:       latP90,
		LatencyP99:       latP99,
		BytesSent:        stats.BytesSent,
		BytesReceived:    stats.BytesReceived,
		Reordered:        stats.Reordered,
		Retransmitted:    stats.Retransmitted,
		GoodputBps:       goodput(stats.BytesReceived, duration),
		TailRecovery:     stats.TailRecovery,
		Target:           target,
	}

	if err != nil {
		if (errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err)) && forward >= minBurstPackets && reverse >= minBurstPackets {
			err = nil
		} else {
			return forward, reverse, metrics, err
		}
	}
	if forward < minBurstPackets || reverse < minBurstPackets {
		return forward, reverse, metrics, fmt.Errorf("burst: incomplete forward=%d reverse=%d target=%d", forward, reverse, target)
	}

	return forward, reverse, metrics, nil
}

type sctpSession struct {
	clientAssoc  *sctp.Association
	serverAssoc  *sctp.Association
	clientStream *sctp.Stream
	serverStream *sctp.Stream
	clientConn   net.Conn
	serverConn   net.Conn
}

type assocResult struct {
	assoc *sctp.Association
	err   error
}

type streamResult struct {
	stream *sctp.Stream
	err    error
}

type resultMetrics struct {
	Duration         time.Duration
	PacketsPerSecond float64
	CPUSeconds       float64
	LatencyP50       time.Duration
	LatencyP90       time.Duration
	LatencyP99       time.Duration
	BytesSent        uint64
	BytesReceived    uint64
	Reordered        int
	Retransmitted    int
	Dropped          int
	GoodputBps       float64
	TailRecovery     time.Duration
	Target           int
}

type assocStats struct {
	BytesSent     uint64
	BytesReceived uint64
	Reordered     int
	Retransmitted int
	Dropped       int
	TailRecovery  time.Duration
}

type receiveResult struct {
	count        int
	latencies    []time.Duration
	reordered    int
	retrans      int
	tailRecovery time.Duration
	dropped      int
}

func runSCTPBurst(ctx context.Context, leftNet, rightNet *vnet.Net, forwardPackets, reversePackets int, payload []byte, unordered bool) (int, int, []time.Duration, assocStats, error) {
	session, err := establishSCTPSession(ctx, leftNet, rightNet)
	if err != nil {
		return 0, 0, nil, assocStats{}, err
	}
	defer session.close()

	if err := warmupStreams(ctx, session.clientStream, session.serverStream); err != nil {
		var netErr net.Error
		if !(isTimeoutErr(err) || (errors.As(err, &netErr) && netErr.Timeout())) {
			return 0, 0, nil, assocStats{}, fmt.Errorf("sctp: warmup: %w", err)
		}
	}

	forwardCh := make(chan receiveResult, 1)
	reverseCh := make(chan receiveResult, 1)

	go func() {
		count, lats, reorder, retrans, tail, dropped := receivePackets(ctx, session.serverStream, forwardPackets, len(payload))
		forwardCh <- receiveResult{count: count, latencies: lats, reordered: reorder, retrans: retrans, tailRecovery: tail, dropped: dropped}
	}()
	go func() {
		count, lats, reorder, retrans, tail, dropped := receivePackets(ctx, session.clientStream, reversePackets, len(payload))
		reverseCh <- receiveResult{count: count, latencies: lats, reordered: reorder, retrans: retrans, tailRecovery: tail, dropped: dropped}
	}()

	if unordered {
		session.clientStream.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0) //nolint:errcheck
		session.serverStream.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0) //nolint:errcheck
	}

	sendErr := transmitPackets(ctx, session.clientStream, forwardPackets, payload)
	sendErr = errors.Join(sendErr, transmitPackets(ctx, session.serverStream, reversePackets, payload))

	forwardRes := <-forwardCh
	reverseRes := <-reverseCh
	forward := forwardRes.count
	reverse := reverseRes.count
	forwardLat := forwardRes.latencies
	reverseLat := reverseRes.latencies

	if sendErr != nil {
		return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), sendErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), ctxErr
	}

	return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), nil
}

func establishSCTPSession(ctx context.Context, leftNet, rightNet *vnet.Net) (*sctpSession, error) {
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000}
	clientAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5001}

	serverConn, err := rightNet.DialUDP("udp4", serverAddr, clientAddr)
	if err != nil {
		return nil, fmt.Errorf("sctp: server dial: %w", err)
	}

	clientConn, err := leftNet.DialUDP("udp4", clientAddr, serverAddr)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("sctp: client dial: %w", err)
	}

	serverConfig := sctp.Config{
		NetConn:       serverConn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}
	clientConfig := sctp.Config{
		NetConn:       clientConn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	serverAssocCh := make(chan *sctp.Association, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		assoc, serveErr := sctp.Server(serverConfig)
		if serveErr != nil {
			serverErrCh <- serveErr
			return
		}
		serverAssocCh <- assoc
	}()

	clientAssocCh := make(chan assocResult, 1)
	go func() {
		assoc, assocErr := sctp.Client(clientConfig)
		clientAssocCh <- assocResult{assoc: assoc, err: assocErr}
	}()

	var clientAssoc *sctp.Association
	select {
	case res := <-clientAssocCh:
		if res.err != nil {
			serverConn.Close()
			clientConn.Close()
			return nil, fmt.Errorf("sctp: client: %w", res.err)
		}
		clientAssoc = res.assoc
	case <-ctx.Done():
		serverConn.Close()
		clientConn.Close()
		return nil, ctx.Err()
	}

	var serverAssoc *sctp.Association
	select {
	case serverErr := <-serverErrCh:
		clientAssoc.Close()
		serverConn.Close()
		clientConn.Close()
		return nil, fmt.Errorf("sctp: server: %w", serverErr)
	case serverAssoc = <-serverAssocCh:
	case <-ctx.Done():
		clientAssoc.Close()
		serverConn.Close()
		clientConn.Close()
		return nil, ctx.Err()
	}

	clientStreamCh := make(chan streamResult, 1)
	go func() {
		stream, streamErr := clientAssoc.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
		clientStreamCh <- streamResult{stream: stream, err: streamErr}
	}()
	serverStreamCh := make(chan streamResult, 1)
	go func() {
		stream, streamErr := serverAssoc.AcceptStream()
		serverStreamCh <- streamResult{stream: stream, err: streamErr}
	}()

	var clientStream *sctp.Stream
	var serverStream *sctp.Stream
	for clientStream == nil || serverStream == nil {
		select {
		case res := <-clientStreamCh:
			if res.err != nil {
				serverAssoc.Close()
				clientAssoc.Close()
				serverConn.Close()
				clientConn.Close()
				return nil, fmt.Errorf("sctp: open stream: %w", res.err)
			}
			clientStream = res.stream
			// Kick the server side by sending an initial warmup packet.
			_ = clientStream.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = clientStream.Write(make([]byte, 8))
		case res := <-serverStreamCh:
			if res.err != nil {
				serverAssoc.Close()
				clientAssoc.Close()
				serverConn.Close()
				clientConn.Close()
				return nil, fmt.Errorf("sctp: accept stream: %w", res.err)
			}
			serverStream = res.stream
		case <-ctx.Done():
			serverAssoc.Close()
			clientAssoc.Close()
			serverConn.Close()
			clientConn.Close()
			return nil, ctx.Err()
		}
	}

	return &sctpSession{
		clientAssoc:  clientAssoc,
		serverAssoc:  serverAssoc,
		clientStream: clientStream,
		serverStream: serverStream,
		clientConn:   clientConn,
		serverConn:   serverConn,
	}, nil
}

func (s *sctpSession) close() {
	_ = s.clientStream.Close()
	_ = s.serverStream.Close()
	_ = s.clientAssoc.Close()
	_ = s.serverAssoc.Close()
	_ = s.clientConn.Close()
	_ = s.serverConn.Close()
}

func warmupStreams(ctx context.Context, clientStream, serverStream *sctp.Stream) error {
	handshake := []byte("warmup")
	const attempts = 3
	for i := 0; i < attempts; i++ {
		if err := sendOne(ctx, clientStream, handshake); err != nil {
			if isTimeoutErr(err) {
				continue
			}
			return err
		}
		if err := recvOne(serverStream, len(handshake)); err != nil {
			if isTimeoutErr(err) {
				continue
			}
			return err
		}
		if err := sendOne(ctx, serverStream, handshake); err != nil {
			if isTimeoutErr(err) {
				continue
			}
			return err
		}
		if err := recvOne(clientStream, len(handshake)); err != nil {
			if isTimeoutErr(err) {
				continue
			}
			return err
		}
		return nil
	}

	return fmt.Errorf("warmup: exceeded retries")
}

func sendOne(ctx context.Context, stream *sctp.Stream, payload []byte) error {
	if err := stream.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return err
	}
	if _, err := stream.Write(payload); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}

		return err
	}

	return nil
}

func recvOne(stream *sctp.Stream, payloadSize int) error {
	buf := make([]byte, payloadSize+16)
	if err := stream.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return err
	}
	if _, err := stream.Read(buf); err != nil {
		return err
	}

	return nil
}

func receivePackets(ctx context.Context, stream *sctp.Stream, packets int, payloadSize int) (int, []time.Duration, int, int, time.Duration, int) {
	buf := make([]byte, payloadSize+16)
	count := 0
	latencies := make([]time.Duration, 0, packets)
	seen := make(map[uint64]int, packets)
	expectedSeq := uint64(1)
	reordered := 0
	retrans := 0
	var lastSendTS int64
	var lastRecvTS time.Time
	dropped := 0
	for count < packets {
		_ = stream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := stream.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
				default:
					continue
				}
			}

			return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
		}
		count++
		if n >= 8 {
			sendTS := int64(binary.LittleEndian.Uint64(buf[:8]))
			if sendTS > 0 {
				latencies = append(latencies, time.Since(time.Unix(0, sendTS)))
				if sendTS > lastSendTS {
					lastSendTS = sendTS
				}
				lastRecvTS = time.Now()
			}
		}
		if n >= 16 {
			seq := binary.LittleEndian.Uint64(buf[8:16])
			if seq != expectedSeq {
				reordered++
			}
			if seen[seq] > 0 {
				retrans++
			}
			seen[seq]++
			if seq == expectedSeq {
				expectedSeq++
			}
			if seq > uint64(packets) {
				dropped++
			}
		}
	}

	return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
}

func recvTail(lastSendTS int64, lastRecvTS time.Time) time.Duration {
	if lastSendTS == 0 || lastRecvTS.IsZero() {
		return 0
	}
	return lastRecvTS.Sub(time.Unix(0, lastSendTS))
}

func transmitPackets(ctx context.Context, stream *sctp.Stream, packets int, payload []byte) error {
	seq := uint64(1)
	for i := 0; i < packets; {
		if err := stream.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return fmt.Errorf("burst: set write deadline: %w", err)
		}
		now := uint64(time.Now().UnixNano())
		binary.LittleEndian.PutUint64(payload[:8], now)
		binary.LittleEndian.PutUint64(payload[8:16], seq)
		if _, err := stream.Write(payload); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}

			return fmt.Errorf("burst: write: %w", err)
		}
		i++
		seq++

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}

func derivePairSeed(base int64, p pair, idx int) int64 {
	payload := fmt.Sprintf("%d:%s:%s:%s:%s:%d", base, p.Left.Name, p.Left.Commit, p.Right.Name, p.Right.Commit, idx)
	sum := sha256.Sum256([]byte(payload))

	return int64(binary.LittleEndian.Uint64(sum[:8])) //nolint:gosec // not cryptographic purpose
}

func deriveSelfSeed(base int64, idx int) int64 {
	payload := fmt.Sprintf("%d:self:%d", base, idx)
	sum := sha256.Sum256([]byte(payload))

	return int64(binary.LittleEndian.Uint64(sum[:8])) //nolint:gosec // not cryptographic purpose
}

func isSelfPair(p pair) bool {
	return p.Left.Name == p.Right.Name && p.Left.Commit == p.Right.Commit
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func collectStats(session *sctpSession, forward receiveResult, reverse receiveResult) assocStats {
	return assocStats{
		BytesSent:     session.clientAssoc.BytesSent() + session.serverAssoc.BytesSent(),
		BytesReceived: session.clientAssoc.BytesReceived() + session.serverAssoc.BytesReceived(),
		Reordered:     forward.reordered + reverse.reordered,
		Retransmitted: forward.retrans + reverse.retrans,
		Dropped:       forward.dropped + reverse.dropped,
		TailRecovery:  maxDuration(forward.tailRecovery, reverse.tailRecovery),
	}
}

func computePercentiles(latencies []time.Duration) (time.Duration, time.Duration, time.Duration) {
	if len(latencies) == 0 {
		return 0, 0, 0
	}
	values := make([]time.Duration, len(latencies))
	copy(values, latencies)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	p50 := values[len(values)*50/100]
	p90 := values[len(values)*90/100]
	p99 := values[len(values)*99/100]

	return p50, p90, p99
}

func readCPUSeconds() float64 {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0
	}

	user := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1_000_000
	sys := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1_000_000

	return user + sys
}

func formatMetrics(m resultMetrics) string {
	return fmt.Sprintf("duration=%s pps=%.2f cpu=%.4fs p50=%s p90=%s p99=%s bytes_sent=%d bytes_recv=%d dropped=%d reordered=%d retrans=%d goodput=%.2fbps tail=%s target=%d",
		m.Duration,
		m.PacketsPerSecond,
		m.CPUSeconds,
		m.LatencyP50,
		m.LatencyP90,
		m.LatencyP99,
		m.BytesSent,
		m.BytesReceived,
		m.Dropped,
		m.Reordered,
		m.Retransmitted,
		m.GoodputBps,
		m.TailRecovery,
		m.Target,
	)
}

func goodput(bytes uint64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds()
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func deriveDefaultSeed(pairs []pair) int64 {
	var builder strings.Builder
	for _, p := range pairs {
		builder.WriteString(p.Left.Name)
		builder.WriteByte(':')
		builder.WriteString(p.Left.Commit)
		builder.WriteByte('|')
		builder.WriteString(p.Right.Name)
		builder.WriteByte(':')
		builder.WriteString(p.Right.Commit)
		builder.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	seed := int64(binary.LittleEndian.Uint64(sum[:8])) //nolint:gosec // not cryptographic purpose
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	return seed
}
