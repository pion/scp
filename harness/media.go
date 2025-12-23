// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/vnet"
)

const (
	defaultMediaPattern   = "IPBBPBBPBBPB"
	rtpHeaderSize         = 12
	rtpHeaderExtensionLen = 8
	rtpPayloadOffset      = rtpHeaderSize + rtpHeaderExtensionLen
	rtpPayloadType        = 96
	rtpClockRate          = 90_000
)

type mediaSpec struct {
	BitrateBps      int
	FramesPerSecond int
	Duration        time.Duration
	MaxPayload      int
	Pattern         string
	OneWay          bool
	DrainTimeout    time.Duration
	MinDeliveryPct  float64
	Streams         int
	JitterBuffer    time.Duration
}

type mediaPlan struct {
	FrameSizes    []int
	MaxPayload    int
	FrameInterval time.Duration
	TotalPackets  int
	TotalBytes    int
}

func (spec mediaSpec) withDefaults() mediaSpec {
	if spec.BitrateBps <= 0 {
		spec.BitrateBps = 14_000_000
	}
	if spec.FramesPerSecond <= 0 {
		spec.FramesPerSecond = 30
	}
	if spec.Duration <= 0 {
		spec.Duration = 2 * time.Second
	}
	if spec.MaxPayload <= 0 {
		spec.MaxPayload = burstPayloadOctets
	}
	if spec.Pattern == "" {
		spec.Pattern = defaultMediaPattern
	}
	if spec.DrainTimeout <= 0 {
		spec.DrainTimeout = 1 * time.Second
	}
	if spec.MinDeliveryPct <= 0 {
		spec.MinDeliveryPct = 100
	}
	if spec.MinDeliveryPct > 100 {
		spec.MinDeliveryPct = 100
	}
	if spec.Streams <= 0 {
		spec.Streams = 1
	}
	if spec.JitterBuffer < 0 {
		spec.JitterBuffer = 0
	}

	return spec
}

func runMediaTrafficProfile(
	ctx context.Context,
	p pair,
	baseSeed int64,
	idx int,
	profile networkProfile,
	logPath string,
	policy casePolicy,
	fault *faultSpec,
	spec mediaSpec,
	enableInterleaving bool,
	maxMessageSize uint32,
) (int, int, resultMetrics, error) {
	seed := derivePairSeed(baseSeed, idx)
	spec = spec.withDefaults()
	plan, err := buildMediaPlan(spec)
	if err != nil {
		return 0, 0, resultMetrics{}, err
	}

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "10.0.0.0/24",
		QueueSize:     4096,
		MinDelay:      profile.MinDelay,
		MaxJitter:     profile.MaxJitter,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("media: router: %w", err)
	}
	logger, err := newPacketLogger(logPath)
	if err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("media: packet logger: %w", err)
	}
	if logger != nil {
		defer func() {
			_ = logger.Close()
		}()
	}
	if fault != nil {
		if faultInjector := newFaultInjector(*fault); faultInjector != nil {
			router.AddChunkFilter(faultInjector.Filter)
		}
	}
	validator := newWireValidator(logger)
	router.AddChunkFilter(validator.Filter)
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
		return 0, 0, resultMetrics{}, fmt.Errorf("media: add left net: %w", err)
	}
	if err := router.AddNet(rightNet); err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("media: add right net: %w", err)
	}
	if err := router.Start(); err != nil {
		return 0, 0, resultMetrics{}, fmt.Errorf("media: start router: %w", err)
	}
	defer func() {
		_ = router.Stop()
	}()

	startCPU := readCPUSeconds()
	startTime := time.Now()

	leftAdapter, rightAdapter, err := instantiateAdapters(p)
	if err != nil {
		return 0, 0, resultMetrics{}, err
	}
	if enableInterleaving {
		leftOK := supportsInterleaving(leftAdapter)
		rightOK := supportsInterleaving(rightAdapter)
		if !leftOK || !rightOK {
			return 0, 0, resultMetrics{}, fmt.Errorf("%w: left=%s right=%s",
				errInterleavingUnsupported,
				supportLabel(leftAdapter, leftOK),
				supportLabel(rightAdapter, rightOK),
			)
		}
	}

	forward, reverse, latencies, stats, err := runSCTPMedia(
		ctx,
		leftNet,
		rightNet,
		leftAdapter,
		rightAdapter,
		plan,
		profile.Unordered,
		seed,
		sessionOptions{
			EnableInterleaving: enableInterleaving,
			MaxMessageSize:     maxMessageSize,
		},
		spec,
	)

	duration := time.Since(startTime)
	cpu := readCPUSeconds() - startCPU
	packets := forward + reverse
	pps := 0.0
	if duration > 0 {
		pps = float64(packets) / duration.Seconds()
	}

	latP50, latP90, latP99 := computePercentiles(latencies)
	wireSummary := validator.Summary()
	metrics := resultMetrics{
		Duration:         duration,
		PacketsPerSecond: pps,
		CPUSeconds:       cpu,
		LatencyP50:       latP50,
		LatencyP90:       latP90,
		LatencyP99:       latP99,
		BytesSent:        stats.BytesSent,
		BytesReceived:    stats.BytesReceived,
		Dropped:          stats.Dropped,
		Reordered:        stats.Reordered,
		Retransmitted:    stats.Retransmitted,
		WirePackets:      wireSummary.TotalPackets,
		WireChecksumErrs: wireSummary.ChecksumErrors,
		WireParseErrors:  wireSummary.ParseErrors,
		WireShortPackets: wireSummary.ShortPackets,
		WireLogErrors:    wireSummary.LogErrors,
		GoodputBps:       goodput(stats.BytesReceived, duration),
		TailRecovery:     stats.TailRecovery,
		Target:           plan.TotalPackets,
	}

	if err != nil {
		if (errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err)) && policy.MinForward > 0 {
			if forward >= policy.MinForward && (policy.MinReverse == 0 || reverse >= policy.MinReverse) {
				err = nil
			}
		}
	}
	if err != nil {
		return forward, reverse, metrics, err
	}

	return forward, reverse, metrics, nil
}

func runSCTPMedia(
	ctx context.Context,
	leftNet, rightNet *vnet.Net,
	leftAdapter, rightAdapter Adapter,
	plan mediaPlan,
	unordered bool,
	seed int64,
	opts sessionOptions,
	spec mediaSpec,
) (int, int, []time.Duration, assocStats, error) {
	session, err := establishSCTPSession(ctx, leftNet, rightNet, leftAdapter, rightAdapter, opts)
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

	clientStreams, serverStreams, err := openMediaStreams(ctx, session, spec.Streams)
	if err != nil {
		return 0, 0, nil, assocStats{}, err
	}
	defer closeExtraStreams(clientStreams)
	defer closeExtraStreams(serverStreams)

	mediaCtx := ctx
	var cancel context.CancelFunc
	if spec.Duration > 0 || spec.DrainTimeout > 0 {
		timeout := spec.Duration + spec.DrainTimeout
		if timeout > 0 {
			mediaCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	sendDone := make(chan struct{})
	forwardCh := make(chan receiveResult, 1)
	var reverseCh chan receiveResult
	packetTargets := splitPackets(plan.TotalPackets, len(serverStreams))
	go func() {
		result := receiveMediaStreams(mediaCtx, serverStreams, packetTargets, plan.MaxPayload, sendDone, spec.DrainTimeout, spec.JitterBuffer)
		forwardCh <- result
	}()
	if !spec.OneWay {
		reverseCh = make(chan receiveResult, 1)
		go func() {
			result := receiveMediaStreams(mediaCtx, clientStreams, packetTargets, plan.MaxPayload, sendDone, spec.DrainTimeout, spec.JitterBuffer)
			reverseCh <- result
		}()
	}

	if unordered {
		for _, stream := range clientStreams {
			stream.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		}
		for _, stream := range serverStreams {
			stream.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		}
	}

	sendCh := make(chan error, 2)
	var sendWG sync.WaitGroup
	sendWG.Add(1)
	go func() {
		defer sendWG.Done()
		sendCh <- transmitMediaPackets(mediaCtx, clientStreams, plan, spec, seed)
	}()
	if !spec.OneWay {
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			sendCh <- transmitMediaPackets(mediaCtx, serverStreams, plan, spec, seed+1)
		}()
	}
	go func() {
		sendWG.Wait()
		close(sendDone)
	}()

	forwardRes := <-forwardCh
	var reverseRes receiveResult
	if spec.OneWay {
		reverseRes = receiveResult{}
	} else {
		reverseRes = <-reverseCh
	}
	var sendErr error
	if spec.OneWay {
		sendErr = <-sendCh
	} else {
		sendErr = errors.Join(<-sendCh, <-sendCh)
	}

	forward := forwardRes.count
	reverse := reverseRes.count
	forwardLat := forwardRes.latencies
	reverseLat := reverseRes.latencies

	if sendErr != nil {
		return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), sendErr
	}
	if ctxErr := mediaCtx.Err(); ctxErr != nil {
		return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), ctxErr
	}

	return forward, reverse, append(forwardLat, reverseLat...), collectStats(session, forwardRes, reverseRes), nil
}

func transmitMediaPackets(ctx context.Context, streams []Stream, plan mediaPlan, spec mediaSpec, seed int64) error {
	if len(streams) == 0 {
		return nil
	}
	payload := make([]byte, plan.MaxPayload)
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed>>1))) //nolint:gosec // not cryptographic purpose
	for i := rtpPayloadOffset; i < len(payload); i++ {
		payload[i] = byte(rng.IntN(256))
	}

	start := time.Now()
	frameInterval := plan.FrameInterval
	rtpStep := uint32(1)
	if spec.FramesPerSecond > 0 {
		rtpStep = uint32(rtpClockRate / spec.FramesPerSecond)
		if rtpStep == 0 {
			rtpStep = 1
		}
	}
	baseTS := rng.Uint32()
	seqs := make([]uint16, len(streams))
	ssrcs := make([]uint32, len(streams))
	for i := range seqs {
		seqs[i] = 1
		ssrcs[i] = rng.Uint32()
	}
	streamIdx := 0

	for frameIndex, frameSize := range plan.FrameSizes {
		remaining := frameSize
		packetsInFrame := (frameSize + plan.MaxPayload - 1) / plan.MaxPayload
		packetInterval := time.Duration(0)
		if packetsInFrame > 0 && frameInterval > 0 {
			packetInterval = frameInterval / time.Duration(packetsInFrame)
		}
		frameStart := start
		if frameInterval > 0 {
			frameStart = start.Add(time.Duration(frameIndex) * frameInterval)
		}
		for packetIndex := 0; packetIndex < packetsInFrame; packetIndex++ {
			size := remaining
			if size > plan.MaxPayload {
				size = plan.MaxPayload
			}
			if size < rtpPayloadOffset {
				size = rtpPayloadOffset
			}

			if err := streams[streamIdx].SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return fmt.Errorf("media: set write deadline: %w", err)
			}
			timestamp := baseTS + uint32(frameIndex)*rtpStep
			marker := packetIndex == packetsInFrame-1
			seq := seqs[streamIdx]
			seqs[streamIdx]++
			writeRTPHeader(payload, seq, timestamp, marker, ssrcs[streamIdx])
			now := uint64(time.Now().UnixNano())
			binary.LittleEndian.PutUint64(payload[rtpHeaderSize:rtpPayloadOffset], now)
			if _, err := streams[streamIdx].Write(payload[:size]); err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
						continue
					}
				}

				return fmt.Errorf("media: write: %w", err)
			}
			remaining -= size
			if remaining < 0 {
				remaining = 0
			}
			streamIdx++
			if streamIdx >= len(streams) {
				streamIdx = 0
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if packetInterval > 0 {
				deadline := frameStart.Add(time.Duration(packetIndex+1) * packetInterval)
				if err := sleepUntil(ctx, deadline); err != nil {
					return err
				}
			}
		}

		if frameInterval > 0 {
			deadline := frameStart.Add(frameInterval)
			if err := sleepUntil(ctx, deadline); err != nil {
				return err
			}
		}
	}

	return nil
}

func buildMediaPlan(spec mediaSpec) (mediaPlan, error) {
	spec = spec.withDefaults()
	if spec.MaxPayload < 16 {
		return mediaPlan{}, fmt.Errorf("media: max payload must be >= 16")
	}
	if spec.MaxPayload < rtpPayloadOffset {
		return mediaPlan{}, fmt.Errorf("media: max payload must be >= %d", rtpPayloadOffset)
	}
	if spec.FramesPerSecond <= 0 {
		return mediaPlan{}, fmt.Errorf("media: fps must be > 0")
	}
	frameInterval := time.Second / time.Duration(spec.FramesPerSecond)
	if frameInterval <= 0 {
		return mediaPlan{}, fmt.Errorf("media: frame interval must be > 0")
	}
	frameCount := int(spec.Duration / frameInterval)
	if frameCount <= 0 {
		return mediaPlan{}, fmt.Errorf("media: duration too short")
	}
	totalBytes := int(int64(spec.BitrateBps) * int64(spec.Duration) / (8 * int64(time.Second)))
	if totalBytes <= 0 {
		return mediaPlan{}, fmt.Errorf("media: bitrate too low")
	}

	totalWeight := 0
	weights := make([]int, frameCount)
	for i := 0; i < frameCount; i++ {
		weight := mediaPatternWeight(spec.Pattern, i)
		if weight < 1 {
			weight = 1
		}
		weights[i] = weight
		totalWeight += weight
	}
	if totalWeight == 0 {
		return mediaPlan{}, fmt.Errorf("media: pattern has zero weight")
	}

	bytesPerWeight := totalBytes / totalWeight
	remainder := totalBytes - bytesPerWeight*totalWeight
	frameSizes := make([]int, frameCount)
	totalPackets := 0
	for i, weight := range weights {
		size := weight * bytesPerWeight
		if remainder > 0 {
			size++
			remainder--
		}
		if size < rtpPayloadOffset {
			size = rtpPayloadOffset
		}
		frameSizes[i] = size
		totalPackets += (size + spec.MaxPayload - 1) / spec.MaxPayload
	}

	return mediaPlan{
		FrameSizes:    frameSizes,
		MaxPayload:    spec.MaxPayload,
		FrameInterval: frameInterval,
		TotalPackets:  totalPackets,
		TotalBytes:    totalBytes,
	}, nil
}

func writeRTPHeader(buf []byte, seq uint16, timestamp uint32, marker bool, ssrc uint32) {
	if len(buf) < rtpHeaderSize {
		return
	}
	buf[0] = 0x80
	buf[1] = rtpPayloadType
	if marker {
		buf[1] |= 0x80
	}
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], timestamp)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
}

func splitPackets(total int, streams int) []int {
	if streams <= 0 {
		return nil
	}
	targets := make([]int, streams)
	if total <= 0 {
		return targets
	}
	base := total / streams
	remainder := total % streams
	for i := 0; i < streams; i++ {
		targets[i] = base
		if i < remainder {
			targets[i]++
		}
	}
	return targets
}

func openMediaStreams(ctx context.Context, session *sctpSession, count int) ([]Stream, []Stream, error) {
	if session == nil {
		return nil, nil, errMissingAdapter
	}
	clientStreams := []Stream{session.clientStream}
	serverStreams := []Stream{session.serverStream}
	if count <= 1 {
		return clientStreams, serverStreams, nil
	}
	for i := 1; i < count; i++ {
		stream, err := session.clientAssoc.OpenStream(uint16(i), PayloadTypeWebRTCBinary)
		if err != nil {
			return nil, nil, fmt.Errorf("sctp: open stream %d: %w", i, err)
		}
		clientStreams = append(clientStreams, stream)
	}
	for i := 1; i < count; i++ {
		streamCh := make(chan streamResult, 1)
		go func() {
			stream, err := session.serverAssoc.AcceptStream()
			streamCh <- streamResult{stream: stream, err: err}
		}()
		_ = sendOne(ctx, clientStreams[i], []byte("warmup"))
		select {
		case res := <-streamCh:
			if res.err != nil {
				return nil, nil, fmt.Errorf("sctp: accept stream: %w", res.err)
			}
			serverStreams = append(serverStreams, res.stream)
			_ = recvOne(res.stream, len("warmup"))
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return clientStreams, serverStreams, nil
}

func closeExtraStreams(streams []Stream) {
	if len(streams) <= 1 {
		return
	}
	for i := 1; i < len(streams); i++ {
		_ = streams[i].Close()
	}
}

func receiveMediaStreams(
	ctx context.Context,
	streams []Stream,
	targets []int,
	payloadSize int,
	done <-chan struct{},
	drainTimeout time.Duration,
	jitterBuffer time.Duration,
) receiveResult {
	if len(streams) == 0 {
		return receiveResult{}
	}
	resCh := make(chan receiveResult, len(streams))
	var wg sync.WaitGroup
	for i, stream := range streams {
		target := 0
		if i < len(targets) {
			target = targets[i]
		}
		if target <= 0 {
			continue
		}
		wg.Add(1)
		go func(s Stream, packets int) {
			defer wg.Done()
			count, lats, reorder, retrans, tail, dropped := receiveMediaPackets(ctx, s, packets, payloadSize, done, drainTimeout, jitterBuffer)
			resCh <- receiveResult{count: count, latencies: lats, reordered: reorder, retrans: retrans, tailRecovery: tail, dropped: dropped}
		}(stream, target)
	}
	go func() {
		wg.Wait()
		close(resCh)
	}()
	var combined receiveResult
	for res := range resCh {
		combined.count += res.count
		combined.latencies = append(combined.latencies, res.latencies...)
		combined.reordered += res.reordered
		combined.retrans += res.retrans
		combined.dropped += res.dropped
		combined.tailRecovery = maxDuration(combined.tailRecovery, res.tailRecovery)
	}
	return combined
}

func receiveMediaPackets(
	ctx context.Context,
	stream Stream,
	packets int,
	payloadSize int,
	done <-chan struct{},
	drainTimeout time.Duration,
	jitterBuffer time.Duration,
) (int, []time.Duration, int, int, time.Duration, int) {
	buf := make([]byte, payloadSize+16)
	count := 0
	latencies := make([]time.Duration, 0, packets)
	seen := make(map[uint16]int, packets)
	expectedSeq := uint16(1)
	reordered := 0
	retrans := 0
	var lastSendTS int64
	var lastRecvTS time.Time
	var doneAt time.Time
	dropped := 0
	for count < packets {
		select {
		case <-ctx.Done():
			return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
		default:
		}
		_ = stream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := stream.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
				default:
				}
				if done != nil && drainTimeout > 0 {
					select {
					case <-done:
						if doneAt.IsZero() {
							doneAt = time.Now()
							if lastRecvTS.IsZero() {
								lastRecvTS = doneAt
							}
						}
					default:
					}
					if !doneAt.IsZero() {
						last := lastRecvTS
						if last.IsZero() {
							last = doneAt
						}
						if time.Since(last) >= drainTimeout {
							return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
						}
					}
				}
				continue
			}
			return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
		}
		if n < rtpPayloadOffset {
			dropped++
			continue
		}
		recvTime := time.Now()
		seq := binary.BigEndian.Uint16(buf[2:4])
		sendTS := int64(binary.LittleEndian.Uint64(buf[rtpHeaderSize:rtpPayloadOffset]))
		if sendTS > 0 {
			latency := recvTime.Sub(time.Unix(0, sendTS))
			if jitterBuffer > 0 && latency > jitterBuffer {
				dropped++
				continue
			}
			latencies = append(latencies, latency)
			if sendTS > lastSendTS {
				lastSendTS = sendTS
			}
			lastRecvTS = recvTime
		}
		count++
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
		if int(seq) > packets {
			dropped++
		}
	}

	return count, latencies, reordered, retrans, recvTail(lastSendTS, lastRecvTS), dropped
}

func mediaPatternWeight(pattern string, index int) int {
	if pattern == "" {
		pattern = defaultMediaPattern
	}
	ch := pattern[index%len(pattern)]
	switch ch {
	case 'I', 'i':
		return 5
	case 'P', 'p':
		return 2
	case 'B', 'b':
		return 1
	default:
		return 1
	}
}

func sleepUntil(ctx context.Context, deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	if wait := time.Until(deadline); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}

	return nil
}
