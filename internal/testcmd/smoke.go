// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/vnet"
)

const (
	minBurstPackets    = 64
	burstRange         = 512 - minBurstPackets + 1
	burstPayloadOctets = 1200
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

			forward, reverse, err := runBurstTraffic(ctx, pair, resolvedSeed, idx*repeat+iter)
			result.ForwardBurst = forward
			result.ReverseBurst = reverse
			result.Passed = err == nil && forward >= minBurstPackets && reverse >= minBurstPackets
			result.Details = fmt.Sprintf("run=%d %s->%s=%d packets, %s->%s=%d packets",
				iter+1, pair.Left.Name, pair.Right.Name, forward, pair.Right.Name, pair.Left.Name, reverse,
			)
			if err != nil {
				result.Details += fmt.Sprintf(" err=%v", err)
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func runBurstTraffic(ctx context.Context, p pair, baseSeed int64, idx int) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	seed := derivePairSeed(baseSeed, p, idx)
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed>>1))) //nolint:gosec // not cryptographic purpose
	targetForward := minBurstPackets + rng.IntN(burstRange)
	targetReverse := minBurstPackets + rng.IntN(burstRange)
	payload := make([]byte, burstPayloadOctets)
	for i := range payload {
		payload[i] = byte(rng.IntN(256))
	}

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "10.0.0.0/24",
		QueueSize:     4096,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("burst: router: %w", err)
	}
	leftNet := vnet.NewNet(&vnet.NetConfig{StaticIP: "10.0.0.1"})
	rightNet := vnet.NewNet(&vnet.NetConfig{StaticIP: "10.0.0.2"})
	if err := router.AddNet(leftNet); err != nil {
		return 0, 0, fmt.Errorf("burst: add left net: %w", err)
	}
	if err := router.AddNet(rightNet); err != nil {
		return 0, 0, fmt.Errorf("burst: add right net: %w", err)
	}
	if err := router.Start(); err != nil {
		return 0, 0, fmt.Errorf("burst: start router: %w", err)
	}
	defer func() {
		_ = router.Stop()
	}()

	forward, forwardErr := sendBurst(ctx, leftNet, rightNet, "10.0.0.2:5000", targetForward, payload)
	reverse, reverseErr := sendBurst(ctx, rightNet, leftNet, "10.0.0.1:5001", targetReverse, payload)

	return forward, reverse, errors.Join(forwardErr, reverseErr)
}

func sendBurst(
	ctx context.Context,
	sender *vnet.Net,
	receiver *vnet.Net,
	listenAddr string,
	packets int,
	payload []byte,
) (int, error) {
	recv, err := setupReceiver(receiver, listenAddr)
	if err != nil {
		return 0, err
	}
	defer closeReceiver(recv)

	sendConn, err := setupSender(sender, listenAddr)
	if err != nil {
		return 0, err
	}
	defer closeSender(sendConn)

	delivered := make(chan int, 1)
	go receivePackets(ctx, recv, packets, payload, delivered)

	sendErr := transmitPackets(ctx, sendConn, packets, payload)
	count := <-delivered

	return count, sendErr
}

func setupReceiver(receiver *vnet.Net, listenAddr string) (net.PacketConn, error) {
	recv, err := receiver.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("burst: listen %s: %w", listenAddr, err)
	}

	return recv, nil
}

func closeReceiver(recv net.PacketConn) {
	if err := recv.Close(); err != nil {
		log.Printf("burst: close listener: %v", err)
	}
}

func setupSender(sender *vnet.Net, listenAddr string) (net.Conn, error) {
	sendConn, err := sender.Dial("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("burst: dial %s: %w", listenAddr, err)
	}

	return sendConn, nil
}

func closeSender(sendConn net.Conn) {
	if err := sendConn.Close(); err != nil {
		log.Printf("burst: close sender: %v", err)
	}
}

func receivePackets(
	ctx context.Context,
	recv net.PacketConn,
	packets int,
	payload []byte,
	delivered chan<- int,
) {
	defer close(delivered)

	buf := make([]byte, len(payload)+16)
	count := 0
	for count < packets {
		_ = recv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _, err := recv.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-ctx.Done():
					delivered <- count

					return
				default:
					continue
				}
			}
			delivered <- count

			return
		}
		count++
	}

	delivered <- count
}

func transmitPackets(ctx context.Context, conn net.Conn, packets int, payload []byte) error {
	for i := 0; i < packets; {
		if err := conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return fmt.Errorf("burst: set write deadline: %w", err)
		}
		if _, err := conn.Write(payload); err != nil {
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
