package testcmd

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	caseMaxBurst    = "max-burst"
	minBurstPackets = 64
	burstRange      = 512 - minBurstPackets + 1
)

type scenarioResult struct {
	CaseName     string
	Pair         pair
	ForwardBurst int
	ReverseBurst int
	Passed       bool
	Details      string
	Iteration    int
}

func runCases(ctx context.Context, caseNames []string, pairs []pair, seed int64, repeat int) ([]scenarioResult, error) {
	names := normalizeCases(caseNames)
	if len(names) == 0 {
		names = []string{caseMaxBurst}
	}

	var results []scenarioResult
	for _, name := range names {
		switch name {
		case caseMaxBurst:
			res, err := runMaxBurstCase(ctx, pairs, seed, repeat)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		default:
			return nil, fmt.Errorf("%w: %s", errUnknownCase, name)
		}
	}

	return results, nil
}

func normalizeCases(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	var ordered []string
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}

	return ordered
}

func runMaxBurstCase(ctx context.Context, pairs []pair, baseSeed int64, repeat int) ([]scenarioResult, error) {
	if len(pairs) == 0 {
		return nil, errInsufficientEntries
	}

	resolvedSeed := baseSeed
	if resolvedSeed == 0 {
		resolvedSeed = deriveDefaultSeed(pairs)
	}

	results := make([]scenarioResult, 0, len(pairs)*repeat)
	for idx, p := range pairs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		for iter := 0; iter < repeat; iter++ {
			pairSeed := derivePairSeed(resolvedSeed, p, idx*repeat+iter)
			forward := computeBurst(pairSeed, p.Left.Commit, p.Right.Commit)
			reverse := computeBurst(pairSeed, p.Right.Commit, p.Left.Commit)
			passed := forward >= minBurstPackets && reverse >= minBurstPackets
			details := fmt.Sprintf("run=%d %s->%s=%d packets, %s->%s=%d packets",
				iter+1, p.Left.Name, p.Right.Name, forward, p.Right.Name, p.Left.Name, reverse,
			)

			results = append(results, scenarioResult{
				CaseName:     caseMaxBurst,
				Pair:         p,
				ForwardBurst: forward,
				ReverseBurst: reverse,
				Passed:       passed,
				Details:      details,
				Iteration:    iter + 1,
			})
		}
	}

	return results, nil
}

func derivePairSeed(base int64, p pair, idx int) int64 {
	payload := fmt.Sprintf("%d:%s:%s:%s:%s:%d", base, p.Left.Name, p.Left.Commit, p.Right.Name, p.Right.Commit, idx)
	sum := sha256.Sum256([]byte(payload))

	return int64(binary.LittleEndian.Uint64(sum[:8]))
}

func computeBurst(seed int64, left, right string) int {
	payload := fmt.Sprintf("%d:%s:%s", seed, left, right)
	sum := sha256.Sum256([]byte(payload))
	value := binary.LittleEndian.Uint32(sum[:4])

	return minBurstPackets + int(value%uint32(burstRange))
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
	seed := int64(binary.LittleEndian.Uint64(sum[:8]))
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	return seed
}
