// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func runCase(ctx context.Context, pairs []pair, seed int64, repeat int, timeout time.Duration, outDir string, def caseDefinition, interleavingOverride string) ([]scenarioResult, error) {
	if len(pairs) == 0 {
		return nil, errInsufficientEntries
	}

	results := make([]scenarioResult, 0, len(pairs)*repeat)
	for _, p := range pairs {
		for iter := range repeat {
			iterCtx, cancel := withTimeout(ctx, timeout)
			seq := iter
			logPath := packetLogPath(outDir, def.Name, p, iter+1)
			var forward int
			var reverse int
			var metrics resultMetrics
			var err error
			enableInterleaving := resolveInterleaving(def, interleavingOverride)
			if def.Media != nil {
				forward, reverse, metrics, err = runMediaTrafficProfile(
					iterCtx,
					p,
					seed,
					seq,
					def.Profile,
					logPath,
					def.Policy,
					def.Fault,
					*def.Media,
					enableInterleaving,
					def.MaxMessageSize,
				)
			} else {
				forward, reverse, metrics, err = runBurstTrafficProfile(
					iterCtx,
					p,
					seed,
					seq,
					def.Profile,
					logPath,
					def.Policy,
					def.Fault,
					def.PayloadSize,
					enableInterleaving,
					def.MaxMessageSize,
				)
			}
			cancel()

			res := scenarioResult{
				CaseName:     def.Name,
				Pair:         p,
				Profile:      def.Profile,
				Iteration:    iter + 1,
				ForwardBurst: forward,
				ReverseBurst: reverse,
				Metrics:      metrics,
				WireLog:      logPath,
			}
			res.Details = fmt.Sprintf("run=%d %s->%s=%d packets, %s->%s=%d packets",
				iter+1, p.Left.Name, p.Right.Name, forward, p.Right.Name, p.Left.Name, reverse,
			)
			res.Errored = err != nil || hasWireErrors(metrics)

			passed, failures := evaluateCase(res, err, def.Policy)
			res.Passed = passed
			if err != nil {
				res.Details += fmt.Sprintf(" err=%v", err)
			}
			if len(failures) > 0 {
				res.Details += " assert=" + strings.Join(failures, ",")
			}

			results = append(results, res)
		}
	}

	return results, nil
}

func evaluateCase(res scenarioResult, runErr error, policy casePolicy) (bool, []string) {
	var failures []string
	if runErr != nil && !policy.AllowRunError {
		failures = append(failures, "run_error")
	}
	if policy.MinForward > 0 && res.ForwardBurst < policy.MinForward {
		failures = append(failures, fmt.Sprintf("forward=%d<%d", res.ForwardBurst, policy.MinForward))
	}
	if policy.MinReverse > 0 && res.ReverseBurst < policy.MinReverse {
		failures = append(failures, fmt.Sprintf("reverse=%d<%d", res.ReverseBurst, policy.MinReverse))
	}
	if policy.MinPPS > 0 && res.Metrics.PacketsPerSecond < policy.MinPPS {
		failures = append(failures, fmt.Sprintf("pps=%.2f<%.2f", res.Metrics.PacketsPerSecond, policy.MinPPS))
	}
	if res.Metrics.WireLogErrors > 0 {
		failures = append(failures, fmt.Sprintf("wire_log_errors=%d", res.Metrics.WireLogErrors))
	}
	if !policy.AllowWireErrors {
		if res.Metrics.WireChecksumErrs > 0 || res.Metrics.WireParseErrors > 0 || res.Metrics.WireShortPackets > 0 {
			failures = append(failures, fmt.Sprintf("wire_errors=%d/%d/%d",
				res.Metrics.WireChecksumErrs,
				res.Metrics.WireParseErrors,
				res.Metrics.WireShortPackets,
			))
		}
	}
	if policy.RequireChecksumErrors && res.Metrics.WireChecksumErrs == 0 {
		failures = append(failures, "checksum_errors=0")
	}
	if policy.RequireParseErrors && res.Metrics.WireParseErrors == 0 {
		failures = append(failures, "parse_errors=0")
	}

	return len(failures) == 0, failures
}

func hasWireErrors(metrics resultMetrics) bool {
	return metrics.WireChecksumErrs > 0 || metrics.WireParseErrors > 0 || metrics.WireShortPackets > 0 || metrics.WireLogErrors > 0
}
