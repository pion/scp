// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pion/scp/internal/scp"
)

type runConfig struct {
	GeneratedAt   time.Time          `json:"generated_at"`
	LockPath      string             `json:"lock_path"`
	PairMode      string             `json:"pair_mode"`
	Include       []string           `json:"include,omitempty"`
	Exclude       []string           `json:"exclude,omitempty"`
	ExplicitPairs []string           `json:"explicit_pairs,omitempty"`
	Cases         []string           `json:"cases"`
	Timeout       string             `json:"timeout"`
	Repeat        int                `json:"repeat"`
	Seed          int64              `json:"seed"`
	Interleaving  string             `json:"interleaving,omitempty"`
	Pairs         []pairRecord       `json:"pairs"`
	Parameters    runParameters      `json:"parameters"`
	Profiles      []profileEntry     `json:"profiles,omitempty"`
	CasePolicies  []casePolicyRecord `json:"case_policies,omitempty"`
	Pprof         pprofRecord        `json:"pprof,omitempty"`
}

type runParameters struct {
	MinBurstPackets     int     `json:"min_burst_packets"`
	BurstRange          int     `json:"burst_range"`
	BurstPayloadOctets  int     `json:"burst_payload_octets"`
	MinPacketsPerSecond float64 `json:"min_packets_per_second"`
}

type profileEntry struct {
	Case    string        `json:"case"`
	Profile profileRecord `json:"profile"`
}

type pprofRecord struct {
	CPU    string `json:"cpu,omitempty"`
	Heap   string `json:"heap,omitempty"`
	Allocs string `json:"allocs,omitempty"`
}

type casePolicyRecord struct {
	Case                  string  `json:"case"`
	MinForward            int     `json:"min_forward,omitempty"`
	MinReverse            int     `json:"min_reverse,omitempty"`
	MinPPS                float64 `json:"min_pps,omitempty"`
	AllowWireErrors       bool    `json:"allow_wire_errors,omitempty"`
	AllowRunError         bool    `json:"allow_run_error,omitempty"`
	RequireChecksumErrors bool    `json:"require_checksum_errors,omitempty"`
	RequireParseErrors    bool    `json:"require_parse_errors,omitempty"`
	PayloadSize           int     `json:"payload_size,omitempty"`
	EnableInterleaving    bool    `json:"enable_interleaving,omitempty"`
	MaxMessageSize        uint32  `json:"max_message_size,omitempty"`
	MediaBitrateBps       int     `json:"media_bitrate_bps,omitempty"`
	MediaFPS              int     `json:"media_fps,omitempty"`
	MediaDuration         string  `json:"media_duration,omitempty"`
	MediaMaxPayload       int     `json:"media_max_payload,omitempty"`
	MediaPattern          string  `json:"media_pattern,omitempty"`
	MediaOneWay           bool    `json:"media_one_way,omitempty"`
	MediaDrainTimeout     string  `json:"media_drain_timeout,omitempty"`
	MediaMinDeliveryPct   float64 `json:"media_min_delivery_pct,omitempty"`
	Fault                 string  `json:"fault,omitempty"`
	FaultEvery            int     `json:"fault_every,omitempty"`
}

type runResults struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Seed        int64          `json:"seed"`
	Results     []resultRecord `json:"results"`
}

type resultRecord struct {
	Case         string        `json:"case"`
	Pair         pairRecord    `json:"pair"`
	Profile      profileRecord `json:"profile"`
	ForwardBurst int           `json:"forward_burst"`
	ReverseBurst int           `json:"reverse_burst"`
	Passed       bool          `json:"passed"`
	Errored      bool          `json:"errored"`
	Details      string        `json:"details,omitempty"`
	WireLog      string        `json:"wire_log,omitempty"`
	Iteration    int           `json:"iteration"`
	Metrics      metricsRecord `json:"metrics"`
}

type pairRecord struct {
	Left  entryRecord `json:"left"`
	Right entryRecord `json:"right"`
}

type entryRecord struct {
	Name       string            `json:"name"`
	Selector   string            `json:"selector,omitempty"`
	Commit     string            `json:"commit"`
	Provenance string            `json:"provenance,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type profileRecord struct {
	Name        string  `json:"name,omitempty"`
	MinDelay    string  `json:"min_delay"`
	MaxJitter   string  `json:"max_jitter"`
	DropPercent float64 `json:"drop_percent"`
	Unordered   bool    `json:"unordered"`
}

type metricsRecord struct {
	DurationNs       int64   `json:"duration_ns"`
	Duration         string  `json:"duration"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	CPUSeconds       float64 `json:"cpu_seconds"`
	LatencyP50Ns     int64   `json:"latency_p50_ns"`
	LatencyP50       string  `json:"latency_p50"`
	LatencyP90Ns     int64   `json:"latency_p90_ns"`
	LatencyP90       string  `json:"latency_p90"`
	LatencyP99Ns     int64   `json:"latency_p99_ns"`
	LatencyP99       string  `json:"latency_p99"`
	BytesSent        uint64  `json:"bytes_sent"`
	BytesReceived    uint64  `json:"bytes_received"`
	Dropped          int     `json:"dropped"`
	Reordered        int     `json:"reordered"`
	Retransmitted    int     `json:"retransmitted"`
	WirePackets      int     `json:"wire_packets"`
	WireChecksumErrs int     `json:"wire_checksum_errors"`
	WireParseErrors  int     `json:"wire_parse_errors"`
	WireShortPackets int     `json:"wire_short_packets"`
	WireLogErrors    int     `json:"wire_log_errors"`
	GoodputBps       float64 `json:"goodput_bps"`
	TailRecoveryNs   int64   `json:"tail_recovery_ns"`
	TailRecovery     string  `json:"tail_recovery"`
	Target           int     `json:"target"`
}

func writeArtifacts(opts Options, seed int64, cases []string, pairs []pair, results []scenarioResult, timeout time.Duration) error {
	if opts.OutDir == "" {
		return nil
	}

	dir := filepath.Clean(opts.OutDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("test: out-dir: %w", err)
	}

	generatedAt := time.Now().UTC()
	config := runConfig{
		GeneratedAt:   generatedAt,
		LockPath:      opts.LockPath,
		PairMode:      opts.PairMode,
		Include:       opts.IncludeNames,
		Exclude:       opts.ExcludeNames,
		ExplicitPairs: opts.ExplicitPairs,
		Cases:         cases,
		Timeout:       timeout.String(),
		Repeat:        opts.Repeat,
		Seed:          seed,
		Interleaving:  opts.Interleaving,
		Pairs:         convertPairs(pairs),
		Parameters: runParameters{
			MinBurstPackets:     minBurstPackets,
			BurstRange:          burstRange,
			BurstPayloadOctets:  burstPayloadOctets,
			MinPacketsPerSecond: minPacketsPerSecond,
		},
		Profiles:     collectProfiles(cases),
		CasePolicies: collectCasePolicies(cases),
		Pprof: pprofRecord{
			CPU:    opts.PprofCPU,
			Heap:   opts.PprofHeap,
			Allocs: opts.PprofAllocs,
		},
	}
	resultsDoc := runResults{
		GeneratedAt: generatedAt,
		Seed:        seed,
		Results:     convertResults(results),
	}

	if err := writeJSON(filepath.Join(dir, "config.json"), config); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "results.json"), resultsDoc); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "seed.txt"), []byte(fmt.Sprintf("%d\n", seed)), 0o600); err != nil {
		return fmt.Errorf("test: write seed: %w", err)
	}

	return nil
}

func collectProfiles(cases []string) []profileEntry {
	if len(cases) == 0 {
		return nil
	}

	profiles := make([]profileEntry, 0, len(cases))
	for _, name := range cases {
		profiles = append(profiles, profileEntry{
			Case:    name,
			Profile: profileRecordFromProfile(profileForCase(name)),
		})
	}

	return profiles
}

func collectCasePolicies(cases []string) []casePolicyRecord {
	if len(cases) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(cases))
	policies := make([]casePolicyRecord, 0, len(cases))
	for _, name := range cases {
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		if def, ok := lookupCaseDefinition(name); ok {
			record := casePolicyRecord{
				Case:                  def.Name,
				MinForward:            def.Policy.MinForward,
				MinReverse:            def.Policy.MinReverse,
				MinPPS:                def.Policy.MinPPS,
				AllowWireErrors:       def.Policy.AllowWireErrors,
				AllowRunError:         def.Policy.AllowRunError,
				RequireChecksumErrors: def.Policy.RequireChecksumErrors,
				RequireParseErrors:    def.Policy.RequireParseErrors,
				PayloadSize:           def.PayloadSize,
				EnableInterleaving:    def.EnableInterleaving,
				MaxMessageSize:        def.MaxMessageSize,
			}
			if def.Media != nil {
				spec := def.Media.withDefaults()
				record.MediaBitrateBps = spec.BitrateBps
				record.MediaFPS = spec.FramesPerSecond
				record.MediaDuration = spec.Duration.String()
				record.MediaMaxPayload = spec.MaxPayload
				record.MediaPattern = spec.Pattern
				record.MediaOneWay = spec.OneWay
				record.MediaDrainTimeout = spec.DrainTimeout.String()
				record.MediaMinDeliveryPct = spec.MinDeliveryPct
			}
			if def.Fault != nil {
				record.Fault = string(def.Fault.Mode)
				record.FaultEvery = def.Fault.Every
			}
			policies = append(policies, record)
			continue
		}
		policies = append(policies, casePolicyRecord{Case: name})
	}

	return policies
}

func profileForCase(name string) networkProfile {
	if def, ok := lookupCaseDefinition(name); ok {
		return def.Profile
	}

	return networkProfile{Name: name}
}

func convertPairs(pairs []pair) []pairRecord {
	out := make([]pairRecord, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, pairRecord{
			Left:  recordFromEntry(p.Left),
			Right: recordFromEntry(p.Right),
		})
	}

	return out
}

func convertResults(results []scenarioResult) []resultRecord {
	out := make([]resultRecord, 0, len(results))
	for _, res := range results {
		out = append(out, resultRecord{
			Case:         res.CaseName,
			Pair:         pairRecord{Left: recordFromEntry(res.Pair.Left), Right: recordFromEntry(res.Pair.Right)},
			Profile:      profileRecordFromProfile(res.Profile),
			ForwardBurst: res.ForwardBurst,
			ReverseBurst: res.ReverseBurst,
			Passed:       res.Passed,
			Errored:      res.Errored,
			Details:      res.Details,
			WireLog:      res.WireLog,
			Iteration:    res.Iteration,
			Metrics:      metricsRecordFromMetrics(res.Metrics),
		})
	}

	return out
}

func recordFromEntry(entry scp.LockEntry) entryRecord {
	return entryRecord{
		Name:       entry.Name,
		Selector:   entry.Selector,
		Commit:     entry.Commit,
		Provenance: entry.Provenance,
		Labels:     entry.Labels,
	}
}

func profileRecordFromProfile(profile networkProfile) profileRecord {
	return profileRecord{
		Name:        profile.Name,
		MinDelay:    profile.MinDelay.String(),
		MaxJitter:   profile.MaxJitter.String(),
		DropPercent: profile.DropPercent,
		Unordered:   profile.Unordered,
	}
}

func metricsRecordFromMetrics(metrics resultMetrics) metricsRecord {
	return metricsRecord{
		DurationNs:       metrics.Duration.Nanoseconds(),
		Duration:         metrics.Duration.String(),
		PacketsPerSecond: metrics.PacketsPerSecond,
		CPUSeconds:       metrics.CPUSeconds,
		LatencyP50Ns:     metrics.LatencyP50.Nanoseconds(),
		LatencyP50:       metrics.LatencyP50.String(),
		LatencyP90Ns:     metrics.LatencyP90.Nanoseconds(),
		LatencyP90:       metrics.LatencyP90.String(),
		LatencyP99Ns:     metrics.LatencyP99.Nanoseconds(),
		LatencyP99:       metrics.LatencyP99.String(),
		BytesSent:        metrics.BytesSent,
		BytesReceived:    metrics.BytesReceived,
		Dropped:          metrics.Dropped,
		Reordered:        metrics.Reordered,
		Retransmitted:    metrics.Retransmitted,
		WirePackets:      metrics.WirePackets,
		WireChecksumErrs: metrics.WireChecksumErrs,
		WireParseErrors:  metrics.WireParseErrors,
		WireShortPackets: metrics.WireShortPackets,
		WireLogErrors:    metrics.WireLogErrors,
		GoodputBps:       metrics.GoodputBps,
		TailRecoveryNs:   metrics.TailRecovery.Nanoseconds(),
		TailRecovery:     metrics.TailRecovery.String(),
		Target:           metrics.Target,
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("test: marshal %s: %w", path, err)
	}
	data = append(data, '\n')

	return os.WriteFile(filepath.Clean(path), data, 0o600)
}
