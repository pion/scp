// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"fmt"
	"math"
	"time"
)

type casePolicy struct {
	MinForward            int
	MinReverse            int
	MinPPS                float64
	AllowWireErrors       bool
	AllowRunError         bool
	RequireChecksumErrors bool
	RequireParseErrors    bool
}

type caseDefinition struct {
	Name               string
	Profile            networkProfile
	Policy             casePolicy
	Fault              *faultSpec
	Media              *mediaSpec
	PayloadSize        int
	EnableInterleaving bool
	MaxMessageSize     uint32
}

func defaultPolicy() casePolicy {
	return casePolicy{
		MinForward: minBurstPackets,
		MinReverse: minBurstPackets,
		MinPPS:     minPacketsPerSecond,
	}
}

func faultPolicy(requireChecksum, requireParse bool) casePolicy {
	return casePolicy{
		AllowWireErrors:       true,
		AllowRunError:         true,
		RequireChecksumErrors: requireChecksum,
		RequireParseErrors:    requireParse,
	}
}

func mediaPolicy(spec mediaSpec) casePolicy {
	spec = spec.withDefaults()
	policy := defaultPolicy()
	if plan, err := buildMediaPlan(spec); err == nil && plan.TotalPackets > 0 {
		minForward := plan.TotalPackets
		if spec.MinDeliveryPct > 0 && spec.MinDeliveryPct < 100 {
			minForward = int(math.Ceil(float64(plan.TotalPackets) * spec.MinDeliveryPct / 100.0))
		}
		if minForward < 1 {
			minForward = 1
		}
		policy.MinForward = minForward
		if spec.OneWay {
			policy.MinReverse = 0
		} else {
			policy.MinReverse = minForward
		}
	}

	return policy
}

var mediaHEVCSpec = mediaSpec{
	BitrateBps:      3_000_000,
	FramesPerSecond: 25,
	Duration:        2 * time.Second,
	MaxPayload:      1200,
	Pattern:         defaultMediaPattern,
	OneWay:          true,
	DrainTimeout:    3 * time.Second,
	MinDeliveryPct:  90,
	Streams:         4,
}

var caseDefinitions = map[string]caseDefinition{
	caseMaxBurst: {
		Name:    caseMaxBurst,
		Profile: networkProfile{Name: caseMaxBurst},
		Policy:  defaultPolicy(),
	},
	caseHandshake: {
		Name:    caseHandshake,
		Profile: networkProfile{Name: caseHandshake},
		Policy:  defaultPolicy(),
	},
	caseUnorderedLowRTT: {
		Name:    caseUnorderedLowRTT,
		Profile: lowRTTProfile(),
		Policy:  defaultPolicy(),
	},
	caseUnorderedHighRTT: {
		Name:    caseUnorderedHighRTT,
		Profile: highRTTProfile(),
		Policy:  defaultPolicy(),
	},
	caseUnorderedDynamicRTT: {
		Name:    caseUnorderedDynamicRTT,
		Profile: dynamicRTTProfile(),
		Policy:  defaultPolicy(),
	},
	caseCongestionRack: {
		Name:    caseCongestionRack,
		Profile: congestionProfile(),
		Policy:  defaultPolicy(),
	},
	caseRetransmission: {
		Name:    caseRetransmission,
		Profile: lossProfile(),
		Policy:  defaultPolicy(),
	},
	caseRackReorderLow: {
		Name:    caseRackReorderLow,
		Profile: rackReorderLowProfile(),
		Policy:  defaultPolicy(),
	},
	caseRackReorderHigh: {
		Name:    caseRackReorderHigh,
		Profile: rackReorderHighProfile(),
		Policy:  defaultPolicy(),
	},
	caseRackBurstLoss: {
		Name:    caseRackBurstLoss,
		Profile: rackBurstLossProfile(),
		Policy:  defaultPolicy(),
	},
	caseFragmentation: {
		Name:           caseFragmentation,
		Profile:        networkProfile{Name: caseFragmentation},
		Policy:         defaultPolicy(),
		PayloadSize:    8192,
		MaxMessageSize: 16384,
	},
	caseInterleaving: {
		Name:               caseInterleaving,
		Profile:            networkProfile{Name: caseInterleaving},
		Policy:             defaultPolicy(),
		PayloadSize:        8192,
		EnableInterleaving: true,
		MaxMessageSize:     16384,
	},
	caseMediaHEVC: {
		Name:    caseMediaHEVC,
		Profile: mediaHEVCProfile(),
		Policy:  mediaPolicy(mediaHEVCSpec),
		Media:   &mediaHEVCSpec,
	},
	caseFaultChecksum: {
		Name:    caseFaultChecksum,
		Profile: networkProfile{Name: caseFaultChecksum},
		Policy:  faultPolicy(true, false),
		Fault:   &faultSpec{Mode: faultModeChecksum, Every: 7},
	},
	caseFaultBadChunkLen: {
		Name:    caseFaultBadChunkLen,
		Profile: networkProfile{Name: caseFaultBadChunkLen},
		Policy:  faultPolicy(false, true),
		Fault:   &faultSpec{Mode: faultModeBadChunkLen, Every: 7},
	},
	caseFaultNonZeroPadding: {
		Name:    caseFaultNonZeroPadding,
		Profile: networkProfile{Name: caseFaultNonZeroPadding},
		Policy:  faultPolicy(false, true),
		Fault:   &faultSpec{Mode: faultModeNonZeroPadding, Every: 7},
		// Force non-4-byte-aligned chunks so padding bytes exist to corrupt.
		PayloadSize: 1201,
	},
}

func caseDefinitionFor(name string) (caseDefinition, error) {
	if def, ok := caseDefinitions[name]; ok {
		return def, nil
	}

	return caseDefinition{}, fmt.Errorf("%w: %s", errUnknownCase, name)
}

func lookupCaseDefinition(name string) (caseDefinition, bool) {
	def, ok := caseDefinitions[name]
	return def, ok
}
