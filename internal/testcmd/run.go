// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"fmt"

	"github.com/pion/scp/internal/scp"
)

func Run(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}

	lock, err := loadAndValidateLock(opts.LockPath)
	if err != nil {
		return err
	}

	pairs, caseNames, err := prepareTestData(opts, lock)
	if err != nil {
		return err
	}

	results, err := runCases(ctx, caseNames, pairs, opts.Seed, opts.Repeat)
	if err != nil {
		return err
	}

	if err := reportResults(results, opts.JUnitPath); err != nil {
		return err
	}

	return checkFailures(results)
}

func validateOptions(opts Options) error {
	if opts.LockPath == "" {
		return errMissingLockPath
	}
	if opts.Repeat <= 0 {
		return errInvalidRepeat
	}

	return nil
}

func loadAndValidateLock(lockPath string) (*scp.Lockfile, error) {
	lock, err := scp.ReadLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("test: read lock: %w", err)
	}
	if lock == nil || len(lock.Entries) == 0 {
		return nil, errEmptyLock
	}

	return lock, nil
}

func prepareTestData(opts Options, lock *scp.Lockfile) ([]pair, []string, error) {
	include := buildNameSet(opts.IncludeNames)
	exclude := buildNameSet(opts.ExcludeNames)
	entries, err := selectEntries(lock.Entries, include, exclude)
	if err != nil {
		return nil, nil, err
	}

	pairs, err := buildPairs(entries, opts.PairMode, opts.ExplicitPairs)
	if err != nil {
		return nil, nil, err
	}

	caseNames := scp.SplitAndTrim(opts.Cases)

	return pairs, caseNames, nil
}

func reportResults(results []scenarioResult, junitPath string) error {
	printResults(results)

	if junitPath != "" {
		if err := writeJUnitReport(junitPath, results); err != nil {
			return err
		}
	}

	return nil
}

func checkFailures(results []scenarioResult) error {
	if failures := countFailures(results); failures > 0 {
		return fmt.Errorf("%w: %d failing cases", errScenarioFailed, failures)
	}

	return nil
}

func printResults(results []scenarioResult) {
	if len(results) == 0 {
		fmt.Println("test: no cases executed")

		return
	}

	for _, res := range results {
		label := res.CaseName
		if res.Iteration > 1 {
			label = fmt.Sprintf("%s#%d", label, res.Iteration)
		}
		fmt.Printf("[%s] %s ↔ %s :: forward=%d packets, reverse=%d packets\n",
			label,
			res.Pair.Left.Name,
			res.Pair.Right.Name,
			res.ForwardBurst,
			res.ReverseBurst,
		)
		if !res.Passed && res.Details != "" {
			fmt.Printf("  details: %s\n", res.Details)
		}
		if (res.Metrics != resultMetrics{}) {
			fmt.Printf("  metrics: %s\n", formatMetrics(res.Metrics))
		}
	}
}

func countFailures(results []scenarioResult) int {
	failures := 0
	for _, res := range results {
		if !res.Passed {
			failures++
		}
	}

	return failures
}
