package testcmd

import (
	"context"
	"fmt"

	"github.com/pion/scp/internal/scp"
)

func Run(ctx context.Context, opts Options) error {
	if opts.LockPath == "" {
		return errMissingLockPath
	}
	if opts.Repeat <= 0 {
		return errInvalidRepeat
	}

	lock, err := scp.ReadLock(opts.LockPath)
	if err != nil {
		return fmt.Errorf("test: read lock: %w", err)
	}
	if lock == nil || len(lock.Entries) == 0 {
		return errEmptyLock
	}

	include := buildNameSet(opts.IncludeNames)
	exclude := buildNameSet(opts.ExcludeNames)
	entries, err := selectEntries(lock.Entries, include, exclude)
	if err != nil {
		return err
	}

	pairs, err := buildPairs(entries, opts.PairMode, opts.ExplicitPairs)
	if err != nil {
		return err
	}

	caseNames := scp.SplitAndTrim(opts.Cases)
	results, err := runCases(ctx, caseNames, pairs, opts.Seed, opts.Repeat)
	if err != nil {
		return err
	}

	printResults(results)

	if opts.JUnitPath != "" {
		if err := writeJUnitReport(opts.JUnitPath, results); err != nil {
			return err
		}
	}

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
