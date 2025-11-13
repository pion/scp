// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
)

type junitSuite struct {
	XMLName   xml.Name    `xml:"testsuite"`
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	TestCases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	SystemOut string        `xml:"system-out,omitempty"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr,omitempty"`
	Details string `xml:",chardata"`
}

func writeJUnitReport(path string, results []scenarioResult) error {
	if path == "" {
		return nil
	}
	if err := ensureJUnitDir(path); err != nil {
		return err
	}

	suite := junitSuite{
		Name:     "scp-smoke",
		Tests:    len(results),
		Failures: countFailures(results),
	}

	for _, res := range results {
		caseName := fmt.Sprintf("%s_vs_%s", res.Pair.Left.Name, res.Pair.Right.Name)
		if res.Iteration > 1 {
			caseName = fmt.Sprintf("%s#%d", caseName, res.Iteration)
		}
		jc := junitCase{
			Classname: "scp." + res.CaseName,
			Name:      caseName,
			SystemOut: res.Details,
		}
		if !res.Passed {
			jc.Failure = &junitFailure{
				Message: "max burst threshold not met",
				Details: res.Details,
			}
		}
		suite.TestCases = append(suite.TestCases, jc)
	}

	data, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)

	return os.WriteFile(path, data, 0o640)
}

func ensureJUnitDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	return os.MkdirAll(dir, 0o750)
}
