// Package resolve resolves SCTP references into manifest and lock entries.
package resolve

import "errors"

var (
	errNoRefs             = errors.New("resolve: no refs specified")
	errNoRefsAfterParsing = errors.New("resolve: no refs specified after parsing")
	errDuplicateEntry     = errors.New("resolve: duplicate entry name")
	errUnsupportedType    = errors.New("resolve: unsupported selector type")
	errBranchNotFound     = errors.New("resolve: branch not found")
	errInvalidPRNumber    = errors.New("resolve: invalid PR number")
	errEmptyPathSelector  = errors.New("resolve: empty path selector")
	errRangeNoMatches     = errors.New("resolve: no matching tags for range")
)
