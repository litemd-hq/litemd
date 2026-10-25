// Package sync defines the optimistic-concurrency rules shared by the server's
// mutation handlers and (documentationally) by clients.
//
// Every mutating request must carry exactly one precondition. Unconditional
// writes are rejected, so two devices editing the same path surface a conflict
// instead of silently overwriting each other.
//
//	If-Match: <version>   compare-and-swap. The file must exist live at exactly
//	                      that version.
//	                        version mismatch        -> 409 + current entry
//	                        path absent             -> 412
//	                        path deleted/tombstoned -> 409 + current entry
//	If-None-Match: *      create-only. The path must not hold a live file.
//	                        existing live file      -> 412 + current entry
//	                        absent or tombstoned    -> proceed
//
// Neither precondition -> 428 Precondition Required. Both -> 412.
//
// Clients reconcile a 409/412 by fetching the returned current entry, running a
// three-way merge against their local copy, and retrying with the new version.
package sync

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/litemd-hq/litemd/internal/files"
)

// ErrPreconditionRequired is returned when a mutation carries no precondition.
var ErrPreconditionRequired = errors.New("a precondition is required: send If-Match: <version> or If-None-Match: *")

// Conflict reports a version mismatch or a deleted path. Current carries the
// server state so clients can resolve deterministically.
type Conflict struct {
	Current     *files.Entry
	Description string
}

func (c *Conflict) Error() string { return c.Description }

// PreconditionFailed reports a structurally wrong precondition: malformed, an
// unsupported form, or an assumption that does not hold (e.g. If-None-Match
// against an existing file).
type PreconditionFailed struct {
	Current     *files.Entry
	Description string
}

func (p *PreconditionFailed) Error() string { return p.Description }

// Check applies the OCC rules to the current entry, which is nil when the path
// has no entry at all. A tombstone is non-nil with Deleted set.
func Check(ifMatch, ifNoneMatch string, current *files.Entry) error {
	switch {
	case ifMatch == "" && ifNoneMatch == "":
		return ErrPreconditionRequired

	case ifMatch != "" && ifNoneMatch != "":
		return &PreconditionFailed{Description: "send either If-Match or If-None-Match, not both"}

	case ifNoneMatch != "":
		if ifNoneMatch != "*" {
			return &PreconditionFailed{Description: fmt.Sprintf("unsupported If-None-Match %q: only \"*\" is allowed", ifNoneMatch)}
		}
		if current != nil && !current.Deleted {
			return &PreconditionFailed{Current: current, Description: "path already exists"}
		}
		return nil // creating over absence or a tombstone is allowed

	default: // If-Match
		if ifMatch == "*" {
			return &PreconditionFailed{Description: "If-Match: * is not a concurrency check; send a version, or If-None-Match: * to create"}
		}
		v, err := strconv.ParseUint(ifMatch, 10, 64)
		if err != nil {
			return &PreconditionFailed{Description: fmt.Sprintf("malformed If-Match %q: expected a version number", ifMatch)}
		}
		if current == nil {
			return &PreconditionFailed{Description: fmt.Sprintf("If-Match version %d on a path with no server entry", v)}
		}
		if current.Deleted {
			return &Conflict{Current: current, Description: fmt.Sprintf("file was deleted at version %d", current.Version)}
		}
		if current.Version != v {
			return &Conflict{
				Current:     current,
				Description: fmt.Sprintf("version mismatch: client has %d, server has %d", v, current.Version),
			}
		}
		return nil
	}
}
