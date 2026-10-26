// Package sync defines the optimistic-concurrency rules shared by the server's
// mutation handlers and (documentationally) by clients. It is resource-agnostic:
// files and folders both check their preconditions through Check.
//
// Every mutating request must carry exactly one precondition. Unconditional
// writes are rejected, so two devices editing the same target surface a conflict
// instead of silently overwriting each other.
//
//	If-Match: <version>   compare-and-swap. The record must exist live at exactly
//	                      that version.
//	                        version mismatch        -> 409 + current record
//	                        path absent             -> 412
//	                        path deleted/tombstoned -> 409 + current record
//	If-None-Match: *      create-only. The path must not hold a live record.
//	                        existing live record    -> 412 + current record
//	                        absent or tombstoned    -> proceed
//
// Neither precondition -> 428 Precondition Required. Both -> 412.
//
// Clients reconcile a 409/412 by fetching the returned current record, merging
// against their local copy, and retrying with the new version.
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
// server state (a *files.Entry or *files.Folder) so clients can resolve
// deterministically.
type Conflict struct {
	Current     any
	Description string
}

func (c *Conflict) Error() string { return c.Description }

// PreconditionFailed reports a structurally wrong precondition: malformed, an
// unsupported form, or an assumption that does not hold (e.g. If-None-Match
// against an existing record).
type PreconditionFailed struct {
	Current     any
	Description string
}

func (p *PreconditionFailed) Error() string { return p.Description }

// State is the resource-agnostic snapshot a precondition is checked against.
// Current is the record to embed in the error envelope (a *files.Entry or
// *files.Folder) and is nil when the path has no record at all.
type State struct {
	Exists  bool   // a record exists, live or tombstoned
	Deleted bool   // that record is a tombstone
	Version uint64 // meaningful only when Exists
	Current any    // server record to hand back on failure, or nil
}

// EntryState builds the precondition state for a file entry (nil when absent).
func EntryState(e *files.Entry) State {
	if e == nil {
		return State{}
	}
	return State{Exists: true, Deleted: e.Deleted, Version: e.Version, Current: e}
}

// FolderState builds the precondition state for a folder record (nil when absent).
func FolderState(f *files.Folder) State {
	if f == nil {
		return State{}
	}
	return State{Exists: true, Deleted: f.Deleted, Version: f.Version, Current: f}
}

// Check applies the OCC rules to st. A tombstone is a present-but-deleted
// record; an absent path is Exists=false.
func Check(ifMatch, ifNoneMatch string, st State) error {
	switch {
	case ifMatch == "" && ifNoneMatch == "":
		return ErrPreconditionRequired

	case ifMatch != "" && ifNoneMatch != "":
		return &PreconditionFailed{Description: "send either If-Match or If-None-Match, not both"}

	case ifNoneMatch != "":
		if ifNoneMatch != "*" {
			return &PreconditionFailed{Description: fmt.Sprintf("unsupported If-None-Match %q: only \"*\" is allowed", ifNoneMatch)}
		}
		if st.Exists && !st.Deleted {
			return &PreconditionFailed{Current: st.Current, Description: "path already exists"}
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
		if !st.Exists {
			return &PreconditionFailed{Description: fmt.Sprintf("If-Match version %d on a path with no server entry", v)}
		}
		if st.Deleted {
			return &Conflict{Current: st.Current, Description: fmt.Sprintf("record was deleted at version %d", st.Version)}
		}
		if st.Version != v {
			return &Conflict{
				Current:     st.Current,
				Description: fmt.Sprintf("version mismatch: client has %d, server has %d", v, st.Version),
			}
		}
		return nil
	}
}
