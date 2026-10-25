package sync

import (
	"errors"
	"testing"

	"github.com/litemd-hq/litemd/internal/files"
)

func live(v uint64) *files.Entry { return &files.Entry{Path: "a.md", Version: v} }
func tomb(v uint64) *files.Entry { return &files.Entry{Path: "a.md", Version: v, Deleted: true} }

func TestCheck(t *testing.T) {
	const (
		wantNil = iota
		wantRequired
		wantConflict
		wantPrecond
	)

	cases := []struct {
		name        string
		ifMatch     string
		ifNoneMatch string
		current     *files.Entry
		want        int
	}{
		{"no precondition", "", "", live(1), wantRequired},

		{"both preconditions", "1", "*", live(1), wantPrecond},

		{"create when absent", "", "*", nil, wantNil},
		{"create over tombstone", "", "*", tomb(3), wantNil},
		{"create over live", "", "*", live(1), wantPrecond},
		{"create with junk value", "", "abc", live(1), wantPrecond},

		{"cas match", "2", "", live(2), wantNil},
		{"cas mismatch", "1", "", live(2), wantConflict},
		{"cas on absent path", "1", "", nil, wantPrecond},
		{"cas on tombstone", "3", "", tomb(3), wantConflict},
		{"cas wildcard", "*", "", live(1), wantPrecond},
		{"cas malformed", "x", "", live(1), wantPrecond},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.ifMatch, tc.ifNoneMatch, tc.current)
			switch tc.want {
			case wantNil:
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			case wantRequired:
				if !errors.Is(err, ErrPreconditionRequired) {
					t.Fatalf("err = %v, want ErrPreconditionRequired", err)
				}
			case wantConflict:
				var c *Conflict
				if !errors.As(err, &c) {
					t.Fatalf("err = %v, want *Conflict", err)
				}
				if c.Current == nil {
					t.Error("conflict must carry the current entry")
				}
			case wantPrecond:
				var p *PreconditionFailed
				if !errors.As(err, &p) {
					t.Fatalf("err = %v, want *PreconditionFailed", err)
				}
			}
		})
	}
}

func TestPreconditionFailureCarriesEntryWhenKnown(t *testing.T) {
	// "create over live" is a 412 that should still hand back the entry so the
	// client can retry with the right version.
	err := Check("", "*", live(7))
	var p *PreconditionFailed
	if !errors.As(err, &p) {
		t.Fatalf("err = %v, want *PreconditionFailed", err)
	}
	if p.Current == nil || p.Current.Version != 7 {
		t.Errorf("current = %+v, want version 7", p.Current)
	}
}
