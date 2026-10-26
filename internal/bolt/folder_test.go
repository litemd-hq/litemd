package bolt

import (
	"encoding/json"
	"testing"

	bbolt "go.etcd.io/bbolt"

	"github.com/litemd-hq/litemd/internal/files"
)

// TestPutFileCreatesAncestorFolders checks that writing a file records every
// ancestor directory as a folder, so folders sync even when empty.
func TestPutFileCreatesAncestorFolders(t *testing.T) {
	s := testStore(t)

	if err := s.PutFile("u1", entry("a/b/c.md", 1)); err != nil {
		t.Fatalf("put: %v", err)
	}
	got := map[string]bool{}
	folders, err := s.Folders("u1")
	if err != nil {
		t.Fatalf("folders: %v", err)
	}
	for _, f := range folders {
		if !f.Deleted {
			got[f.Path] = true
		}
	}
	if !got["a"] || !got["a/b"] {
		t.Fatalf("ancestor folders = %v, want a and a/b", got)
	}
}

// TestBackfillFolders checks the one-time migration that gives a pre-existing
// vault (files written before folders existed) its folder records.
func TestBackfillFolders(t *testing.T) {
	s := testStore(t)

	// Simulate a legacy entry written directly, bypassing putEntry's upkeep.
	raw, err := json.Marshal(&files.Entry{Path: "notes/deep/plan.md", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(BucketFiles).Put(fileKey("u1", "notes/deep/plan.md"), raw)
	}); err != nil {
		t.Fatal(err)
	}

	if folders, _ := s.Folders("u1"); len(folders) != 0 {
		t.Fatalf("expected no folders before backfill, got %v", folders)
	}
	if err := s.BackfillFolders(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	got := map[string]bool{}
	folders, _ := s.Folders("u1")
	for _, f := range folders {
		got[f.Path] = true
	}
	if !got["notes"] || !got["notes/deep"] {
		t.Fatalf("backfilled folders = %v, want notes and notes/deep", got)
	}
}

// TestMoveFolderRewritesTree checks that a move tombstones the old paths and
// creates the new ones for both files and folders.
func TestMoveFolderRewritesTree(t *testing.T) {
	s := testStore(t)

	if err := s.PutFile("u1", entry("notes/a.md", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile("u1", entry("notes/deep/b.md", 1)); err != nil {
		t.Fatal(err)
	}

	movedFiles, movedFolders, err := s.MoveFolder("", "u1", "notes", "journal")
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if len(movedFiles) != 4 { // two tombstones + two live entries
		t.Errorf("moved files = %d, want 4", len(movedFiles))
	}
	if len(movedFolders) != 4 { // notes, notes/deep tombstones + journal, journal/deep live
		t.Errorf("moved folders = %d, want 4", len(movedFolders))
	}

	live := map[string]bool{}
	all, _ := s.Manifest("u1")
	for _, e := range all {
		if !e.Deleted {
			live[e.Path] = true
		}
	}
	if !live["journal/a.md"] || !live["journal/deep/b.md"] {
		t.Fatalf("live files = %v, want journal paths", live)
	}
	if live["notes/a.md"] || live["notes/deep/b.md"] {
		t.Fatalf("old paths should be tombstoned: %v", live)
	}

	// The move is refused when it would clobber a live destination.
	if err := s.PutFile("u1", entry("other/x.md", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile("u1", entry("target/x.md", 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MoveFolder("", "u1", "other", "target"); err == nil {
		t.Error("expected a collision error moving other -> target")
	}
}

// TestDeleteFolderTree checks that a recursive delete tombstones the whole
// subtree and leaves unrelated paths alone.
func TestDeleteFolderTree(t *testing.T) {
	s := testStore(t)
	for _, p := range []string{"notes/a.md", "notes/deep/b.md", "keep/other.md"} {
		if err := s.PutFile("u1", entry(p, 1)); err != nil {
			t.Fatal(err)
		}
	}

	deadFiles, deadFolders, err := s.DeleteFolderTree("", "u1", "notes")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(deadFiles) != 2 {
		t.Errorf("dead files = %d, want 2", len(deadFiles))
	}
	if len(deadFolders) != 2 { // notes and notes/deep
		t.Errorf("dead folders = %d, want 2", len(deadFolders))
	}
	for _, d := range deadFiles {
		if !d.Deleted {
			t.Errorf("file %s not tombstoned", d.Path)
		}
	}
	for _, d := range deadFolders {
		if !d.Deleted {
			t.Errorf("folder %s not tombstoned", d.Path)
		}
	}

	live := map[string]bool{}
	all, _ := s.Manifest("u1")
	for _, e := range all {
		if !e.Deleted {
			live[e.Path] = true
		}
	}
	if !live["keep/other.md"] {
		t.Errorf("unrelated file removed: %v", live)
	}
	if live["notes/a.md"] || live["notes/deep/b.md"] {
		t.Errorf("deleted files still live: %v", live)
	}
}
