package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestUserCLIDrivesAccountManagement bootstraps an admin through init, then
// exercises the host-side account commands against the same data directory.
func TestUserCLIDrivesAccountManagement(t *testing.T) {
	bin := requireBinary(t)
	dir := t.TempDir()
	data := filepath.Join(dir, "data")

	if out, err := exec.Command(bin, "init", "-batch",
		"-out", filepath.Join(dir, "config.json"),
		"-data", data,
		"-admin-username", "alice", "-admin-password", "password123",
	).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	run := func(args ...string) (string, error) {
		out, err := exec.Command(bin, append([]string{"user"}, args...)...).CombinedOutput()
		return string(out), err
	}

	out, err := run("list", "-data", data)
	if err != nil {
		t.Fatalf("user list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "admin") {
		t.Errorf("list missing alice/admin:\n%s", out)
	}

	if out, err := run("add", "-data", data, "-username", "bob", "-password", "password123", "-quota", "2MiB"); err != nil {
		t.Fatalf("user add: %v\n%s", err, out)
	}
	out, err = run("show", "-data", data, "-username", "bob")
	if err != nil {
		t.Fatalf("user show: %v\n%s", err, out)
	}
	if !strings.Contains(out, "username:  bob") || !strings.Contains(out, "quota:     2.0 MiB") {
		t.Errorf("show output unexpected:\n%s", out)
	}

	// Rename bob to robert.
	if out, err := run("rename", "-data", data, "-username", "bob", "-new-name", "robert"); err != nil {
		t.Fatalf("user rename: %v\n%s", err, out)
	}
	out, err = run("show", "-data", data, "-username", "robert")
	if err != nil {
		t.Fatalf("user show after rename: %v\n%s", err, out)
	}
	if !strings.Contains(out, "username:  robert") {
		t.Errorf("rename did not take effect:\n%s", out)
	}

	// Refuse to remove the only administrator.
	if out, err := run("demote", "-data", data, "-username", "alice"); err == nil {
		t.Errorf("demoting the last admin should fail:\n%s", out)
	}

	// Deleting a user works.
	if out, err := run("delete", "-data", data, "-username", "robert"); err != nil {
		t.Fatalf("user delete: %v\n%s", err, out)
	}
	out, _ = run("list", "-data", data)
	if strings.Contains(out, "robert") {
		t.Errorf("robert should be gone:\n%s", out)
	}
}

func TestUserCLIUnknownCommand(t *testing.T) {
	bin := requireBinary(t)
	out, err := exec.Command(bin, "user", "banana").CombinedOutput()
	if err == nil {
		t.Errorf("an unknown subcommand should fail:\n%s", out)
	}
}
