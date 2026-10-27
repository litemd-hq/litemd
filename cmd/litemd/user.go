package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
)

const userUsage = `litemd user - manage accounts from the host

Usage:
  litemd user <command> [flags]

Commands:
  add      create a user (first user becomes the administrator)
  list     list users with quota and usage
  show     show one user
  rename   change a user's username
  passwd   set a user's password and sign them out everywhere
  promote  grant administrator
  demote   revoke administrator
  quota    set a user's storage quota (0 = unlimited)
  revoke   sign a user out of every device
  delete   delete a user and their files

Flags:
  -data <dir>        data directory (default ./data)
  -config <file>     read data_dir from a JSON config file
  -username <name>   target account (all commands except add/list)
  -new-name <name>   the new username (rename)
  -password <pw>     password (add, passwd)
  -admin             grant administrator on add
  -quota <size>      quota such as 1GiB, 500MiB or 0 (add, quota)

The database takes an exclusive lock, so stop the server before running this.
`

func userMain(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(errOut, userUsage)
		return flag.ErrHelp
	}
	cmd := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet("litemd user "+cmd, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprint(errOut, userUsage) }
	dataDir := fs.String("data", "./data", "data directory")
	configPath := fs.String("config", "", "read data_dir from a JSON config file")
	username := fs.String("username", "", "target account")
	newName := fs.String("new-name", "", "the new username (rename)")
	password := fs.String("password", "", "password (add, passwd)")
	admin := fs.Bool("admin", false, "grant administrator on add")
	quota := fs.String("quota", "", "quota such as 1GiB, 500MiB or 0")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %q", fs.Arg(0))
	}
	if *configPath != "" {
		cfg, err := config.Parse([]string{"-config", *configPath})
		if err != nil {
			return err
		}
		*dataDir = cfg.DataDir
	}

	if cmd == "help" {
		fmt.Fprint(out, userUsage)
		return nil
	}
	// Validate the command before touching the filesystem, so a typo never
	// creates a data directory.
	if !knownUserCommand(cmd) {
		return fmt.Errorf("unknown command %q; run `litemd user help`", cmd)
	}

	store, err := bolt.Open(*dataDir)
	if err != nil {
		return fmt.Errorf("open %s (is the server still running? stop it first): %w", *dataDir, err)
	}
	defer store.Close()

	svc, err := auth.NewService(store, config.DefaultAccessTokenTTL, config.DefaultRefreshTokenTTL)
	if err != nil {
		return err
	}

	switch cmd {
	case "add":
		return userAdd(out, svc, *username, *password, *admin, *quota)
	case "list":
		return userList(out, store)
	case "show":
		return userShow(out, store, *username)
	case "rename":
		return userRename(out, store, *username, *newName)
	case "passwd":
		return userPasswd(out, svc, store, *username, *password)
	case "promote", "demote":
		return userSetAdmin(out, store, *username, cmd == "promote")
	case "quota":
		return userSetQuota(out, store, *username, *quota)
	case "revoke":
		return userRevoke(out, store, *username)
	case "delete":
		return userDelete(out, store, *dataDir, *username)
	default:
		return fmt.Errorf("unknown command %q; run `litemd user help`", cmd)
	}
}

func knownUserCommand(cmd string) bool {
	switch cmd {
	case "add", "list", "show", "rename", "passwd", "promote", "demote", "quota", "revoke", "delete":
		return true
	default:
		return false
	}
}

func userAdd(out io.Writer, svc *auth.Service, username, password string, admin bool, quota string) error {
	if username == "" || password == "" {
		return errors.New("add requires -username and -password")
	}
	name, err := config.NormalizeUsername(username)
	if err != nil {
		return err
	}
	if err := config.ValidatePassword(password); err != nil {
		return err
	}
	q, err := parseQuota(quota)
	if err != nil {
		return err
	}
	u, err := svc.Register(auth.RegisterOptions{
		Username:        name,
		Password:        password,
		Quota:           q,
		IsAdmin:         admin,
		AdminAuthorized: true,
		Open:            true,
	})
	if err != nil {
		return err
	}
	role := "user"
	if u.IsAdmin {
		role = "admin"
	}
	fmt.Fprintf(out, "created %s %q (%s)\n", role, u.Username, u.UUID)
	return nil
}

func userList(out io.Writer, store *bolt.Store) error {
	users, err := store.ListUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Fprintln(out, "no users")
		return nil
	}
	for _, u := range users {
		used, err := store.UsedBytes(u.UUID)
		if err != nil {
			return err
		}
		role := "user"
		if u.IsAdmin {
			role = "admin"
		}
		fmt.Fprintf(out, "%-12s %-20s %-6s quota=%s used=%s\n",
			u.UUID[:12], u.Username, role, formatBytes(u.Quota), formatBytes(used))
	}
	return nil
}

func userShow(out io.Writer, store *bolt.Store, username string) error {
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	used, err := store.UsedBytes(u.UUID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "uuid:      %s\n", u.UUID)
	fmt.Fprintf(out, "username:  %s\n", u.Username)
	fmt.Fprintf(out, "admin:     %v\n", u.IsAdmin)
	fmt.Fprintf(out, "quota:     %s\n", formatBytes(u.Quota))
	fmt.Fprintf(out, "used:      %s\n", formatBytes(used))
	fmt.Fprintf(out, "created:   %s\n", u.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	return nil
}

func userRename(out io.Writer, store *bolt.Store, username, newName string) error {
	if newName == "" {
		return errors.New("rename requires -new-name")
	}
	name, err := config.NormalizeUsername(newName)
	if err != nil {
		return err
	}
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	updated, err := store.UpdateUserUsername(u.UUID, name)
	if err != nil {
		if errors.Is(err, bolt.ErrUsernameTaken) {
			return fmt.Errorf("username %q is already taken", name)
		}
		return err
	}
	fmt.Fprintf(out, "renamed %q to %q\n", u.Username, updated.Username)
	return nil
}

func userPasswd(out io.Writer, svc *auth.Service, store *bolt.Store, username, password string) error {
	if password == "" {
		return errors.New("passwd requires -password")
	}
	if err := config.ValidatePassword(password); err != nil {
		return err
	}
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	if err := svc.ResetPassword(u.UUID, password); err != nil {
		return err
	}
	fmt.Fprintf(out, "updated password for %q; signed them out everywhere\n", u.Username)
	return nil
}

func userSetAdmin(out io.Writer, store *bolt.Store, username string, isAdmin bool) error {
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	if _, err := store.UpdateUser(u.UUID, nil, &isAdmin); err != nil {
		if errors.Is(err, bolt.ErrLastAdmin) {
			return errors.New("refusing to remove the last administrator")
		}
		return err
	}
	verb := "promoted"
	if !isAdmin {
		verb = "demoted"
	}
	fmt.Fprintf(out, "%s %q\n", verb, u.Username)
	return nil
}

func userSetQuota(out io.Writer, store *bolt.Store, username, quota string) error {
	if quota == "" {
		return errors.New("quota requires -quota (use 0 for unlimited)")
	}
	q, err := parseQuota(quota)
	if err != nil {
		return err
	}
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	if _, err := store.UpdateUser(u.UUID, &q, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "set quota for %q to %s\n", u.Username, formatBytes(q))
	return nil
}

func userRevoke(out io.Writer, store *bolt.Store, username string) error {
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	n, err := store.RevokeAllForUser(u.UUID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "revoked %d session token(s) for %q\n", n, u.Username)
	return nil
}

func userDelete(out io.Writer, store *bolt.Store, dataDir, username string) error {
	u, err := lookupUser(store, username)
	if err != nil {
		return err
	}
	if err := store.DeleteUser(u.UUID); err != nil {
		if errors.Is(err, bolt.ErrLastAdmin) {
			return errors.New("refusing to delete the last administrator")
		}
		return err
	}
	cfg := &config.Config{DataDir: dataDir}
	if err := os.RemoveAll(cfg.UserRoot(u.UUID)); err != nil {
		fmt.Fprintf(out, "deleted %q, but could not remove their files: %v\n", u.Username, err)
		return nil
	}
	fmt.Fprintf(out, "deleted %q and their files\n", u.Username)
	return nil
}

func lookupUser(store *bolt.Store, username string) (*bolt.User, error) {
	if username == "" {
		return nil, errors.New("-username is required")
	}
	u, err := store.UserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("unknown user %q", username)
	}
	return u, nil
}

// parseQuota accepts a byte count or a KiB/MiB/GiB (or KB/MB/GB) suffixed size;
// an empty string means the built-in default and "0" means unlimited.
func parseQuota(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return config.DefaultQuotaBytes, nil
	}
	mult := int64(1)
	up := strings.ToUpper(s)
	for _, suffix := range []struct {
		name string
		mult int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	} {
		if strings.HasSuffix(up, suffix.name) {
			mult = suffix.mult
			s = strings.TrimSpace(s[:len(s)-len(suffix.name)])
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid quota %q", s)
	}
	return n * mult, nil
}

// formatBytes renders a byte count for humans; 0 means unlimited.
func formatBytes(n int64) string {
	if n == 0 {
		return "unlimited"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
