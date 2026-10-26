package httpapi

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/files"
	syncpkg "github.com/litemd-hq/litemd/internal/sync"
)

type manifestResponse struct {
	Files []files.Entry `json:"files"`
}

// handleManifest returns the full file index of the authenticated user,
// including tombstones, ordered by path.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	entries, err := s.store.Manifest(user.UUID)
	if err != nil {
		s.log.Error("manifest", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if entries == nil {
		entries = []files.Entry{}
	}
	writeJSON(w, http.StatusOK, manifestResponse{Files: entries})
}

// resolveUserPath validates the URL path against the user's sandbox and
// returns the clean relative path plus its absolute filesystem location.
func (s *Server) resolveUserPath(user *bolt.User, raw string) (clean, abs string, err error) {
	clean, err = files.CleanRelPath(raw)
	if err != nil {
		return "", "", err
	}
	root := s.cfg.UserRoot(user.UUID)
	abs, err = files.Resolve(root, clean)
	if err != nil {
		return "", "", err
	}
	if err := files.CheckSymlinks(root, abs); err != nil {
		return "", "", err
	}
	return clean, abs, nil
}

// handleDownload streams a file with ETag (sha256) support: matching
// If-None-Match yields 304, Range requests are served by http.ServeContent.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, abs, err := s.resolveUserPath(user, r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	entry, err := s.store.GetFile(user.UUID, clean)
	if err != nil || entry.Deleted {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		if os.IsNotExist(err) {
			// Index and disk diverged: tombstone the ghost entry.
			s.log.Warn("indexed file missing on disk", "path", clean)
		}
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}

	etag := `"` + entry.SHA256 + `"`
	ct := entry.ContentType
	if ct == "" {
		// Entries written before content types existed: derive it now.
		ct = contentTypeFor(clean, abs)
	}
	ct = sanitizeContentType(ct)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", ct)
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	http.ServeContent(w, r, "", entry.ModTime, f)
}

func ifNoneMatch(header, etag string) bool {
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}
	return false
}

// handleUpload atomically writes the request body to the user's sandbox.
// Optimistic concurrency via If-Match: version match or "*"; mismatch is a
// 409 carrying the current server entry; If-Match on a never-existing path
// is a 412. Quota and global size cap are enforced mid-stream.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, abs, err := s.resolveUserPath(user, r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}

	// A file and a folder cannot occupy the same path.
	if folder, ferr := s.store.GetFolder(user.UUID, clean); ferr == nil && !folder.Deleted {
		writeErrorWith(w, http.StatusPreconditionFailed, "path_kind_conflict", "a folder already exists at this path", folder)
		return
	}

	entry, getErr := s.store.GetFile(user.UUID, clean)
	if getErr != nil && !storeNotFound(getErr) {
		s.log.Error("get file", "err", getErr)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// Mutations require an explicit precondition: no last-write-wins.
	if err := syncpkg.Check(r.Header.Get("If-Match"), r.Header.Get("If-None-Match"), syncpkg.EntryState(entry)); err != nil {
		s.writeSyncError(w, err)
		return
	}
	created := entry == nil || entry.Deleted

	allowed := s.cfg.MaxUpload
	if user.Quota > 0 {
		used, err := s.store.UsedBytes(user.UUID)
		if err != nil {
			s.log.Error("used bytes", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		var oldSize int64
		if entry != nil && !entry.Deleted {
			oldSize = entry.Size
		}
		quotaRoom := user.Quota - used + oldSize
		if quotaRoom <= 0 {
			writeError(w, http.StatusRequestEntityTooLarge, "quota_exceeded", "user quota exceeded")
			return
		}
		if quotaRoom < allowed {
			allowed = quotaRoom
		}
	}

	// Markdown uploads are validated for UTF-8 before the write is committed.
	isMarkdown := files.IsMarkdownFile(clean)
	var opts []files.Option
	if isMarkdown {
		opts = append(opts, files.WithVerify(verifyUTF8))
	}

	// The entry is parsed and committed in the tx around the rename: the file
	// is only published if metadata parsing and the atomic quota check pass, so
	// a rejected upload never replaces the previous version.
	newEntry := &files.Entry{Path: clean, ModTime: time.Now().UTC()}
	commit := func(tmpPath string, res files.WriteResult) error {
		newEntry.SHA256 = res.SHA256
		newEntry.Size = res.Size
		if isMarkdown {
			if meta, links, err := files.ParseFile(tmpPath); err == nil {
				newEntry.Metadata = meta
				newEntry.Links = links
			} else {
				s.log.Warn("markdown parse failed", "path", clean, "err", err)
			}
		}
		newEntry.ContentType = contentTypeFor(clean, tmpPath)
		return s.store.PutFileChecked(user.UUID, newEntry, user.Quota)
	}
	opts = append(opts, files.WithVerify(commit))

	if _, err := files.AtomicWrite(abs, http.MaxBytesReader(w, r.Body, allowed), allowed, opts...); err != nil {
		// http.MaxBytesReader aborts the read as soon as the cap is reached,
		// so an oversized body surfaces here rather than as files.ErrTooLarge.
		var maxBytes *http.MaxBytesError
		switch {
		case errors.Is(err, files.ErrInvalidEncoding):
			writeError(w, http.StatusBadRequest, "invalid_markdown", err.Error())
		case errors.Is(err, bolt.ErrQuotaExceeded):
			writeError(w, http.StatusRequestEntityTooLarge, "quota_exceeded", "user quota exceeded")
		case errors.Is(err, files.ErrTooLarge), errors.As(err, &maxBytes):
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "payload exceeds size limit or remaining quota")
		default:
			// Windows: rename over an open handle fails transiently; tell the
			// client to retry rather than surfacing a generic 500.
			s.log.Error("atomic write", "err", err, "path", clean)
			writeError(w, http.StatusInternalServerError, "write_failed", "file write failed; safe to retry")
		}
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, newEntry)
}

// verifyUTF8 streams an on-disk file through a UTF-8 validator. It runs as a
// pre-rename check so an invalid upload never replaces a good file.
func verifyUTF8(path string, _ files.WriteResult) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	v := files.NewUTF8Validator()
	if _, err := io.Copy(v, f); err != nil {
		return err
	}
	return v.Err()
}

// handleDelete tombstones a file so other clients observe the deletion as a
// new version during sync. The bytes are removed immediately. Like uploads, it
// requires a precondition (If-Match: <version>) so a stale delete cannot
// clobber a newer write.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, abs, err := s.resolveUserPath(user, r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	entry, err := s.store.GetFile(user.UUID, clean)
	if err != nil || entry.Deleted {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}
	if err := syncpkg.Check(r.Header.Get("If-Match"), "", syncpkg.EntryState(entry)); err != nil {
		s.writeSyncError(w, err)
		return
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		s.log.Error("delete", "err", err, "path", clean)
		writeError(w, http.StatusInternalServerError, "delete_failed", "file delete failed")
		return
	}
	entry.Deleted = true
	entry.Size = 0
	entry.ModTime = time.Now().UTC()
	if err := s.store.PutFile(user.UUID, entry); err != nil {
		s.log.Error("put file", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeSyncError(w http.ResponseWriter, err error) {
	if errors.Is(err, syncpkg.ErrPreconditionRequired) {
		writeError(w, http.StatusPreconditionRequired, "precondition_required", err.Error())
		return
	}
	var conflict *syncpkg.Conflict
	var precondition *syncpkg.PreconditionFailed
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict.Current, conflict.Description)
	case errors.As(err, &precondition):
		writeErrorWith(w, http.StatusPreconditionFailed, "precondition_failed", precondition.Description, precondition.Current)
	default:
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}
