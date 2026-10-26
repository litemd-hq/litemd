package httpapi

import (
	"errors"
	"net/http"
	"time"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/files"
	syncpkg "github.com/litemd-hq/litemd/internal/sync"
)

type foldersResponse struct {
	Folders []files.Folder `json:"folders"`
}

// handleFolders returns every folder record of the authenticated user,
// including tombstones, ordered by path.
func (s *Server) handleFolders(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	folders, err := s.store.Folders(user.UUID)
	if err != nil {
		s.log.Error("folders", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if folders == nil {
		folders = []files.Folder{}
	}
	writeJSON(w, http.StatusOK, foldersResponse{Folders: folders})
}

// handleFolderPut creates (or resurrects) a folder record. Folders have no
// bytes; the record is what makes an empty folder sync between devices.
func (s *Server) handleFolderPut(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, err := files.CleanRelPath(r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}

	// A file and a folder cannot occupy the same path.
	if e, ferr := s.store.GetFile(user.UUID, clean); ferr == nil && !e.Deleted {
		writeErrorWith(w, http.StatusPreconditionFailed, "path_kind_conflict", "a file already exists at this path", e)
		return
	}

	folder, getErr := s.store.GetFolder(user.UUID, clean)
	if getErr != nil && !storeNotFound(getErr) {
		s.log.Error("get folder", "err", getErr)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if err := syncpkg.Check(r.Header.Get("If-Match"), r.Header.Get("If-None-Match"), syncpkg.FolderState(folder)); err != nil {
		s.writeSyncError(w, err)
		return
	}
	created := folder == nil || folder.Deleted

	f := &files.Folder{Path: clean, ModTime: time.Now().UTC()}
	if err := s.store.PutFolder(user.UUID, f); err != nil {
		s.log.Error("put folder", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, f)
}

// handleFolderDelete tombstones a folder record so other clients observe the
// deletion. By default only that record is removed: descendant files and
// folders are untouched, so a folder that still holds notes stays in the tree
// until those are removed too. With ?recursive=true the whole subtree (files
// and folders) is tombstoned and its bytes are removed in one transaction.
func (s *Server) handleFolderDelete(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, err := files.CleanRelPath(r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	folder, err := s.store.GetFolder(user.UUID, clean)
	if err != nil || folder.Deleted {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}
	if err := syncpkg.Check(r.Header.Get("If-Match"), "", syncpkg.FolderState(folder)); err != nil {
		s.writeSyncError(w, err)
		return
	}

	if r.URL.Query().Get("recursive") == "true" {
		deadFiles, deadFolders, err := s.store.DeleteFolderTree(s.cfg.UserRoot(user.UUID), user.UUID, clean)
		if err != nil {
			s.log.Error("delete folder tree", "err", err, "path", clean)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if deadFiles == nil {
			deadFiles = []files.Entry{}
		}
		if deadFolders == nil {
			deadFolders = []files.Folder{}
		}
		writeJSON(w, http.StatusOK, affectedRecords{Folders: deadFolders, Files: deadFiles})
		return
	}

	folder.Deleted = true
	folder.ModTime = time.Now().UTC()
	if err := s.store.PutFolder(user.UUID, folder); err != nil {
		s.log.Error("put folder", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type moveRequest struct {
	To string `json:"to"`
}

// affectedRecords is the response for operations that rewrite many paths at
// once (a folder move, or a recursive delete): every record that changed,
// tombstones included.
type affectedRecords struct {
	Folders []files.Folder `json:"folders"`
	Files   []files.Entry  `json:"files"`
}

// handleFolderMove renames or moves a folder and everything beneath it in a
// single transaction. It returns the affected records: a tombstone at each old
// path and a live record at each new path.
func (s *Server) handleFolderMove(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	from, err := files.CleanRelPath(r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	var req moveRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	to, err := files.CleanRelPath(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", "invalid destination: "+err.Error())
		return
	}
	if to == from || files.IsUnder(to, from) || files.IsUnder(from, to) {
		writeError(w, http.StatusPreconditionFailed, "invalid_move", "cannot move a folder into itself or over itself")
		return
	}

	folder, err := s.store.GetFolder(user.UUID, from)
	if err != nil || folder.Deleted {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}
	if err := syncpkg.Check(r.Header.Get("If-Match"), "", syncpkg.FolderState(folder)); err != nil {
		s.writeSyncError(w, err)
		return
	}

	movedFiles, movedFolders, err := s.store.MoveFolder(s.cfg.UserRoot(user.UUID), user.UUID, from, to)
	if err != nil {
		if errors.Is(err, bolt.ErrMoveCollision) {
			writeError(w, http.StatusConflict, "conflict", "destination path already exists")
			return
		}
		s.log.Error("move folder", "err", err, "from", from, "to", to)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if movedFiles == nil {
		movedFiles = []files.Entry{}
	}
	if movedFolders == nil {
		movedFolders = []files.Folder{}
	}
	writeJSON(w, http.StatusOK, affectedRecords{Folders: movedFolders, Files: movedFiles})
}
