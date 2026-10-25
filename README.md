# litemd

A lightweight, single-binary sync server for Markdown notes.

## Status

Early and self-host-focused. It is actively used and tested but **not
production-hardened** yet: TLS is self-signed unless you supply a certificate,
rate limiting is in-process, access tokens cannot be revoked before they expire,
and the API may change before 1.0. Treat deployments behind a VPN or on a
trusted network as the supported configuration today.

## Features

- Single self-contained binary (embedded database, no external services)
- Per-user sandboxes with one folder per user
- JWT auth: short-lived access tokens plus rotating refresh tokens
  (refresh-token reuse revokes the whole token family)
- Atomic, crash-safe writes (write-temp + fsync + rename)
- Optimistic concurrency on every write: `If-Match: <version>` to update,
  `If-None-Match: *` to create, with tombstones so deletions propagate.
  There is no last-write-wins path; conflicting writes are rejected.
- Markdown-aware: UTF-8 validation and YAML frontmatter metadata
  (`title`, `tags`, arbitrary extras) parsed on upload and returned with
  every file entry
- Derived indexes built atomically with every write: tag index, wikilink
  backlinks, note graph, and an "unresolved targets" list
- Attachments (images, audio, video, PDFs, documents) stored as opaque bytes
  with a persisted MIME type, served with `Range` support and XSS-safe types
- Per-user storage quotas and a global upload size cap
- TLS with automatic self-signed certificate generation
- Per-IP rate limiting on authentication endpoints

## Install / Build

```bash
go install github.com/litemd-hq/litemd/cmd/litemd@latest
# or
make build
```

## Getting started

Run the setup wizard. It asks a few questions, writes a config file, and creates
your first account (the first account is the admin):

```bash
litemd init
```

```
  █ litemd setup

  Basics
    Data directory: [/var/lib/litemd] /srv/litemd
    Listen address: [:8443]
    Quota per user: [1GiB]
    ...
  ──────────────────────
  Configuration to write
  config file         /etc/litemd/config.json
  data directory      /srv/litemd
  quota per user      1 GiB
  administrator       alice
  ──────────────────────
  ✓ wrote /etc/litemd/config.json
  ✓ created administrator "alice"

  Next steps
    → litemd -config /etc/litemd/config.json
```

It degrades gracefully: with no terminal on stdin (Docker, Ansible, CI) it never
prompts and uses flags plus defaults, so the same command is scriptable:

```bash
litemd init -batch -out /etc/litemd/config.json -data /srv/litemd \
  -tls insecure -trusted-proxies 127.0.0.1/32 \
  -admin-username alice -admin-password "$(cat /run/secrets/litemd-admin)"
```

An existing config file is never clobbered without `-force`. Output is plain
ASCII with no colour when piped, so it is safe to log.

## Usage

```bash
litemd help                  # list commands and server flags
litemd init                  # interactive setup (writes a config, creates the admin)
litemd                       # start the server
litemd -version              # print the version
```

```bash
litemd -addr ":8443" -data /path/to/data
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-config` | none | Path to a JSON config file |
| `-addr` | `:8443` | Listen address |
| `-data` | `./data` | Data directory (database, TLS certs, user files) |
| `-tls-cert` | auto | TLS certificate path (PEM) |
| `-tls-key` | auto | TLS private key path (PEM) |
| `-insecure` | `false` | Serve plain HTTP; use only behind a TLS-terminating proxy |
| `-quota-bytes` | 1 GiB | Per-user storage quota |
| `-max-upload` | 64 MiB | Maximum accepted upload size |
| `-access-ttl` | `15m` | Access token lifetime |
| `-refresh-ttl` | `168h` | Refresh token lifetime |
| `-trusted-proxies` | none | Comma-separated IPs/CIDRs whose `X-Forwarded-For` is trusted |
| `-rate-limit-burst` | `10` | Auth requests allowed in a burst per client |
| `-rate-limit-refill-per-sec` | `0.1` | Auth rate limit token refill per second |
| `-log-level` | `info` | `debug`, `info`, `warn` or `error` |

### Configuration file

Every setting can live in a JSON file instead of flags. Point the server at one
with `-config /etc/litemd/config.json` or `LITEMD_CONFIG`:

```json
{
  "addr": ":8443",
  "data_dir": "/var/lib/litemd",
  "tls_cert": "",
  "tls_key": "",
  "insecure": false,
  "quota_bytes": 1073741824,
  "max_upload": 67108864,
  "access_ttl": "15m",
  "refresh_ttl": "168h",
  "trusted_proxies": ["127.0.0.1/32", "::1/128"],
  "rate_limit_burst": 10,
  "rate_limit_refill_per_sec": 0.1,
  "log_level": "info"
}
```

See [`config.example.json`](config.example.json). Durations accept a Go string
(`"15m"`, `"168h"`) or nanoseconds as a number; sizes are bytes. Unknown keys are
rejected, so typos fail loudly rather than being silently ignored. Since the file
may name certificate paths, keep it readable only by the service user (`chmod 600`).

Precedence, lowest to highest:

1. built-in defaults
2. the config file
3. `LITEMD_*` environment variables
4. explicit command-line flags

So a flag always wins, and you can keep secrets or host-specific values in the
environment while sharing the rest of the file.

All settings are also available as `LITEMD_*` environment variables
(e.g. `LITEMD_ADDR`, `LITEMD_DATA_DIR`, `LITEMD_CONFIG`).

### TLS

Without a certificate the server generates a self-signed one into the data
directory on first boot. Clients must then trust it explicitly or skip
verification — fine for a LAN or VPN, not for the public internet. Point it at a
real certificate instead:

```bash
litemd -tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
       -tls-key  /etc/letsencrypt/live/example.com/privkey.pem
```

**Behind Cloudflare Tunnel (or any TLS-terminating proxy) you do not need a
certificate here at all.** The tunnel terminates TLS at Cloudflare's edge and
the `cloudflared` connection to your origin is already authenticated and
encrypted, so run the origin as `-insecure` bound to loopback and let the tunnel
handle HTTPS:

```bash
litemd -insecure -addr 127.0.0.1:8443 -data /var/lib/litemd
cloudflared tunnel --url http://127.0.0.1:8443
```

When you put the server behind a proxy, also set `-trusted-proxies` to the
proxy's address (e.g. `-trusted-proxies 127.0.0.1/32`) so rate limiting sees the
real client IP from `X-Forwarded-For`. Without it, every client shares one
bucket and a single attacker can lock everyone out.

### Sessions and revocation

Two tokens are issued at login: a short-lived **access token** (sent as
`Authorization: Bearer`) and a long-lived **refresh token** that rotates on
every use. Re-presenting a consumed refresh token is treated as theft and
revokes the whole family.

`POST /api/v1/auth/revoke-all` (authenticated) deletes every refresh token for
the account, signing it out on all devices. Access tokens already issued remain
valid until they expire, which is why `-access-ttl` defaults to 15 minutes;
raise it only if you accept a longer revocation window.

## API

Base path: `/api/v1`. Full contract: [`api/openapi.yaml`](api/openapi.yaml).

### Authentication

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/auth/register` | Register a user (first user becomes admin) |
| `POST` | `/auth/login` | Obtain an access/refresh token pair |
| `POST` | `/auth/refresh` | Rotate the refresh token |
| `POST` | `/auth/logout` | Invalidate a refresh token |
| `POST` | `/auth/revoke-all` | Sign out of every device (auth required) |

### Files

All file routes require `Authorization: Bearer <access_token>`.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/files` | Full manifest, including tombstones and Markdown metadata |
| `GET` | `/files/{path}` | Download a file (`ETag`, `If-None-Match`, Range) |
| `PUT` | `/files/{path}` | Upload a file atomically (requires a precondition) |
| `DELETE` | `/files/{path}` | Delete a file (tombstone; requires a precondition) |

### Concurrency (no last-write-wins)

Every write must carry exactly one precondition. Requests without one are
rejected with `428 Precondition Required`.

| Goal | Header | Failure |
| --- | --- | --- |
| Create a new file | `If-None-Match: *` | `412` if a live file exists |
| Update an existing file | `If-Match: <version>` | `409` if the version moved |
| Delete | `If-Match: <version>` | `409` if the version moved |

`<version>` is the entry's numeric `version` from the manifest, **not** the
`ETag` (which is the content `sha256`). On `409` the response body carries the
current server entry under `error.server_entry`; the client fetches that
version, runs its three-way (`diff-match-patch`) merge, and retries with the new
version. A tombstone is treated as "no live file", so `If-None-Match: *` can
recreate a deleted path.

Because a stale `DELETE` now also conflicts, a delete issued from a device with
old state can no longer silently discard a newer write.

### Conflict copies (binaries, and unresolved merges)

Markdown clients resolve conflicts by three-way merging (`diff-match-patch`) and
retrying, so conflicts are rare. Binaries cannot be merged, so the recommended
pattern is **keep-both**, implemented entirely on the client — the server needs
no new endpoints:

1. On `409`, the client writes its own bytes to a *conflict copy* using
   `If-None-Match: *`, leaving the canonical path holding the server's version.
2. On `412` (the name is taken), it retries with a disambiguated suffix.
3. It resolves later, in any UI it likes, with ordinary operations:

   | Choice | Operations |
   | --- | --- |
   | Keep theirs | `DELETE` the conflict copy |
   | Keep mine | `PUT` the canonical path with `If-Match: <version>`, then `DELETE` the copy |
   | Keep both | `PUT` the copy to a chosen name, then `DELETE` the placeholder |

The server never learns which side "won" — the decision is expressed as normal
writes and deletes, and the copy disappears when the client deletes it.

**Naming convention:** insert a marker before the extension so the derived
`content_type` stays correct, and avoid characters the path validator rejects
(notably `:`):

```
notes/photo.jpg
  -> notes/photo (conflict copy phone 2026-10-25T18-30-00Z).jpg
```

Conflict copies are ordinary files: they count against quota, appear in every
device's manifest, and propagate like anything else. Clients should remember
locally that a path is conflicted so they do not re-upload and loop, and should
evict old copies (`GET /files` gives `mtime`/`size` to age them out).

### Indexes

Built and updated inside the same database transaction as every write, so they
never lag the manifest. For pre-existing data they are backfilled once at
startup.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/tags` | All tags with live-note counts |
| `GET` | `/tags/{tag}` | Notes carrying a tag |
| `GET` | `/links/{path}` | Outgoing wikilinks, each with resolution status |
| `GET` | `/backlinks/{path}` | Notes that link to this note |
| `GET` | `/unresolved` | Link targets with no matching note, ranked by refs |
| `GET` | `/graph` | `{nodes, edges}` for graph UIs |

### Markdown metadata

On upload, any path ending in `.md` or `.markdown` is validated as UTF-8 and
its leading YAML frontmatter is parsed. The result is stored with the entry and
returned from `GET /files` and `PUT /files/{path}`:

```yaml
---
title: Release Plan
tags: [planning, q4]
author: alice
---
# Release Plan
```

```json
{
  "path": "notes/plan.md",
  "version": 42,
  "sha256": "…",
  "size": 128,
  "mtime": "2026-04-01T12:00:00Z",
  "metadata": {
    "title": "Release Plan",
    "tags": ["planning", "q4"],
    "extra": { "author": "alice" }
  }
}
```

Files without frontmatter upload normally and simply omit `metadata`.
Non-Markdown files are stored byte-for-byte with no metadata.

### Tags and wikilinks

Tags come from two places and are merged: the `tags:` frontmatter key and
inline `#tag` tokens in the body. They are lowercased and de-duplicated.

Wikilinks `[[Target]]`, `[[Target|alias]]` and `[[Target#heading]]` are parsed
from the body (fenced and inline code are ignored). Backlinks are matched by
note *name* (base name without extension, case-insensitive), mirroring the
common "shortest path" resolution model, so links survive renames. Note that
two notes sharing a name in different folders resolve to the lexicographically
first path.

```markdown
---
title: Roadmap
tags: [planning]
---

See [[Design Doc]] for context. #q4
```

`GET /links/notes/roadmap.md` reports whether each target currently resolves,
and `GET /backlinks/notes/design-doc.md` lists the notes pointing at it.

### Attachments

Images, audio, video, PDFs and other documents upload and download as opaque
bytes through the same endpoints as notes; nothing is parsed. The only special
treatment is the MIME type:

- On upload the server records a `content_type` on the entry, preferring the
  path extension and falling back to sniffing the first 512 bytes. The
  client-supplied request `Content-Type` is ignored, so a client cannot label a
  file `text/html`.
- On download that type is sent in `Content-Type`, so browsers render or play
  supported media inline and download the rest. `Range` requests work, giving
  seeking for audio/video.
- Browser-executable types (`text/html`, `image/svg+xml`, `application/xml`,
  JavaScript, ...) are downgraded to `application/octet-stream` to avoid
  stored-XSS when served alongside `X-Content-Type-Options: nosniff`.
- Entries written before this existed have no stored type; the server derives
  it on demand at download time.

Note the default limits: `-max-upload` is 64 MiB and the server read/write
timeouts are 5 minutes, which will reject large media uploads unless raised.

### Paths and limits

A path is the file's location relative to your vault root, e.g.
`notes/daily/2026-10-25.md`. These are rejected outright:

- absolute paths (`/etc/passwd`) and backslashes
- any `.` or `..` segment
- segments ending in `.` or a space, and DOS device names (`CON`, `NUL`, `COM1`, ...)
- `<`, `>`, `:`, `"`, `|`, `?`, `*`, and control characters
- more than 1024 bytes overall, 32 segments, or 255 runes in one segment

| Limit | Default | Setting |
| --- | --- | --- |
| Maximum upload size | 64 MiB | `-max-upload` |
| Per-user storage quota | 1 GiB | `-quota-bytes` |
| Access token lifetime | 15 m | `-access-ttl` |
| Refresh token lifetime | 168 h | `-refresh-ttl` |
| Auth burst / refill | 10 / 0.1 per s | `-rate-limit-burst`, `-rate-limit-refill-per-sec` |
| Upload/download timeout | 5 m | built in |

### Error reference

Every error uses one envelope:

```json
{ "error": { "code": "conflict", "message": "version mismatch: client has 4, server has 7",
             "server_entry": { "path": "a.md", "version": 7, "...": "..." } } }
```

`server_entry` is always present on `409`, and on `412` when the server knows the
current entry.

| Status | Codes | Meaning |
| --- | --- | --- |
| 400 | `bad_request`, `bad_username`, `bad_password`, `invalid_path`, `invalid_markdown`, `invalid_request` | malformed input, bad path, or a non-UTF-8 Markdown upload |
| 401 | `unauthorized`, `invalid_credentials`, `token_expired`, `token_revoked` | missing/expired bearer token, or a reused refresh token |
| 403 | `forbidden` | registration attempted without an admin token |
| 404 | `not_found` | no such file, or the path is a tombstone |
| 409 | `conflict`, `username_taken` | version mismatch, or a deleted path |
| 412 | `precondition_failed` | `If-Match` on an absent path, `If-None-Match` on an existing one, or a malformed precondition |
| 413 | `too_large`, `quota_exceeded` | body exceeds `-max-upload`, or the user's quota |
| 428 | `precondition_required` | a write arrived with no precondition |
| 429 | `rate_limited` | too many auth attempts; see `Retry-After` |
| 500 | `internal`, `write_failed`, `delete_failed` | server-side failure; `write_failed` is safe to retry |

### Rate limiting

`POST /auth/login` and `POST /auth/refresh` are limited per client IP with a
token bucket. Exceeding it returns `429` with `Retry-After: 30`. Behind a proxy,
set `-trusted-proxies` so the real address from `X-Forwarded-For` is used —
otherwise every user shares a single bucket. `X-Forwarded-For` is ignored unless
the immediate peer is a configured trusted proxy, so a client cannot spoof it.

### Worked example

```bash
BASE=https://localhost:8443

# First account becomes the admin.
curl -sk -X POST $BASE/api/v1/auth/register -H 'content-type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# Log in for a token pair.
TOKENS=$(curl -sk -X POST $BASE/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"password123"}')
ACCESS=$(printf '%s' "$TOKENS" | jq -r .access_token)

# Create a note (create-only, so it cannot clobber an existing file).
curl -sk -X PUT $BASE/api/v1/files/notes/hello.md \
  -H "authorization: Bearer $ACCESS" -H 'if-none-match: *' \
  --data-binary $'---\ntitle: Hello\ntags: [demo]\n---\nSee [[World]].\n'

# The manifest: every entry, tombstones included.
curl -sk $BASE/api/v1/files -H "authorization: Bearer $ACCESS" | jq

# Download (add If-None-Match: "<sha256>" to get 304 when unchanged).
curl -sk $BASE/api/v1/files/notes/hello.md -H "authorization: Bearer $ACCESS"

# Update using the version from the manifest, then delete it the same way.
curl -sk -X PUT $BASE/api/v1/files/notes/hello.md \
  -H "authorization: Bearer $ACCESS" -H 'if-match: 2' --data-binary @hello.md
curl -sk -X DELETE $BASE/api/v1/files/notes/hello.md \
  -H "authorization: Bearer $ACCESS" -H 'if-match: 3'
```

## Development

```bash
make test    # run tests
make build   # build ./litemd
make run     # build and run
```

## Deployment

A `Dockerfile` and a hardened `deploy/litemd.service` unit are included.

```bash
# Container (mount a volume at /data)
docker build -t litemd .
docker run -d -p 127.0.0.1:8443:8443 -v litemd-data:/data litemd

# systemd
sudo install -m755 litemd /usr/local/bin/litemd
sudo useradd --system --home /var/lib/litemd litemd
sudo install -m644 deploy/litemd.service /etc/systemd/system/
sudo systemctl enable --now litemd
```

### Backups

All state lives in the data directory: `litemd.db` (users, tokens, file index and
derived indexes) plus the per-user files under `users/`. The embedded database is
**single-process** — a second server opening the same directory waits 5 seconds
then fails — so copy the whole directory with the server stopped:

```bash
sudo systemctl stop litemd
sudo cp -a /var/lib/litemd /backup/litemd-$(date +%F)
sudo systemctl start litemd
```

There is no online snapshot endpoint yet, so a hot copy can capture a torn
database. Restoring is the reverse: stop the server, replace the directory, start
it again. On first boot it backfills any missing derived indexes.

## Project layout

| Package | Responsibility |
| --- | --- |
| `cmd/litemd` | entry point, subcommand dispatch (`init`, `help`, `-version`) |
| `internal/config` | flags, environment and JSON config; precedence and validation |
| `internal/setup` | the `litemd init` wizard |
| `internal/auth` | Argon2id hashing, JWT access tokens, rotating refresh tokens |
| `internal/bolt` | the bbolt store: users, tokens, file index, tag/backlink indexes |
| `internal/files` | path sandbox, atomic writes, Markdown parsing, content-type sniffing |
| `internal/sync` | the optimistic-concurrency precondition rules |
| `internal/httpapi` | handlers, middleware, routing |
| `internal/tlsutil` | certificate generation and loading |
| `api/openapi.yaml` | the HTTP contract |

## Releases and CI

Releases are built locally with [goreleaser](https://goreleaser.com); there is no
release workflow in CI. Cross-compiling is fully supported — the release matrix
covers Linux/macOS on amd64 and arm64, plus 32-bit ARM (`armv6`, `armv7`) for
Raspberry Pi images.

### Versioning

The **git tag is the version**. goreleaser reads it and stamps the binary:

```bash
git add -A && git commit -m "..."     # tag a commit, not an empty tree
git tag v0.1.0
goreleaser release                    # -> litemd_0.1.0_Linux_armv7.tar.gz, "litemd 0.1.0"
```

goreleaser strips the leading `v`, so the tag `v0.1.0` yields `litemd 0.1.0`.
Snapshot builds (no tag) report `0.0.0-SNAPSHOT-<sha>`.

For builds that do not go through goreleaser, the version comes from a constant
in `cmd/litemd/main.go` — bump it when you cut a release so local builds do not
lag the tag:

```bash
go build ./cmd/litemd && ./litemd -version   # litemd 0.1.0
make build VERSION=0.2.0-rc1                 # one-off override
```

`-version` prints it, and the server logs it on startup.

### Release commands

Each release attaches **both** wrapped and unwrapped builds:

- `litemd_<version>_<Os>_<arch>.tar.gz` (or `.zip` on Windows) — preserves the
  executable bit.
- `litemd_<version>_<Os>_<arch>` (or `.exe`) — the bare executable, for
  downloading and running directly. GitHub does not store the executable bit, so
  a downloaded binary may need `chmod +x`; on macOS a downloaded binary is also
  quarantined, and `xattr -d com.apple.quarantine litemd_…` clears it.

```bash
goreleaser check                        # validate .goreleaser.yml
make snapshot                           # goreleaser release --snapshot --clean
make release                            # goreleaser release (needs a tag + GITHUB_TOKEN)
```

`make snapshot` needs no tag: it builds every target into `dist/`, with the
plain runnable binaries at `dist/litemd_<os>_<arch>_<variant>/litemd`, e.g.
`dist/litemd_darwin_arm64_v8.0/litemd` on Apple Silicon or
`dist/litemd_linux_arm_7/litemd` for a 32-bit Pi. The reported version is
`0.0.0-SNAPSHOT-<sha>` until you tag.

`.github/workflows/ci.yml` runs `gofmt`, `go vet`, `go build` and
`go test -race` on every push and pull request. It does not build or publish
binaries — that is goreleaser's job. Keep it if you want a second pair of eyes on
each push (and it is what makes a "tests pass" claim verifiable to others); drop
it if you are the only committer and always run the suite locally before pushing.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Every request is `401` | The access token expired (15 m by default) — refresh it. Note the value is a real JWT, not the file `ETag`. |
| `428 precondition_required` | You sent a write without `If-Match` or `If-None-Match`. Send exactly one. |
| `409` over and over | Another device is writing the same path. Read `error.server_entry`, resolve, retry with the new version. |
| Client refuses the certificate | It is self-signed. Import the generated `tls.crt`, pass a real certificate with `-tls-cert`/`-tls-key`, or terminate TLS at a proxy. |
| `open .../litemd.db: timeout` | Another process holds the database. bbolt is single-process: stop the other instance. |
| `address already in use` | Another instance is listening on that port. |
| `permission denied` on the data directory | Run `litemd init` as the service user, or `chown` the directory. |
| Server will not start after moving the data directory | The TLS certificate lives inside it; move the whole directory, not just the database. |
| Uploads fail at 64 MiB | Raise `-max-upload`. |
| `invalid_markdown` | A `.md`/`.markdown` upload was not valid UTF-8. |

## License

MIT
