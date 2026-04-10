# Herald Upstream Sync Tracker

This repo is a **thin overlay on Archon Herald**. The client and server code
were forked from:

- `apps/herald-client/` — React front-end
- `services/herald/server/` — Express/Node back-end

in the archon monorepo: https://github.com/archetech/archon

## How to sync from upstream

1. Clone the latest archon monorepo (or pull into an existing clone).
2. For each modified file listed below, run a 3-way merge:
   - BASE: the Herald version at the last sync (see "Last Sync" below)
   - OURS: the current file in this repo
   - THEIRS: the latest Herald version
3. Run `client` and `server` locally to confirm nothing broke.
4. Update the "Last Sync" line and the file list below.

## Last Sync

- Date: 2026-04-10
- Herald source commit: initial fork from `archetech/archon@main`

## Files modified from Herald upstream

Track every file that diverges from Herald here. Files NOT listed should be
byte-identical to upstream and can be replaced wholesale during sync.

### Client

- `client/package.json` — renamed to `@archon-social/client`, version reset to 0.1.0
- `client/src/App.tsx` — rewrote the unauthenticated `Home()` view to be a
  directory-first landing page with hero, stats strip, community grid, and
  modern footer. Added `HomeDirectoryEntry` interface. Public directory fetch
  moved into `Home` (previously only in `ViewMembers`). Removed the
  `if (!auth)` early return so the landing page renders immediately. Hide the
  large `<Header>` on the unauthenticated landing page.
- `client/index.html` — archon.social title, description, OG tags, theme color,
  llms.txt discovery link.
- `client/public/manifest.json` — archon.social branding, theme color #7c5cff.
- `client/public/robots.txt` — added reference to /llms.txt convention.

### Server

- `server/package.json` — renamed to `@archon-social/server`, version reset to 0.1.0.
- Removed stale `server/.env.archon-social` (used old `NS_*` env vars).

### Added files (not in Herald)

- `HERALD-SYNC.md` — this file
- `README.md` — archon.social-specific readme
- `.gitignore` — repo-level ignore
- `client/public/llms.txt` — short AI visitor guide (Jeremy Howard llms.txt convention)
- `client/public/llms-full.txt` — full AI visitor guide with curl examples
- `client/public/agents.html` — human-readable agent onboarding page (standalone HTML)

## Files intentionally deleted from Herald upstream

_(none yet)_
