# archon.social

> Decentralized names for humans and AIs, built on [Archon Protocol](https://archetech.com).

**archon.social** is a reference application demonstrating how to build a
decentralized naming service on top of Archon. Claim your `@name`, prove
ownership of your DID, and receive verifiable credentials — all without a
central authority.

This repo is a thin overlay on [Archon Herald](https://github.com/archetech/archon/tree/main/services/herald)
with custom branding, a directory-first landing page, and dedicated AI visitor
guidance (`/llms.txt`, `/agents.html`). When Herald ships new features, they
can be merged in via the process documented in [HERALD-SYNC.md](./HERALD-SYNC.md).

## Structure

```
archon-social/
├── client/          # React front-end (forked from apps/herald-client)
├── server/          # Express back-end (forked from services/herald/server)
├── HERALD-SYNC.md   # Upstream sync tracker
└── README.md        # this file
```

## For AI agents

See [`/llms.txt`](./client/public/llms.txt) for a concise guide, or
[`/agents.html`](./client/public/agents.html) for the full walkthrough.

TL;DR:

```bash
# 1. Get a challenge
CHALLENGE=$(curl -s https://archon.social/api/challenge | jq -r '.challenge')

# 2. Sign it with keymaster
RESPONSE=$(npx @didcid/keymaster create-response $CHALLENGE)

# 3. Claim your name
curl -s -X PUT https://archon.social/api/name \
  -H "Authorization: Bearer $RESPONSE" \
  -H "Content-Type: application/json" \
  -d '{"name":"your-agent-name"}' | jq .
```

## For humans

Visit [archon.social](https://archon.social), sign in with your Archon wallet,
and claim your `@name`.

Don't have a wallet yet? Install one:
- [Web wallet](https://wallet.archon.technology)
- [Chrome extension](https://archetech.com)
- Or run the CLI: `npx @didcid/keymaster`

## Development

```bash
# Install
cd client && npm install
cd ../server && npm install

# Run server (default port 4230)
cd server && npm run build && npm start

# Run client dev (default port 3001)
cd client && npm run dev
```

Configure via environment variables — see `server/sample.env` for the full
list. Required: `ARCHON_HERALD_SESSION_SECRET` and `ARCHON_GATEKEEPER_URL`.

## Deployment

archon.social runs as part of the public Archon node. The production
deployment sits behind Drawbridge at https://archon.social.

## License

MIT — same as Archon Herald and the rest of the Archon Protocol stack.

## Credits

- Built on [Archon Herald](https://github.com/archetech/archon/tree/main/services/herald)
  by David McFadzean (macterra) and the Archon team.
- archon.social wrapper and reference app by [Archetech](https://archetech.com).
