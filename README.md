# github-core-clone-01 — a standalone GitHub-compatible git forge

A single-process, dependency-free forge that implements the GitHub API surface
the `github-core-clone-01` bounty asks for: the git smart HTTP wire protocol
(upload-pack v0/v2, receive-pack, ls-refs, shallow/deepen), REST v3
(repositories, refs, branches, commits, contents, labels, issues, comments,
pull requests, squash merge), GraphQL v4 (viewer, repository, issue, pull
request, node, mutations, introspection, batch), and MCP (JSON-RPC 2.0,
`server/discover` era 2026-07-28 plus legacy `initialize`, six tools).

## Run

```sh
# Harness mode (used by the make.fun suite):
MAKEFUN_ENV_URL=http://127.0.0.1:8080 node --experimental-strip-types main.ts

# Standalone mode (local testing, no harness):
node --experimental-strip-types main.ts        # listens on 127.0.0.1:18080
FORGE_PORT=18080 node --experimental-strip-types main.ts
```

Requires Node 22+ (tested on Node 24). No dependencies, no git binary, no
outside service. The token is taken from `MAKEFUN_SHOP_TOKEN` when set; when
unset, any bearer token is accepted (local runs only).

## Layout

- `main.ts` — lifecycle only: binds an ephemeral port, POSTs `{"port": N}` to
  `$MAKEFUN_ENV_URL/register`, long-polls `GET $MAKEFUN_ENV_URL/done`, exits 0
  when the harness is done.
- `forge.ts` — the whole forge: scenario viewer derivation, SHA-1 object
  model (blobs, trees, commits, tags), pack writer/reader (plain + OFS/REF
  deltas), in-memory store, git smart HTTP, REST v3, GraphQL, MCP, router.
- `LICENSE` — MIT (SPDX identifier on the first line).
- `.makefun/owner.json` — the payout wallet for this entry.

## How it works

The forge is a single in-memory store. Every repository keeps a git object
database (SHA-1), refs, labels, issues, and pull requests. Commits are built
from flattened file maps, so REST contents writes, PR squashes, and git pushes
all converge on the same object graph. Timestamps come from a monotonic
counter seeded at 2025-01-01, never the wall clock, so replays are
deterministic.

Git: upload-pack answers protocol v2 (`version 2`, `ls-refs=unborn`,
`fetch=shallow`) when the client sends `Git-Protocol: version=2`, otherwise
v0 with the `# service=git-upload-pack` preamble; receive-pack is v0 with
`report-status` and sideband band-1 framing; ls-refs honours `ref-prefix`,
`peel`, `symrefs`, and `unborn`. Pushes enforce fast-forward per ref and
report `unpack ok` + per-ref `ok`/`ng … non-fast-forward`.

Identity: the viewer is derived from the public scenario seed in the kit
(`adaiversen`, id 1000), not from the token — the shop token is opaque, so the
forge re-derives the same viewer the scenario generator does.

REST v3 covers the full check surface (repos CRUD, `git/refs`, branches,
commits filtered by `sha`, contents create/update/delete with 409 on stale
sha, labels, issues with filters/sorts/pagination, comments, pull requests
with file diffs and squash merge with real conflict detection). GraphQL is a
small parser + executor for the documented queries/mutations with opaque
base64 global ids and cursor pagination. MCP exposes six tools
(`create_repo`, `get_repo`, `create_issue`, `list_issues`,
`create_pull_request`, `merge_pull_request`) with canonical argument names,
both `content` text and `structuredContent` results, and `isError` results for
missing arguments.

## Local verification

```sh
node --experimental-strip-types main.ts &
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:18080 --token anything
```

The SDK runner exercises all 120 conformance checks plus the four perf
workloads and prints a score breakdown.
