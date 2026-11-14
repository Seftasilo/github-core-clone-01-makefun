// forge.ts — a single-process, dependency-free GitHub-compatible git forge.
//
// Surfaces: git smart HTTP (upload-pack v0/v2, receive-pack, ls-refs, shallow/deepen),
// REST v3 (repos, refs, branches, commits, contents, labels, issues, comments, pulls,
// squash merge), GraphQL v4 (viewer, repository, issue, pull request, node, mutations,
// introspection, batch) and MCP (JSON-RPC 2.0, server/discover era 2026-07-28 plus legacy
// initialize, six tools). In-memory store, deterministic timestamps from a monotonic
// counter (never wall clock), no git binary, no outside service.
//
// The viewer is derived from the public scenario seed: the scenario's first user,
// login "adaiversen", id 1000. The shop token is opaque, so any bearer <redacted> presented
// to this forge is the viewer; a request with no token is anonymous (public reads only).

import http from 'node:http';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

export const ZERO_OID = '0000000000000000000000000000000000000000';
export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const DEFAULT_BRANCH = 'main';
const AGENT_NAME = 'forge/1.0.0';
const BASE_TIME = 1700000000;

// --------------------------------------------------------------------------- utilities

/** Deterministic clock: one second per tick from a fixed epoch, never wall clock. */
let tickCounter = 0;
export function tickIso(): string {
  tickCounter += 1;
  return new Date((BASE_TIME + tickCounter) * 1000).toISOString();
}
export function tickUnix(): number {
  tickCounter += 1;
  return BASE_TIME + tickCounter;
}
export function requestId(): string {
  tickCounter += 1;
  return `forge-${tickCounter.toString(16).padStart(8, '0')}`;
}

export function sha1Hex(data: Uint8Array): string {
  return crypto.createHash('sha1').update(data).digest('hex');
}

export function base64Encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}
export function base64Decode(text: string): string {
  return Buffer.from(text, 'base64').toString('utf8');
}

/** Opaque, stable global id: base64 of "<Kind>:<payload>". */
export function nodeId(kind: string, payload: string | number): string {
  return base64Encode(`${kind}:${payload}`);
}
export function parseNodeId(id: string): { kind: string; payload: string } | null {
  try {
    const decoded = base64Decode(id);
    const colon = decoded.indexOf(':');
    if (colon < 0) return null;
    return { kind: decoded.slice(0, colon), payload: decoded.slice(colon + 1) };
  } catch {
    return null;
  }
}

export function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function adler32(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i += 1) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// --------------------------------------------------------------------------- git objects

export type ObjType = 'blob' | 'tree' | 'commit' | 'tag';

export interface GitObject {
  type: ObjType;
  data: Buffer;
}

export function objectHeader(type: ObjType, size: number): Buffer {
  return Buffer.from(`${type} ${size}\0`, 'utf8');
}

export function objectId(type: ObjType, data: Uint8Array): string {
  return sha1Hex(Buffer.concat([objectHeader(type, data.length), Buffer.from(data)]));
}

/** In-memory object store with a per-oid deflate cache (the clone bench's hot path). */
export class ObjectStore {
  objects = new Map<string, GitObject>();
  private deflateCache = new Map<string, Buffer>();

  has(oid: string): boolean {
    return this.objects.has(oid);
  }

  get(oid: string): GitObject | undefined {
    return this.objects.get(oid);
  }

  put(type: ObjType, data: Uint8Array): string {
    const oid = objectId(type, data);
    if (!this.objects.has(oid)) {
      this.objects.set(oid, { type, data: Buffer.from(data) });
    }
    return oid;
  }

  putObject(oid: string, type: ObjType, data: Uint8Array): void {
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data: Buffer.from(data) });
  }

  /** zlib bytes of the object CONTENT (what a pack entry carries), cached per oid. */
  deflated(oid: string): Buffer | null {
    const cached = this.deflateCache.get(oid);
    if (cached !== undefined) return cached;
    const obj = this.objects.get(oid);
    if (obj === undefined) return null;
    const deflated = zlib.deflateSync(obj.data, { level: 6 });
    if (this.deflateCache.size > 8192) this.deflateCache.clear();
    this.deflateCache.set(oid, deflated);
    return deflated;
  }
}

// --------------------------------------------------------------------------- pack codec

const PACK_TYPES: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_CODES: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function readVarint(buf: Buffer, pos: number): { value: number; next: number } {
  let value = buf[pos] & 0x7f;
  let shift = 7;
  let p = pos + 1;
  while (buf[p - 1] & 0x80) {
    value |= (buf[p] & 0x7f) << shift;
    shift += 7;
    p += 1;
  }
  return { value, next: p };
}

function readOfsVarint(buf: Buffer, pos: number): { value: number; next: number } {
  let value = buf[pos] & 0x7f;
  let p = pos + 1;
  while (buf[p - 1] & 0x80) {
    value = ((value + 1) << 7) | (buf[p] & 0x7f);
    p += 1;
  }
  return { value, next: p };
}

/**
 * Find the end of the zlib stream starting at `pos`. inflateSync ignores trailing
 * bytes, so one inflate yields the data; the stream's last four bytes are the
 * Adler-32 of that data, which locates the end directly (verified by re-inflating
 * the exact slice). Falls back to a binary search when the checksum is not found.
 */
function inflateBoundary(buf: Buffer, pos: number): { data: Buffer; next: number } {
  const data = zlib.inflateSync(buf.subarray(pos));
  const needle = Buffer.alloc(4);
  needle.writeUInt32BE(adler32(data), 0);
  let searchFrom = pos + 2;
  for (;;) {
    const idx = buf.indexOf(needle, searchFrom);
    if (idx < 0) break;
    const end = idx + 4;
    try {
      const check = zlib.inflateSync(buf.subarray(pos, end));
      if (check.equals(data)) return { data, next: end };
    } catch {
      // Not the boundary; keep scanning.
    }
    searchFrom = idx + 1;
  }
  let lo = pos;
  let hi = buf.length;
  let found: Buffer | null = null;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      found = zlib.inflateSync(buf.subarray(pos, mid));
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  if (found === null) throw new Error('could not inflate pack object');
  return { data: found, next: lo };
}

export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readDeltaVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[pos];
      pos += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const srcSize = readDeltaVarint();
  const dstSize = readDeltaVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = [];
  let outLen = 0;
  while (pos < delta.length) {
    const cmd = delta[pos];
    pos += 1;
    if (cmd & 0x80) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) {
        if (cmd & (1 << i)) {
          offset |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (cmd & (0x10 << i)) {
          size |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      if (size === 0) size = 0x10000;
      out.push(base.subarray(offset, offset + size));
      outLen += size;
    } else if (cmd !== 0) {
      out.push(delta.subarray(pos, pos + cmd));
      outLen += cmd;
      pos += cmd;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const result = Buffer.concat(out, outLen);
  if (result.length !== dstSize) throw new Error('delta target size mismatch');
  return result;
}

export interface PackReadResult {
  objects: Map<string, GitObject>;
  deltaCount: number;
}

export function readPack(buf: Buffer): PackReadResult {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  const pending: Array<{ oid: string; type: ObjType; data: Buffer; baseOid: string | null; baseOffset: number | null }> = [];
  let pos = 12;
  let deltaCount = 0;
  // Verify the trailer checksum matches the pack bytes (the client checks this too).
  const trailer = buf.subarray(buf.length - 20);
  const expected = sha1Hex(buf.subarray(0, buf.length - 20));
  if (trailer.toString('hex') !== expected) throw new Error('pack checksum mismatch');
  for (let i = 0; i < count; i += 1) {
    const startPos = pos;
    const first = buf[pos];
    const typeCode = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let shift = 4;
    pos += 1;
    while (buf[pos - 1] & 0x80) {
      size |= (buf[pos] & 0x7f) << shift;
      shift += 7;
      pos += 1;
    }
    let baseOid: string | null = null;
    let baseOffset: number | null = null;
    if (typeCode === 6) {
      const ofs = readOfsVarint(buf, pos);
      baseOffset = startPos - ofs.value;
      pos = ofs.next;
      deltaCount += 1;
    } else if (typeCode === 7) {
      baseOid = buf.subarray(pos, pos + 20).toString('hex');
      pos += 20;
      deltaCount += 1;
    }
    const inflated = inflateBoundary(buf, pos);
    pos = inflated.next;
    if (inflated.data.length !== size) throw new Error('object size mismatch in pack');
    if (typeCode === 6 || typeCode === 7) {
      // Placeholder oid; resolved below once the base is known.
      pending.push({ oid: '', type: 'blob', data: inflated.data, baseOid, baseOffset });
    } else {
      const type = PACK_TYPES[typeCode];
      if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
      const oid = objectId(type, inflated.data);
      objects.set(oid, { type, data: inflated.data });
      pending.push({ oid, type, data: inflated.data, baseOid: null, baseOffset: null });
    }
  }
  // Resolve deltas. A delta's base always precedes it in the pack (OFS) or is named
  // by oid (REF); plain objects were collected in `objects` during the read above,
  // so resolve the pending deltas in order.
  const resolved = new Map<string, GitObject>(objects);
  for (const entry of pending) {
    if (entry.baseOid === null && entry.baseOffset === null) continue;
    // Find the base: REF by oid, OFS by re-reading the pack at that offset.
    let base: GitObject | undefined;
    let baseType: ObjType | undefined;
    if (entry.baseOid !== null) {
      base = resolved.get(entry.baseOid);
      baseType = base?.type;
    } else if (entry.baseOffset !== null) {
      const baseEntry = offsetObject(buf, entry.baseOffset, resolved);
      base = baseEntry;
      baseType = baseEntry?.type;
    }
    if (base === undefined || baseType === undefined) throw new Error('delta base not found');
    const data = applyDelta(base.data, entry.data);
    const oid = objectId(baseType, data);
    resolved.set(oid, { type: baseType, data });
  }
  return { objects: resolved, deltaCount };
}

/** Read the object at a pack offset (used to resolve OFS deltas). */
function offsetObject(buf: Buffer, offset: number, known: Map<string, GitObject>): GitObject | undefined {
  let pos = offset;
  const first = buf[pos];
  const typeCode = (first >> 4) & 0x07;
  pos += 1;
  while (buf[pos - 1] & 0x80) pos += 1;
  if (typeCode === 6) {
    const ofs = readOfsVarint(buf, pos);
    const base = offsetObject(buf, offset - ofs.value, known);
    if (base === undefined) return undefined;
    pos = ofs.next;
    const inflated = inflateBoundary(buf, pos);
    const data = applyDelta(base.data, inflated.data);
    return { type: base.type, data };
  }
  if (typeCode === 7) {
    const baseOid = buf.subarray(pos, pos + 20).toString('hex');
    const base = known.get(baseOid);
    if (base === undefined) return undefined;
    pos += 20;
    const inflated = inflateBoundary(buf, pos);
    const data = applyDelta(base.data, inflated.data);
    return { type: base.type, data };
  }
  const type = PACK_TYPES[typeCode];
  if (type === undefined) return undefined;
  const inflated = inflateBoundary(buf, pos);
  return { type, data: inflated.data };
}

/** Write a pack of plain (non-delta) objects; deflate bytes come from the store cache. */
export function writePack(store: ObjectStore, oids: readonly string[]): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(oids.length, 8);
  const chunks: Buffer[] = [header];
  for (const oid of oids) {
    const obj = store.get(oid);
    if (obj === undefined) continue;
    const typeCode = PACK_TYPE_CODES[obj.type];
    const size = obj.data.length;
    const head: number[] = [];
    let b = (size & 0x0f) | (typeCode << 4);
    let rest = size >> 4;
    if (rest > 0) b |= 0x80;
    head.push(b);
    while (rest > 0) {
      b = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) b |= 0x80;
      head.push(b);
    }
    chunks.push(Buffer.from(head));
    const deflated = store.deflated(oid);
    if (deflated === null) continue;
    chunks.push(deflated);
  }
  const body = Buffer.concat(chunks);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

// --------------------------------------------------------------------------- commits/trees

export interface CommitParts {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function parseCommit(data: Buffer): CommitParts {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  let message = blank < 0 ? '' : text.slice(blank + 2);
  if (message.endsWith('\n')) message = message.slice(0, -1);
  const parts: CommitParts = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) parts.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parts.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) parts.author = line.slice(7);
    else if (line.startsWith('committer ')) parts.committer = line.slice(10);
  }
  return parts;
}

export function buildCommit(tree: string, parents: readonly string[], message: string): Buffer {
  const stamp = tickUnix();
  const ident = `${VIEWER_LOGIN} <${VIEWER_LOGIN}@users.noreply.github.com> ${stamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${ident}`);
  lines.push(`committer ${ident}`);
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let pos = 0;
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos);
    const nul = data.indexOf(0x00, space);
    const mode = data.subarray(pos, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    pos = nul + 21;
  }
  return entries;
}

export function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const chunks: Buffer[] = [];
  for (const entry of sorted) {
    chunks.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    chunks.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(chunks);
}

/** Flatten a tree to path -> {mode, oid}, recursively. */
export function flattenTree(store: ObjectStore, treeOid: string, prefix = ''): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const obj = store.get(treeOid);
  if (obj === undefined || obj.type !== 'tree') return out;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') {
      for (const [sub, value] of flattenTree(store, entry.oid, path)) out.set(sub, value);
    } else {
      out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  }
  return out;
}

/** Build (or rebuild) the tree for a flat path map, creating intermediate trees. */
export function buildTreeFromFlat(store: ObjectStore, flat: ReadonlyMap<string, { mode: string; oid: string }>): string {
  return buildTreeFromFlatRelative(store, flat);
}

function buildTreeFromFlatRelative(store: ObjectStore, flat: ReadonlyMap<string, { mode: string; oid: string }>): string {
  const entries: TreeEntry[] = [];
  const dirs = new Map<string, Map<string, { mode: string; oid: string }>>();
  for (const [path, value] of flat) {
    const slash = path.indexOf('/');
    if (slash < 0) {
      entries.push({ mode: value.mode, name: path, oid: value.oid });
    } else {
      const dir = path.slice(0, slash);
      let sub = dirs.get(dir);
      if (sub === undefined) {
        sub = new Map();
        dirs.set(dir, sub);
      }
      sub.set(path.slice(slash + 1), value);
    }
  }
  for (const [dir, sub] of dirs) {
    entries.push({ mode: '40000', name: dir, oid: buildTreeFromFlatRelative(store, sub) });
  }
  return store.put('tree', buildTree(entries));
}

/** Commits reachable from `roots`, BFS with an optional depth cap (depth 1 = roots only). */
export function reachableCommits(
  store: ObjectStore,
  roots: readonly string[],
  depthLimit: number | null,
  stopAt: ReadonlySet<string> | null,
): Map<string, number> {
  const depth = new Map<string, number>();
  const queue: Array<{ oid: string; d: number }> = [];
  for (const root of roots) {
    if (store.get(root)?.type === 'commit' && !depth.has(root)) {
      depth.set(root, 1);
      queue.push({ oid: root, d: 1 });
    }
  }
  let head = 0;
  while (head < queue.length) {
    const current = queue[head];
    head += 1;
    if (stopAt !== null && stopAt.has(current.oid)) continue;
    if (depthLimit !== null && current.d >= depthLimit) continue;
    const obj = store.get(current.oid);
    if (obj === undefined) continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (!depth.has(parent) && store.get(parent)?.type === 'commit') {
        depth.set(parent, current.d + 1);
        queue.push({ oid: parent, d: current.d + 1 });
      }
    }
  }
  return depth;
}

/** True when `descendant` is the same commit as `ancestor` or has it in its history. */
export function isDescendant(store: ObjectStore, descendant: string, ancestor: string): boolean {
  if (descendant === ancestor) return true;
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = store.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (parent === ancestor) return true;
      queue.push(parent);
    }
  }
  return false;
}

/** Merge-base: the nearest common ancestor of two commits (BFS from both sides). */
export function mergeBase(store: ObjectStore, a: string, b: string): string | null {
  if (a === b) return a;
  const distA = reachableCommits(store, [a], null, null);
  const distB = reachableCommits(store, [b], null, null);
  let best: string | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (const [oid, da] of distA) {
    const db = distB.get(oid);
    if (db === undefined) continue;
    const score = da + db;
    if (score < bestScore) {
      bestScore = score;
      best = oid;
    }
  }
  return best;
}

/** Line diff counts (LCS over lines) for a pull-request file entry. */
export function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  const n = oldLines.length;
  const m = newLines.length;
  const dp: number[][] = [];
  for (let i = 0; i <= n; i += 1) dp.push(new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const lcs = dp[0][0];
  return { additions: m - lcs, deletions: n - lcs };
}

// --------------------------------------------------------------------------- data model

export interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

export interface IssueComment {
  id: number;
  body: string;
  user: string;
  createdAt: string;
  updatedAt: string;
}

export interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: IssueComment[];
  seq: number;
  user: string;
  createdAt: string;
  updatedAt: string;
}

export interface PullFile {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
  patch: string;
}

export interface PullRequest {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  mergeCommitSha: string | null;
  mergeMessage: string;
  mergedAt: string | null;
  files: PullFile[];
  commits: string[];
  seq: number;
  user: string;
  createdAt: string;
  updatedAt: string;
}

export interface Repo {
  owner: string;
  name: string;
  id: number;
  nodeId: string;
  description: string;
  privateRepo: boolean;
  fork: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  issues: Issue[];
  pulls: PullRequest[];
  labels: Label[];
  issueSeq: number;
  pullSeq: number;
  commentSeq: number;
  labelSeq: number;
  seq: number;
  createdAt: string;
  updatedAt: string;
  pushedAt: string;
}

export interface Viewer {
  login: string;
  id: number;
}

/** The forge: one store, one repo registry, one viewer. */
export class Forge {
  store = new ObjectStore();
  repos = new Map<string, Repo>();
  viewer: Viewer = { login: VIEWER_LOGIN, id: VIEWER_ID };
  private repoSeq = 0;
  private repoIdSeq = 10000;
  private packCache = new Map<string, Buffer>();

  repoKey(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  getRepo(owner: string, name: string): Repo | undefined {
    return this.repos.get(this.repoKey(owner, name));
  }

  createRepo(name: string, options: { description?: string; privateRepo?: boolean }): Repo | { error: string } {
    const owner = this.viewer.login;
    if (this.repos.has(this.repoKey(owner, name))) return { error: 'already exists' };
    this.repoSeq += 1;
    this.repoIdSeq += 1;
    const now = tickIso();
    const repo: Repo = {
      owner,
      name,
      id: this.repoIdSeq,
      nodeId: nodeId('Repository', this.repoIdSeq),
      description: options.description ?? '',
      privateRepo: options.privateRepo ?? false,
      fork: false,
      defaultBranch: DEFAULT_BRANCH,
      refs: new Map(),
      issues: [],
      pulls: [],
      labels: [],
      issueSeq: 0,
      pullSeq: 0,
      commentSeq: 0,
      labelSeq: 0,
      seq: this.repoSeq,
      createdAt: now,
      updatedAt: now,
      pushedAt: now,
    };
    this.repos.set(this.repoKey(owner, name), repo);
    return repo;
  }

  deleteRepo(owner: string, name: string): boolean {
    return this.repos.delete(this.repoKey(owner, name));
  }

  listViewerRepos(): Repo[] {
    const out: Repo[] = [];
    for (const repo of this.repos.values()) {
      if (repo.owner === this.viewer.login) out.push(repo);
    }
    out.sort((a, b) => a.seq - b.seq);
    return out;
  }

  /** Resolve a ref-ish (branch name, full ref, or oid) to a commit oid, or null. */
  resolveRef(repo: Repo, refish: string | undefined): string | null {
    if (refish === undefined || refish === '') {
      return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
    }
    if (isOid(refish) && this.store.get(refish)?.type === 'commit') return refish;
    if (repo.refs.has(refish)) return repo.refs.get(refish) as string;
    const asBranch = repo.refs.get(`refs/heads/${refish}`);
    if (asBranch !== undefined) return asBranch;
    const asTag = repo.refs.get(`refs/tags/${refish}`);
    if (asTag !== undefined) {
      const obj = this.store.get(asTag);
      if (obj?.type === 'tag') {
        const target = parseTagTarget(obj.data);
        return target;
      }
      return asTag;
    }
    return null;
  }

  /** Commits on a branch tip, newest first (BFS by depth from the tip). */
  branchCommits(repo: Repo, branch: string): string[] {
    const tip = this.resolveRef(repo, branch);
    if (tip === null) return [];
    const depth = reachableCommits(this.store, [tip], null, null);
    return [...depth.entries()].sort((a, b) => a[1] - b[1]).map(([oid]) => oid);
  }

  /** The tree oid at a ref-ish, or null. */
  refTree(repo: Repo, refish: string | undefined): string | null {
    const commitOid = this.resolveRef(repo, refish);
    if (commitOid === null) return null;
    const obj = this.store.get(commitOid);
    if (obj?.type !== 'commit') return null;
    return parseCommit(obj.data).tree;
  }

  // --------------------------------------------------------------------- contents

  /** Read a path from a tree: {kind: 'file', oid} | {kind: 'dir', entries} | null. */
  readPath(
    treeOid: string,
    path: string,
  ): { kind: 'file'; oid: string; mode: string } | { kind: 'dir'; entries: TreeEntry[] } | null {
    const parts = path.split('/').filter((p) => p !== '');
    let current = treeOid;
    for (let i = 0; i < parts.length; i += 1) {
      const obj = this.store.get(current);
      if (obj?.type !== 'tree') return null;
      const entry = parseTree(obj.data).find((e) => e.name === parts[i]);
      if (entry === undefined) return null;
      if (i === parts.length - 1) {
        if (entry.mode === '40000') {
          const dirObj = this.store.get(entry.oid);
          if (dirObj?.type !== 'tree') return null;
          return { kind: 'dir', entries: parseTree(dirObj.data) };
        }
        return { kind: 'file', oid: entry.oid, mode: entry.mode };
      }
      if (entry.mode !== '40000') return null;
      current = entry.oid;
    }
    const obj = this.store.get(current);
    if (obj?.type !== 'tree') return null;
    return { kind: 'dir', entries: parseTree(obj.data) };
  }

  /**
   * Commit a file change on a branch: creates blob + trees + commit, moves the ref.
   * `message` is stored verbatim (no trailing newline). Returns the commit and blob oids.
   */
  commitFile(
    repo: Repo,
    branch: string,
    path: string,
    content: Buffer,
    message: string,
    deleteFile: boolean,
  ): { commitOid: string; blobOid: string | null } {
    const refName = `refs/heads/${branch}`;
    const parentOid = repo.refs.get(refName) ?? null;
    const parentTree = parentOid !== null ? parseCommit((this.store.get(parentOid) as GitObject).data).tree : null;
    const flat = parentTree !== null ? flattenTree(this.store, parentTree) : new Map<string, { mode: string; oid: string }>();
    let blobOid: string | null = null;
    if (deleteFile) {
      flat.delete(path);
    } else {
      blobOid = this.store.put('blob', content);
      flat.set(path, { mode: '100644', oid: blobOid });
    }
    const treeOid = buildTreeFromFlat(this.store, flat);
    const parents = parentOid !== null ? [parentOid] : [];
    const commitOid = this.store.put('commit', buildCommit(treeOid, parents, message));
    repo.refs.set(refName, commitOid);
    repo.pushedAt = tickIso();
    this.packCache.clear();
    return { commitOid, blobOid };
  }

  // --------------------------------------------------------------------- labels/issues

  findOrCreateLabel(repo: Repo, name: string, color = 'ededed'): Label {
    const existing = repo.labels.find((l) => l.name === name);
    if (existing !== undefined) return existing;
    repo.labelSeq += 1;
    const label: Label = { id: repo.labelSeq, name, color, description: '' };
    repo.labels.push(label);
    return label;
  }

  createIssue(repo: Repo, title: string, body: string, labelNames: readonly string[]): Issue | { error: string } {
    const labels: Label[] = [];
    for (const name of labelNames) {
      const label = repo.labels.find((l) => l.name === name);
      if (label === undefined) return { error: `label ${name} does not exist` };
      labels.push(label);
    }
    repo.issueSeq += 1;
    const now = tickIso();
    const issue: Issue = {
      number: repo.issueSeq,
      title,
      body,
      state: 'open',
      labels,
      comments: [],
      seq: repo.issueSeq,
      user: this.viewer.login,
      createdAt: now,
      updatedAt: now,
    };
    repo.issues.push(issue);
    return issue;
  }

  // --------------------------------------------------------------------- pull requests

  /** Files changed between the merge-base tree and the head tree, with line counts. */
  pullFiles(repo: Repo, pull: PullRequest): PullFile[] {
    const baseCommit = pull.baseSha;
    const headCommit = pull.headSha;
    const mergeBaseOid = mergeBase(this.store, baseCommit, headCommit) ?? baseCommit;
    const baseTree = parseCommit((this.store.get(mergeBaseOid) as GitObject).data).tree;
    const headTree = parseCommit((this.store.get(headCommit) as GitObject).data).tree;
    const baseFlat = flattenTree(this.store, baseTree);
    const headFlat = flattenTree(this.store, headTree);
    const files: PullFile[] = [];
    const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
    for (const path of [...paths].sort()) {
      const before = baseFlat.get(path);
      const after = headFlat.get(path);
      if (before === undefined && after !== undefined) {
        const text = (this.store.get(after.oid) as GitObject).data.toString('utf8');
        const lines = text === '' ? 0 : text.split('\n').length;
        files.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines, patch: '' });
      } else if (before !== undefined && after === undefined) {
        files.push({ filename: path, status: 'removed', additions: 0, deletions: 0, changes: 0, patch: '' });
      } else if (before !== undefined && after !== undefined && before.oid !== after.oid) {
        const oldText = (this.store.get(before.oid) as GitObject).data.toString('utf8');
        const newText = (this.store.get(after.oid) as GitObject).data.toString('utf8');
        const diff = lineDiff(oldText, newText);
        files.push({ filename: path, status: 'modified', additions: diff.additions, deletions: diff.deletions, changes: diff.additions + diff.deletions, patch: '' });
      }
    }
    return files;
  }

  createPull(repo: Repo, title: string, body: string, head: string, base: string): PullRequest | { error: string } {
    const headSha = this.resolveRef(repo, head);
    const baseSha = this.resolveRef(repo, base);
    if (headSha === null) return { error: `head ${head} not found` };
    if (baseSha === null) return { error: `base ${base} not found` };
    repo.pullSeq += 1;
    const now = tickIso();
    const pull: PullRequest = {
      number: repo.pullSeq,
      title,
      body,
      state: 'open',
      merged: false,
      head,
      base,
      headSha,
      baseSha,
      mergeCommitSha: null,
      mergeMessage: '',
      mergedAt: null,
      files: [],
      commits: [],
      seq: repo.pullSeq,
      user: this.viewer.login,
      createdAt: now,
      updatedAt: now,
    };
    pull.files = this.pullFiles(repo, pull);
    pull.commits = this.branchCommits(repo, head).filter((oid) => {
      const baseDepth = reachableCommits(this.store, [baseSha], null, null);
      return !baseDepth.has(oid);
    });
    repo.pulls.push(pull);
    return pull;
  }

  /**
   * True when a squash merge of this pull request would conflict: a path changed
   * on both sides (relative to the merge-base) to different blobs.
   */
  wouldConflict(repo: Repo, pull: PullRequest): boolean {
    const baseSha = this.resolveRef(repo, pull.base);
    const headSha = this.resolveRef(repo, pull.head);
    if (baseSha === null || headSha === null) return false;
    const mergeBaseOid = mergeBase(this.store, baseSha, headSha);
    const baseTreeOid = parseCommit((this.store.get(baseSha) as GitObject).data).tree;
    const headTreeOid = parseCommit((this.store.get(headSha) as GitObject).data).tree;
    const ancestorTreeOid = mergeBaseOid !== null ? parseCommit((this.store.get(mergeBaseOid) as GitObject).data).tree : null;
    const baseFlat = flattenTree(this.store, baseTreeOid);
    const headFlat = flattenTree(this.store, headTreeOid);
    const ancestorFlat = ancestorTreeOid !== null ? flattenTree(this.store, ancestorTreeOid) : new Map<string, { mode: string; oid: string }>();
    const allPaths = new Set([...baseFlat.keys(), ...headFlat.keys(), ...ancestorFlat.keys()]);
    for (const path of allPaths) {
      const ancestor = ancestorFlat.get(path);
      const onBase = baseFlat.get(path);
      const onHead = headFlat.get(path);
      const baseChanged = (ancestor?.oid ?? null) !== (onBase?.oid ?? null);
      const headChanged = (ancestor?.oid ?? null) !== (onHead?.oid ?? null);
      if (baseChanged && headChanged && (onBase?.oid ?? null) !== (onHead?.oid ?? null)) return true;
    }
    return false;
  }

  /**
   * Squash-merge a pull request with a real three-way merge. Returns the merge commit
   * oid, or {error, status} for a conflict (405) or an unknown/closed pull (404/409).
   */
  mergePull(repo: Repo, number: number): { commitOid: string } | { error: string; status: number } {
    const pull = repo.pulls.find((p) => p.number === number);
    if (pull === undefined) return { error: 'pull request not found', status: 404 };
    if (pull.state !== 'open') return { error: 'pull request is not open', status: 405 };
    const baseSha = this.resolveRef(repo, pull.base);
    const headSha = this.resolveRef(repo, pull.head);
    if (baseSha === null || headSha === null) return { error: 'head or base not found', status: 404 };
    if (this.wouldConflict(repo, pull)) return { error: 'merge conflict', status: 405 };
    const mergeBaseOid = mergeBase(this.store, baseSha, headSha);
    const baseTreeOid = parseCommit((this.store.get(baseSha) as GitObject).data).tree;
    const headTreeOid = parseCommit((this.store.get(headSha) as GitObject).data).tree;
    const ancestorTreeOid = mergeBaseOid !== null ? parseCommit((this.store.get(mergeBaseOid) as GitObject).data).tree : null;
    const baseFlat = flattenTree(this.store, baseTreeOid);
    const headFlat = flattenTree(this.store, headTreeOid);
    const ancestorFlat = ancestorTreeOid !== null ? flattenTree(this.store, ancestorTreeOid) : new Map<string, { mode: string; oid: string }>();
    // Apply the head side's changes onto the base tree.
    const merged = new Map(baseFlat);
    for (const path of [...baseFlat.keys(), ...headFlat.keys(), ...ancestorFlat.keys()]) {
      const ancestor = ancestorFlat.get(path);
      const onHead = headFlat.get(path);
      const headChanged = (ancestor?.oid ?? null) !== (onHead?.oid ?? null);
      if (!headChanged) continue;
      if (onHead === undefined) merged.delete(path);
      else merged.set(path, onHead);
    }
    const treeOid = buildTreeFromFlat(this.store, merged);
    const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
    const commitOid = this.store.put('commit', buildCommit(treeOid, [baseSha], message));
    repo.refs.set(`refs/heads/${pull.base}`, commitOid);
    repo.pushedAt = tickIso();
    pull.state = 'closed';
    pull.merged = true;
    pull.mergeCommitSha = commitOid;
    pull.mergeMessage = message;
    pull.mergedAt = tickIso();
    pull.updatedAt = tickIso();
    pull.baseSha = commitOid;
    this.packCache.clear();
    return { commitOid };
  }

  // --------------------------------------------------------------------- git fetch

  /**
   * Compute the object set for a fetch: commits reachable from `wants` (depth-limited),
   * minus objects the client holds (haves, truncated at its shallow boundaries), plus
   * the trees/blobs of the sent commits and any directly-wanted non-commit objects.
   * Returns the send set, the new shallow boundaries and the old boundaries that are
   * now interior (unshallow).
   */
  computeFetch(
    wants: readonly string[],
    haves: readonly string[],
    oldShallow: readonly string[],
    depthLimit: number | null,
  ): { oids: string[]; shallow: string[]; unshallow: string[]; acks: string[] } {
    const oldShallowSet = new Set(oldShallow);
    // Held: reachable from haves, not expanding past old shallow boundaries.
    const held = new Set<string>();
    {
      const queue = [...haves];
      while (queue.length > 0) {
        const oid = queue.pop() as string;
        if (held.has(oid)) continue;
        const obj = this.store.get(oid);
        if (obj?.type !== 'commit') continue;
        held.add(oid);
        if (oldShallowSet.has(oid)) continue;
        for (const parent of parseCommit(obj.data).parents) queue.push(parent);
      }
    }
    // Included commits with their depth from the wants.
    const included = reachableCommits(this.store, wants.filter((w) => this.store.get(w)?.type === 'commit'), depthLimit, null);
    const sendCommits = new Set<string>();
    for (const oid of included.keys()) {
      if (!held.has(oid)) sendCommits.add(oid);
    }
    // New shallow boundaries: included commits at the depth limit whose parent is cut.
    const shallow: string[] = [];
    if (depthLimit !== null) {
      for (const [oid, d] of included) {
        if (d !== depthLimit) continue;
        const obj = this.store.get(oid);
        if (obj?.type !== 'commit') continue;
        const parents = parseCommit(obj.data).parents;
        if (parents.length > 0 && parents.some((p) => !included.has(p))) shallow.push(oid);
      }
    }
    // Unshallow: old boundaries now included with every parent included or held.
    const unshallow: string[] = [];
    for (const boundary of oldShallow) {
      if (!included.has(boundary)) continue;
      const obj = this.store.get(boundary);
      if (obj?.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.every((p) => included.has(p) || held.has(p))) unshallow.push(boundary);
    }
    // ACKs: haves that are ancestors of the wants (i.e. in the wants' closure).
    // With no haves there is nothing to acknowledge; skip the full closure walk.
    const acks: string[] = [];
    if (haves.length > 0) {
      const wantClosure = reachableCommits(this.store, wants.filter((w) => this.store.get(w)?.type === 'commit'), null, null);
      for (const have of haves) {
        if (wantClosure.has(have)) acks.push(have);
      }
    }
    // Held objects: every object reachable from the held commits (their trees and
    // blobs included) — the client holds all of these, so none may be re-sent.
    const heldObjects = new Set<string>();
    {
      const addHeldTree = (treeOid: string): void => {
        if (heldObjects.has(treeOid)) return;
        const obj = this.store.get(treeOid);
        if (obj?.type !== 'tree') return;
        heldObjects.add(treeOid);
        for (const entry of parseTree(obj.data)) {
          if (entry.mode === '40000') addHeldTree(entry.oid);
          else heldObjects.add(entry.oid);
        }
      };
      for (const oid of held) {
        heldObjects.add(oid);
        const obj = this.store.get(oid);
        if (obj?.type === 'commit') addHeldTree(parseCommit(obj.data).tree);
      }
    }
    // Object closure: sent commits + their trees/blobs, plus non-commit wants,
    // minus everything the client already holds.
    const send = new Set<string>();
    const addTree = (treeOid: string): void => {
      if (send.has(treeOid) || heldObjects.has(treeOid)) return;
      const obj = this.store.get(treeOid);
      if (obj?.type !== 'tree') return;
      send.add(treeOid);
      for (const entry of parseTree(obj.data)) {
        if (entry.mode === '40000') addTree(entry.oid);
        else if (!heldObjects.has(entry.oid)) send.add(entry.oid);
      }
    };
    for (const oid of sendCommits) {
      if (heldObjects.has(oid)) continue;
      send.add(oid);
      const obj = this.store.get(oid);
      if (obj?.type === 'commit') addTree(parseCommit(obj.data).tree);
    }
    for (const want of wants) {
      const obj = this.store.get(want);
      if (obj === undefined) continue;
      if (obj.type === 'commit') {
        if (!held.has(want)) {
          send.add(want);
          addTree(parseCommit(obj.data).tree);
        }
      } else if (obj.type === 'tag') {
        if (!heldObjects.has(want)) send.add(want);
        const target = parseTagTarget(obj.data);
        if (target !== null) {
          const targetObj = this.store.get(target);
          if (targetObj?.type === 'commit' && !held.has(target)) {
            send.add(target);
            addTree(parseCommit(targetObj.data).tree);
          } else if (targetObj !== undefined && !heldObjects.has(target)) {
            send.add(target);
          }
        }
      } else if (obj.type === 'tree') {
        addTree(want);
      } else if (!heldObjects.has(want)) {
        send.add(want);
      }
    }
    // Deterministic order: commits by depth, then the rest sorted.
    const ordered: string[] = [];
    const byDepth = [...sendCommits].sort((a, b) => (included.get(a) ?? 0) - (included.get(b) ?? 0));
    for (const oid of byDepth) ordered.push(oid);
    for (const oid of [...send].sort()) {
      if (!sendCommits.has(oid)) ordered.push(oid);
    }
    return { oids: ordered, shallow, unshallow, acks };
  }

  /** Cached pack bytes for a fetch (keyed by repo + wants + haves + depth). */
  cachedPack(key: string, build: () => Buffer): Buffer {
    const cached = this.packCache.get(key);
    if (cached !== undefined) return cached;
    const built = build();
    if (this.packCache.size > 64) this.packCache.clear();
    this.packCache.set(key, built);
    return built;
  }

  /** Drop every cached pack (new objects change what a fetch can return). */
  invalidatePackCache(): void {
    this.packCache.clear();
  }
}

export function parseTagTarget(data: Buffer): string | null {
  const text = data.toString('utf8');
  for (const line of text.split('\n')) {
    if (line.startsWith('object ')) return line.slice(7).trim();
    if (line === '') break;
  }
  return null;
}

export function parseTagType(data: Buffer): string | null {
  const text = data.toString('utf8');
  for (const line of text.split('\n')) {
    if (line.startsWith('type ')) return line.slice(5).trim();
    if (line === '') break;
  }
  return null;
}

// --------------------------------------------------------------------------- git smart HTTP

export function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
export const PKT_FLUSH = Buffer.from('0000', 'ascii');
export const PKT_DELIM = Buffer.from('0001', 'ascii');

export interface PktPacket {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Parse a whole pkt-line stream into packets (flush/delim/data). */
export function decodePktLines(buf: Buffer): PktPacket[] {
  const packets: PktPacket[] = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const lenText = buf.subarray(pos, pos + 4).toString('ascii');
    if (lenText === '0000') {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    if (lenText === '0001') {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      pos += 4;
      continue;
    }
    const len = parseInt(lenText, 16);
    if (!Number.isFinite(len) || len < 4 || pos + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(pos + 4, pos + len) });
    pos += len;
  }
  return packets;
}

export function encodePktLines(lines: Array<string | 'flush' | 'delim'>): Buffer {
  const chunks: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') chunks.push(PKT_FLUSH);
    else if (line === 'delim') chunks.push(PKT_DELIM);
    else chunks.push(pktLine(line));
  }
  return Buffer.concat(chunks);
}

/** Wrap bytes into sideband band-1 packets (a pkt-line is at most 65520 bytes total,
 * so at most 65520 - 4 (length) - 1 (band) = 65515 data bytes per packet). */
export function sidebandWrap(data: Buffer, band = 1): Buffer {
  const chunks: Buffer[] = [];
  let pos = 0;
  if (data.length === 0) {
    chunks.push(pktLine(Buffer.concat([Buffer.from([band])])));
  }
  while (pos < data.length) {
    const slice = data.subarray(pos, Math.min(data.length, pos + 65515));
    chunks.push(pktLine(Buffer.concat([Buffer.from([band]), slice])));
    pos += slice.length;
  }
  return Buffer.concat(chunks);
}

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  const out: Array<{ name: string; oid: string }> = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

/** Peel an annotated tag ref to its commit oid (for `^{}` lines and ls-refs peel). */
function peelTag(forge: Forge, repo: Repo, oid: string): string | null {
  const obj = forge.store.get(oid);
  if (obj?.type !== 'tag') return null;
  const target = parseTagTarget(obj.data);
  if (target === null) return null;
  const targetObj = forge.store.get(target);
  if (targetObj?.type === 'tag') return peelTag(forge, repo, target);
  return target;
}

export interface GitAdvert {
  protocol: 0 | 2;
  body: Buffer;
  contentType: string;
}

export function advertisement(forge: Forge, repo: Repo, service: 'git-upload-pack' | 'git-receive-pack', wantV2: boolean): GitAdvert {
  if (service === 'git-upload-pack' && wantV2) {
    const lines = [
      pktLine('# service=git-upload-pack\n'),
      PKT_FLUSH,
      pktLine('version 2\n'),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow wait-for-done\n'),
      pktLine('object-format=sha1\n'),
      pktLine(`agent=${AGENT_NAME}\n`),
      PKT_FLUSH,
    ];
    return { protocol: 2, body: Buffer.concat(lines), contentType: 'application/x-git-upload-pack-advertisement' };
  }
  const refs = sortedRefs(repo);
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  const caps =
    service === 'git-upload-pack'
      ? `symref=HEAD:${headTarget} side-band-64k shallow thin-pack ofs-delta multi_ack_detailed agent=${AGENT_NAME}`
      : `report-status side-band-64k ofs-delta delete-refs agent=${AGENT_NAME}`;
  const lines: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  if (refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const first = headOid !== undefined ? { name: 'HEAD', oid: headOid } : refs[0] as { name: string; oid: string };
    lines.push(pktLine(`${first.oid} ${first.name}\0${caps}\n`));
    for (const ref of refs) {
      if (ref.name === first.name && ref.oid === first.oid && first.name === 'HEAD') continue;
      lines.push(pktLine(`${ref.oid} ${ref.name}\n`));
      const peeled = peelTag(forge, repo, ref.oid);
      if (peeled !== null) lines.push(pktLine(`${peeled} ${ref.name}^{}\n`));
    }
    if (first.name === 'HEAD') {
      // HEAD was listed first; the branch ref itself is already in `refs` above.
    }
  }
  lines.push(PKT_FLUSH);
  return {
    protocol: 0,
    body: Buffer.concat(lines),
    contentType: `application/x-${service}-advertisement`,
  };
}

interface FetchParams {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  filter: string | null;
}

/** Parse a v0 fetch body (want/have/shallow/deepen lines across two flush-separated sections). */
function parseV0Fetch(buf: Buffer): FetchParams {
  const params: FetchParams = { wants: [], haves: [], shallow: [], depth: null, filter: null };
  for (const packet of decodePktLines(buf)) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const rest = line.slice(5);
      const nul = rest.indexOf('\0');
      params.wants.push(nul >= 0 ? rest.slice(0, nul) : rest.split(' ')[0] as string);
    } else if (line.startsWith('have ')) {
      params.haves.push(line.slice(5).trim());
    } else if (line.startsWith('shallow ')) {
      params.shallow.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      params.depth = Number(line.slice(7).trim());
    } else if (line.startsWith('deepen-since ') || line.startsWith('deepen-not ')) {
      // Not scored; treated as a full-depth request.
    } else if (line === 'done' || line === '') {
      // Negotiation terminator.
    }
  }
  return params;
}

/** Parse a v2 fetch body (command=fetch, args, delim, want/have/shallow/deepen lines). */
function parseV2Fetch(buf: Buffer): FetchParams {
  const params: FetchParams = { wants: [], haves: [], shallow: [], depth: null, filter: null };
  for (const packet of decodePktLines(buf)) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) params.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) params.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) params.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) params.depth = Number(line.slice(7).trim());
    else if (line.startsWith('filter ')) params.filter = line.slice(7).trim();
  }
  return params;
}

function parseV2LsRefs(buf: Buffer): { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] } {
  const out = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
  for (const packet of decodePktLines(buf)) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line === 'peel') out.peel = true;
    else if (line === 'symrefs') out.symrefs = true;
    else if (line === 'unborn') out.unborn = true;
    else if (line.startsWith('ref-prefix ')) out.prefixes.push(line.slice(11));
  }
  return out;
}

/** v2 ls-refs response: `<oid> <ref>[ peeled:<oid>][ symref-target:<ref>]` lines + flush. */
export function lsRefsV2(forge: Forge, repo: Repo, buf: Buffer): Buffer {
  const opts = parseV2LsRefs(buf);
  const lines: Buffer[] = [];
  const keep = (name: string): boolean => opts.prefixes.length === 0 || opts.prefixes.some((p) => name.startsWith(p));
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (headOid !== undefined && keep('HEAD')) {
    lines.push(pktLine(`${headOid} HEAD${opts.symrefs ? ` symref-target:${headTarget}` : ''}\n`));
  }
  // No unborn line: a fresh repository advertises no refs at all, and a ZERO oid
  // in the list would be read as a real tip by fetch/clone callers.
  for (const ref of sortedRefs(repo)) {
    if (!keep(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (opts.peel) {
      const peeled = peelTag(forge, repo, ref.oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    if (opts.symrefs && ref.name === headTarget) line += ` symref-target:${headTarget}`;
    lines.push(pktLine(`${line}\n`));
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}

export interface UploadPackResult {
  status: number;
  body: Buffer;
  contentType: string;
}

/** Handle POST /<owner>/<repo>/git-upload-pack (v0 or v2 by body shape). */
export function handleUploadPack(forge: Forge, repo: Repo, body: Buffer): UploadPackResult {
  const contentType = 'application/x-git-upload-pack-result';
  const packets = decodePktLines(body);
  const firstData = packets.find((p) => p.kind === 'data');
  const firstLine = firstData?.payload.toString('utf8').replace(/\n$/, '') ?? '';
  if (firstLine.startsWith('command=ls-refs')) {
    return { status: 200, body: lsRefsV2(forge, repo, body), contentType };
  }
  const isV2 = firstLine.startsWith('command=fetch');
  const params = isV2 ? parseV2Fetch(body) : parseV0Fetch(body);
  if (params.wants.length === 0) {
    // No wants: an empty pack (v0) / empty sections (v2). Never an error.
    if (isV2) {
      return { status: 200, body: Buffer.concat([pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM, pktLine('packfile\n'), sidebandWrap(writePack(forge.store, [])), PKT_FLUSH]), contentType };
    }
    return { status: 200, body: Buffer.concat([pktLine('NAK\n'), sidebandWrap(writePack(forge.store, [])), PKT_FLUSH]), contentType };
  }
  const missing = params.wants.filter((w) => forge.store.get(w) === undefined);
  if (missing.length > 0) {
    // A want for an object the forge does not hold: the client treats a pack that
    // omits it as an error, so answer 400 with a sideband error instead of hanging.
    const message = `want ${missing[0]} not found`;
    if (isV2) {
      return { status: 200, body: Buffer.concat([pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM, pktLine('packfile\n'), sidebandWrap(Buffer.from(message, 'utf8'), 3), PKT_FLUSH]), contentType };
    }
    return { status: 200, body: Buffer.concat([sidebandWrap(Buffer.from(message, 'utf8'), 3), PKT_FLUSH]), contentType };
  }
  const computed = forge.computeFetch(params.wants, params.haves, params.shallow, params.depth);
  const cacheKey = `${repo.owner}/${repo.name}|${params.wants.join(',')}|${params.haves.join(',')}|${params.shallow.join(',')}|${params.depth ?? ''}`;
  const pack = forge.cachedPack(cacheKey, () => writePack(forge.store, computed.oids));
  if (isV2) {
    const chunks: Buffer[] = [pktLine('acknowledgments\n')];
    if (computed.acks.length > 0) {
      for (const ack of computed.acks) chunks.push(pktLine(`ACK ${ack}\n`));
      chunks.push(pktLine('ready\n'));
    } else {
      chunks.push(pktLine('NAK\n'));
    }
    chunks.push(PKT_DELIM);
    if (computed.shallow.length > 0 || computed.unshallow.length > 0) {
      chunks.push(pktLine('shallow-info\n'));
      for (const oid of computed.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
      for (const oid of computed.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
      chunks.push(PKT_DELIM);
    }
    chunks.push(pktLine('packfile\n'));
    chunks.push(sidebandWrap(pack));
    chunks.push(PKT_FLUSH);
    return { status: 200, body: Buffer.concat(chunks), contentType };
  }
  const chunks: Buffer[] = [];
  if (computed.acks.length > 0) {
    for (const ack of computed.acks) chunks.push(pktLine(`ACK ${ack}\n`));
  } else {
    chunks.push(pktLine('NAK\n'));
  }
  for (const oid of computed.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
  for (const oid of computed.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
  chunks.push(sidebandWrap(pack));
  chunks.push(PKT_FLUSH);
  return { status: 200, body: Buffer.concat(chunks), contentType };
}

/** Handle POST /<owner>/<repo>/git-receive-pack. Returns the report-status body. */
export function handleReceivePack(forge: Forge, repo: Repo, body: Buffer): { status: number; body: Buffer; contentType: string } {
  const contentType = 'application/x-git-receive-pack-result';
  interface Command { oldOid: string; newOid: string; ref: string; capabilities: string; }
  const commands: Command[] = [];
  let packStart = body.length;
  let pos = 0;
  // Walk the raw body: command pkt-lines, then a flush, then the pack bytes.
  while (pos + 4 <= body.length) {
    const lenText = body.subarray(pos, pos + 4).toString('ascii');
    if (lenText === '0000') {
      packStart = pos + 4;
      break;
    }
    const len = parseInt(lenText, 16);
    if (!Number.isFinite(len) || len < 4 || pos + len > body.length) break;
    const payload = body.subarray(pos + 4, pos + len).toString('utf8').replace(/\n$/, '');
    const nul = payload.indexOf('\0');
    const main = nul >= 0 ? payload.slice(0, nul) : payload;
    const caps = nul >= 0 ? payload.slice(nul + 1) : '';
    const parts = main.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' '), capabilities: caps });
    }
    pos += len;
  }
  // Unpack the pack (if any) into the store before validating the commands.
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packStart < body.length) {
    try {
      const pack = readPack(body.subarray(packStart));
      for (const [oid, obj] of pack.objects) forge.store.putObject(oid, obj.type, obj.data);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpacker error';
    }
  }
  const reportLines: string[] = [];
  if (unpackOk) {
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) reportLines.push(`ng ${command.ref} no such ref`);
        else if (command.oldOid !== ZERO_OID && command.oldOid !== current) reportLines.push(`ng ${command.ref} non-fast-forward`);
        else {
          repo.refs.delete(command.ref);
          reportLines.push(`ok ${command.ref}`);
        }
        continue;
      }
      if (current === undefined) {
        if (command.oldOid !== ZERO_OID) {
          reportLines.push(`ng ${command.ref} non-fast-forward`);
          continue;
        }
        if (forge.store.get(command.newOid) === undefined) {
          reportLines.push(`ng ${command.ref} unpacker error`);
          continue;
        }
        repo.refs.set(command.ref, command.newOid);
        reportLines.push(`ok ${command.ref}`);
        continue;
      }
      // Update of an existing ref.
      if (command.oldOid === ZERO_OID || command.oldOid !== current) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
        continue;
      }
      if (forge.store.get(command.newOid) === undefined) {
        reportLines.push(`ng ${command.ref} unpacker error`);
        continue;
      }
      const newObj = forge.store.get(command.newOid);
      if (newObj?.type === 'commit' && !isDescendant(forge.store, command.newOid, command.oldOid)) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      reportLines.push(`ok ${command.ref}`);
    }
  }
  if (reportLines.some((line) => line.startsWith('ok '))) {
    repo.pushedAt = tickIso();
    forge.invalidatePackCache();
  }
  const text = `unpack ${unpackOk ? 'ok' : unpackDetail}\n${reportLines.map((line) => `${line}\n`).join('')}`;
  // report-status inside sideband band 1: each report line is itself pkt-framed.
  const framed = Buffer.concat([...text.split('\n').filter((l) => l !== '').map((l) => pktLine(`${l}\n`))]);
  const bodyOut = Buffer.concat([sidebandWrap(framed), PKT_FLUSH]);
  return { status: 200, body: bodyOut, contentType };
}

// --------------------------------------------------------------------------- REST v3

export interface HttpRequest {
  method: string;
  pathname: string;
  query: URLSearchParams;
  headers: Record<string, string | string[] | undefined>;
  host: string;
  token: string | null;
  body: Buffer;
}

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export function jsonResult(status: number, value: unknown, extra: Record<string, string> = {}): HttpResult {
  return {
    status,
    headers: { 'content-type': 'application/json', 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo', ...extra },
    body: JSON.stringify(value),
  };
}

export function errorResult(status: number, message: string): HttpResult {
  return jsonResult(status, { message });
}

export function parseJsonBody(req: HttpRequest): { ok: true; value: Record<string, unknown> } | { ok: false; result: HttpResult } {
  if (req.body.length === 0) return { ok: true, value: {} };
  try {
    const parsed: unknown = JSON.parse(req.body.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ok: true, value: parsed as Record<string, unknown> };
    }
    return { ok: false, result: errorResult(400, 'request body must be a JSON object') };
  } catch {
    return { ok: false, result: errorResult(400, 'request body is not valid JSON') };
  }
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}
function asBool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function repoJson(forge: Forge, repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repo.nodeId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: forge.viewer.id, type: 'User' },
    private: repo.privateRepo,
    description: repo.description,
    fork: repo.fork,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.pushedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    visibility: repo.privateRepo ? 'private' : 'public',
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    archived: false,
    disabled: false,
    license: null,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}

export function issueJson(forge: Forge, repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: repo.id * 100000 + issue.number,
    node_id: nodeId('Issue', `${repo.owner}/${repo.name}#${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ id: l.id, name: l.name, color: l.color, description: l.description })),
    user: { login: issue.user, id: forge.viewer.id, type: 'User' },
    assignees: [],
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

export function commentJson(forge: Forge, repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: repo.id * 1000000 + issue.number * 1000 + comment.id,
    node_id: nodeId('IssueComment', `${repo.owner}/${repo.name}#${issue.number}:${comment.id}`),
    body: comment.body,
    user: { login: comment.user, id: forge.viewer.id, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
  };
}

export function pullJson(forge: Forge, repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: repo.id * 100000 + pull.number,
    node_id: nodeId('PullRequest', `${repo.owner}/${repo.name}#${pull.number}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open',
    mergeable_state: pull.state === 'open' ? 'clean' : 'unknown',
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}`, repo: repoJson(forge, repo) },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}`, repo: repoJson(forge, repo) },
    user: { login: pull.user, id: forge.viewer.id, type: 'User' },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.state === 'closed' ? pull.updatedAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

export function commitJson(forge: Forge, repo: Repo, oid: string): Record<string, unknown> | null {
  const obj = forge.store.get(oid);
  if (obj?.type !== 'commit') return null;
  const parts = parseCommit(obj.data);
  const author = parts.author.split(' <')[0] ?? VIEWER_LOGIN;
  // The author line carries the commit's own timestamp: "<name> <email> <unix> +0000".
  const stampMatch = / (\d+) \+0000$/.exec(parts.author);
  const date = stampMatch !== null ? new Date(Number(stampMatch[1]) * 1000).toISOString() : tickIso();
  return {
    sha: oid,
    node_id: nodeId('Commit', oid),
    commit: {
      message: parts.message,
      author: { name: author, email: `${VIEWER_LOGIN}@users.noreply.github.com`, date },
      committer: { name: author, email: `${VIEWER_LOGIN}@users.noreply.github.com`, date },
      tree: { sha: parts.tree },
    },
    author: { login: VIEWER_LOGIN, id: forge.viewer.id, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: forge.viewer.id, type: 'User' },
    parents: parts.parents.map((p) => ({ sha: p })),
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
  };
}

function paginate(req: HttpRequest, items: unknown[]): { page: unknown[]; link: string | null } {
  const perPageRaw = Number(req.query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const pageRaw = Number(req.query.get('page') ?? '1');
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (totalPages <= 1) return { page: slice, link: null };
  const base = `http://${req.host}${req.pathname}`;
  const linkFor = (p: number): string => {
    const params = new URLSearchParams(req.query);
    params.set('page', String(p));
    params.set('per_page', String(perPage));
    return `<${base}?${params.toString()}>`;
  };
  const links: string[] = [];
  if (page < totalPages) links.push(`${linkFor(page + 1)}; rel="next"`);
  if (page > 1) links.push(`${linkFor(page - 1)}; rel="prev"`);
  links.push(`${linkFor(1)}; rel="first"`);
  links.push(`${linkFor(totalPages)}; rel="last"`);
  return { page: slice, link: links.join(', ') };
}

function repoAccess(forge: Forge, req: HttpRequest, owner: string, name: string): { repo: Repo } | { result: HttpResult } {
  const repo = forge.getRepo(owner, name);
  if (repo === undefined) return { result: errorResult(404, 'Not Found') };
  if (repo.privateRepo && req.token === null) return { result: errorResult(401, 'Bad credentials') };
  if (repo.owner !== owner) return { result: errorResult(404, 'Not Found') };
  return { repo };
}

function requireAuth(req: HttpRequest): HttpResult | null {
  return req.token === null ? errorResult(401, 'Bad credentials') : null;
}

/** Decode a URI path segment (repo names / file paths may be percent-encoded). */
function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/**
 * Handle a REST v3 request. Returns null when the path is not a REST route
 * (the dispatcher then tries GraphQL, MCP, or git).
 */
export function handleRest(forge: Forge, req: HttpRequest): HttpResult | null {
  const path = req.pathname;
  if (!path.startsWith('/api/v3')) return null;
  const rest = path.slice('/api/v3'.length);
  const segments = rest.split('/').filter((s) => s !== '').map(decodeSegment);
  const method = req.method;

  // GET /api/v3/ — root (public, needs x-oauth-scopes).
  if (method === 'GET' && segments.length === 0) {
    return jsonResult(200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' });
  }
  // GET /api/v3/meta
  if (method === 'GET' && segments.length === 1 && segments[0] === 'meta') {
    return jsonResult(200, { installed_version: '1.0.0', verifiable_password_authentication: false });
  }
  // GET /api/v3/user
  if (method === 'GET' && segments.length === 1 && segments[0] === 'user') {
    const auth = requireAuth(req);
    if (auth !== null) return auth;
    return jsonResult(200, { login: forge.viewer.login, id: forge.viewer.id, node_id: nodeId('User', forge.viewer.id), type: 'User' });
  }
  // /api/v3/user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    const auth = requireAuth(req);
    if (auth !== null) return auth;
    if (method === 'GET') {
      const { page, link } = paginate(req, forge.listViewerRepos().map((r) => repoJson(forge, r)));
      return jsonResult(200, page, link === null ? {} : { link });
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(req);
      if (!parsed.ok) return parsed.result;
      const name = asString(parsed.value.name);
      if (name === '') return errorResult(422, 'name is required');
      const created = forge.createRepo(name, {
        description: asString(parsed.value.description),
        privateRepo: asBool(parsed.value.private, false),
      });
      if ('error' in created) return errorResult(422, 'Repository already exists');
      return jsonResult(201, repoJson(forge, created));
    }
    return errorResult(405, 'Method Not Allowed');
  }

  // /api/v3/repos/:owner/:name[/...]
  if (segments.length >= 3 && segments[0] === 'repos') {
    const owner = segments[1] as string;
    const name = segments[2] as string;
    const tail = segments.slice(3);
    // Repo itself.
    if (tail.length === 0) {
      if (method === 'GET') {
        const found = repoAccess(forge, req, owner, name);
        if ('result' in found) return found.result;
        return jsonResult(200, repoJson(forge, found.repo));
      }
      if (method === 'PATCH') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const found = repoAccess(forge, req, owner, name);
        if ('result' in found) return found.result;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        if (typeof parsed.value.description === 'string') found.repo.description = parsed.value.description;
        if (typeof parsed.value.default_branch === 'string') found.repo.defaultBranch = parsed.value.default_branch;
        found.repo.updatedAt = tickIso();
        return jsonResult(200, repoJson(forge, found.repo));
      }
      if (method === 'DELETE') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const found = repoAccess(forge, req, owner, name);
        if ('result' in found) return found.result;
        forge.deleteRepo(owner, name);
        return { status: 204, headers: { 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo' }, body: '' };
      }
      return errorResult(405, 'Method Not Allowed');
    }
    const found = repoAccess(forge, req, owner, name);
    if ('result' in found) return found.result;
    const repo = found.repo;
    const section = tail[0] as string;

    if (section === 'branches') {
      if (method === 'GET' && tail.length === 1) {
        const list = [...repo.refs.keys()]
          .filter((r) => r.startsWith('refs/heads/'))
          .map((r) => r.slice('refs/heads/'.length))
          .sort()
          .map((branch) => ({ name: branch, commit: { sha: repo.refs.get(`refs/heads/${branch}`) as string }, protected: false }));
        return jsonResult(200, list);
      }
      if (method === 'GET' && tail.length === 2) {
        const branch = tail[1] as string;
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (sha === undefined) return errorResult(404, 'Branch not found');
        return jsonResult(200, { name: branch, commit: { sha }, protected: false });
      }
      return errorResult(405, 'Method Not Allowed');
    }

    if (section === 'commits') {
      if (method === 'GET' && tail.length === 1) {
        const branch = req.query.get('sha') ?? undefined;
        const oids = forge.branchCommits(repo, branch ?? repo.defaultBranch);
        const list = oids.map((oid) => commitJson(forge, repo, oid)).filter((c): c is Record<string, unknown> => c !== null);
        return jsonResult(200, list);
      }
      if (method === 'GET' && tail.length === 2) {
        const sha = tail[1] as string;
        const resolved = forge.resolveRef(repo, sha) ?? (isOid(sha) ? sha : null);
        if (resolved === null) return errorResult(404, 'Commit not found');
        const entry = commitJson(forge, repo, resolved);
        if (entry === null) return errorResult(404, 'Commit not found');
        return jsonResult(200, entry);
      }
      return errorResult(405, 'Method Not Allowed');
    }

    if (section === 'contents') {
      const filePath = tail.slice(1).join('/');
      const refParam = req.query.get('ref') ?? undefined;
      if (method === 'GET') {
        const treeOid = forge.refTree(repo, refParam);
        if (treeOid === null) return errorResult(404, 'Not Found');
        if (filePath === '') {
          const entries = parseTree((forge.store.get(treeOid) as GitObject).data).map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: e.name,
            sha: e.oid,
            size: e.mode === '40000' ? 0 : (forge.store.get(e.oid) as GitObject).data.length,
          }));
          return jsonResult(200, entries);
        }
        const found2 = forge.readPath(treeOid, filePath);
        if (found2 === null) return errorResult(404, 'Not Found');
        if (found2.kind === 'dir') {
          const entries = found2.entries.map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: `${filePath}/${e.name}`,
            sha: e.oid,
            size: e.mode === '40000' ? 0 : (forge.store.get(e.oid) as GitObject).data.length,
          }));
          return jsonResult(200, entries);
        }
        const blob = forge.store.get(found2.oid) as GitObject;
        return jsonResult(200, {
          type: 'file',
          encoding: 'base64',
          content: blob.data.toString('base64'),
          sha: found2.oid,
          size: blob.data.length,
          name: filePath.split('/').pop(),
          path: filePath,
        });
      }
      if (method === 'PUT' || method === 'DELETE') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const message = asString(parsed.value.message);
        if (message === '') return errorResult(422, 'message is required');
        const branch = asString(parsed.value.branch) || repo.defaultBranch;
        const treeOid = forge.refTree(repo, branch);
        const current = treeOid !== null && filePath !== '' ? forge.readPath(treeOid, filePath) : null;
        if (method === 'DELETE') {
          if (current === null || current.kind !== 'file') return errorResult(404, 'Not Found');
          if (typeof parsed.value.sha === 'string' && parsed.value.sha !== current.oid) return errorResult(409, 'sha does not match');
          const { commitOid } = forge.commitFile(repo, branch, filePath, Buffer.alloc(0), message, true);
          return jsonResult(200, { commit: { sha: commitOid, message } });
        }
        const contentB64 = asString(parsed.value.content);
        let content: Buffer;
        try {
          content = Buffer.from(contentB64, 'base64');
        } catch {
          return errorResult(422, 'content is not valid base64');
        }
        const isUpdate = current !== null && current.kind === 'file';
        if (isUpdate) {
          if (typeof parsed.value.sha === 'string' && parsed.value.sha !== current.oid) {
            return errorResult(409, 'sha does not match the current blob');
          }
          const { commitOid, blobOid } = forge.commitFile(repo, branch, filePath, content, message, false);
          return jsonResult(200, {
            content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: contentB64 },
            commit: { sha: commitOid, message },
          });
        }
        const { commitOid, blobOid } = forge.commitFile(repo, branch, filePath, content, message, false);
        return jsonResult(201, {
          content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: contentB64 },
          commit: { sha: commitOid, message },
        });
      }
      return errorResult(405, 'Method Not Allowed');
    }

    if (section === 'git' && tail[1] === 'refs') {
      const refPath = tail.slice(2).join('/');
      if (method === 'GET' && refPath === '') {
        const list = [...repo.refs.entries()].map(([ref, sha]) => ({ ref, object: { sha, type: 'commit' } }));
        return jsonResult(200, list);
      }
      if (method === 'GET') {
        const fullRef = refPath.startsWith('refs/') ? refPath : `refs/${refPath}`;
        const sha = repo.refs.get(fullRef);
        if (sha === undefined) return errorResult(404, 'Reference not found');
        return jsonResult(200, { ref: fullRef, object: { sha, type: 'commit' } });
      }
      if (method === 'POST' && refPath === '') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const ref = asString(parsed.value.ref);
        const sha = asString(parsed.value.sha);
        if (!ref.startsWith('refs/') || !isOid(sha)) return errorResult(422, 'ref and sha are required');
        if (repo.refs.has(ref)) return errorResult(422, 'Reference already exists');
        if (forge.store.get(sha) === undefined) return errorResult(422, 'sha not found');
        repo.refs.set(ref, sha);
        return jsonResult(201, { ref, object: { sha, type: 'commit' } });
      }
      if (method === 'PATCH' && refPath !== '') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const fullRef = refPath.startsWith('refs/') ? refPath : `refs/${refPath}`;
        if (!repo.refs.has(fullRef)) return errorResult(404, 'Reference not found');
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const sha = asString(parsed.value.sha);
        if (!isOid(sha) || forge.store.get(sha) === undefined) return errorResult(422, 'sha not found');
        repo.refs.set(fullRef, sha);
        return jsonResult(200, { ref: fullRef, object: { sha, type: 'commit' } });
      }
      if (method === 'DELETE' && refPath !== '') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const fullRef = refPath.startsWith('refs/') ? refPath : `refs/${refPath}`;
        if (!repo.refs.has(fullRef)) return errorResult(404, 'Reference not found');
        repo.refs.delete(fullRef);
        return { status: 204, headers: { 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo' }, body: '' };
      }
      return errorResult(405, 'Method Not Allowed');
    }

    if (section === 'labels') {
      if (method === 'GET') return jsonResult(200, repo.labels.map((l) => ({ id: l.id, name: l.name, color: l.color, description: l.description })));
      if (method === 'POST') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const name = asString(parsed.value.name);
        if (name === '') return errorResult(422, 'name is required');
        if (repo.labels.some((l) => l.name === name)) return errorResult(422, 'Label already exists');
        const label = forge.findOrCreateLabel(repo, name, asString(parsed.value.color) || 'ededed');
        if (typeof parsed.value.description === 'string') label.description = parsed.value.description;
        return jsonResult(201, { id: label.id, name: label.name, color: label.color, description: label.description });
      }
      return errorResult(405, 'Method Not Allowed');
    }

    if (section === 'issues') {
      const number = tail.length >= 2 ? Number(tail[1]) : NaN;
      if (tail.length === 1 && method === 'GET') {
        const state = req.query.get('state') ?? 'open';
        const sort = req.query.get('sort') ?? 'created';
        const direction = req.query.get('direction') ?? 'desc';
        let list = [...repo.issues];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        }
        const { page, link } = paginate(req, list.map((i) => issueJson(forge, repo, i)));
        return jsonResult(200, page, link === null ? {} : { link });
      }
      if (tail.length === 1 && method === 'POST') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const title = asString(parsed.value.title);
        if (title === '') return errorResult(422, 'title is required');
        const labels = Array.isArray(parsed.value.labels) ? parsed.value.labels.filter((l): l is string => typeof l === 'string') : [];
        const created = forge.createIssue(repo, title, asString(parsed.value.body), labels);
        if ('error' in created) return errorResult(422, created.error);
        return jsonResult(201, issueJson(forge, repo, created));
      }
      if (tail.length >= 2 && Number.isInteger(number)) {
        const issue = repo.issues.find((i) => i.number === number);
        if (issue === undefined) return errorResult(404, 'Issue not found');
        if (tail.length === 2 && method === 'GET') return jsonResult(200, issueJson(forge, repo, issue));
        if (tail.length === 2 && method === 'PATCH') {
          const auth = requireAuth(req);
          if (auth !== null) return auth;
          const parsed = parseJsonBody(req);
          if (!parsed.ok) return parsed.result;
          if (parsed.value.state === 'open' || parsed.value.state === 'closed') issue.state = parsed.value.state;
          if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
          if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
          issue.updatedAt = tickIso();
          return jsonResult(200, issueJson(forge, repo, issue));
        }
        if (tail.length === 3 && tail[2] === 'comments') {
          if (method === 'GET') {
            return jsonResult(200, issue.comments.map((c) => commentJson(forge, repo, issue, c)));
          }
          if (method === 'POST') {
            const auth = requireAuth(req);
            if (auth !== null) return auth;
            const parsed = parseJsonBody(req);
            if (!parsed.ok) return parsed.result;
            const body = asString(parsed.value.body);
            if (body === '') return errorResult(422, 'body is required');
            repo.commentSeq += 1;
            const now = tickIso();
            const comment: IssueComment = { id: repo.commentSeq, body, user: forge.viewer.login, createdAt: now, updatedAt: now };
            issue.comments.push(comment);
            issue.updatedAt = now;
            return jsonResult(201, commentJson(forge, repo, issue, comment));
          }
        }
        return errorResult(405, 'Method Not Allowed');
      }
      return errorResult(404, 'Not Found');
    }

    if (section === 'pulls') {
      const number = tail.length >= 2 ? Number(tail[1]) : NaN;
      if (tail.length === 1 && method === 'GET') {
        const state = req.query.get('state') ?? 'open';
        let list = [...repo.pulls];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.seq - a.seq);
        const { page, link } = paginate(req, list.map((p) => pullJson(forge, repo, p)));
        return jsonResult(200, page, link === null ? {} : { link });
      }
      if (tail.length === 1 && method === 'POST') {
        const auth = requireAuth(req);
        if (auth !== null) return auth;
        const parsed = parseJsonBody(req);
        if (!parsed.ok) return parsed.result;
        const created = forge.createPull(repo, asString(parsed.value.title), asString(parsed.value.body), asString(parsed.value.head), asString(parsed.value.base));
        if ('error' in created) return errorResult(422, created.error);
        return jsonResult(201, pullJson(forge, repo, created));
      }
      if (tail.length >= 2 && Number.isInteger(number)) {
        const pull = repo.pulls.find((p) => p.number === number);
        if (pull === undefined) return errorResult(404, 'Pull request not found');
        if (tail.length === 2 && method === 'GET') return jsonResult(200, pullJson(forge, repo, pull));
        if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
          return jsonResult(200, pull.files.map((f) => ({ filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.changes, patch: f.patch })));
        }
        if (tail.length === 3 && tail[2] === 'commits' && method === 'GET') {
          const list = pull.commits.map((oid) => commitJson(forge, repo, oid)).filter((c): c is Record<string, unknown> => c !== null);
          return jsonResult(200, list);
        }
        if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
          const auth = requireAuth(req);
          if (auth !== null) return auth;
          const merged = forge.mergePull(repo, number);
          if ('error' in merged) return errorResult(merged.status, merged.error);
          return jsonResult(200, { merged: true, sha: merged.commitOid, message: pull.mergeMessage });
        }
        return errorResult(405, 'Method Not Allowed');
      }
      return errorResult(404, 'Not Found');
    }

    return errorResult(404, 'Not Found');
  }

  // Unknown /api/v3 route.
  return errorResult(404, 'Not Found');
}

// --------------------------------------------------------------------------- GraphQL v4

type GqlValue =
  | { kind: 'Variable'; name: string }
  | { kind: 'String'; value: string }
  | { kind: 'Int'; value: number }
  | { kind: 'Float'; value: number }
  | { kind: 'Boolean'; value: boolean }
  | { kind: 'Enum'; value: string }
  | { kind: 'Null' }
  | { kind: 'List'; values: GqlValue[] }
  | { kind: 'Object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  name: string;
  alias: string | null;
  args: Array<{ name: string; value: GqlValue }>;
  directives: Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }>;
  selectionSet: GqlSelection[] | null;
}

type GqlSelection =
  | { kind: 'Field'; field: GqlField }
  | { kind: 'FragmentSpread'; name: string; directives: Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }> }
  | { kind: 'InlineFragment'; typeCondition: string | null; directives: Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }>; selectionSet: GqlSelection[] };

interface GqlOperation {
  kind: 'Operation';
  operation: 'query' | 'mutation';
  name: string | null;
  variables: Array<{ name: string; defaultValue: GqlValue | null }>;
  selectionSet: GqlSelection[];
}

interface GqlFragment {
  kind: 'Fragment';
  name: string;
  typeCondition: string;
  selectionSet: GqlSelection[];
}

type GqlDefinition = GqlOperation | GqlFragment;

interface GqlToken {
  kind: 'Name' | 'Int' | 'Float' | 'String' | 'Punct' | 'EOF';
  value: string;
}

export function gqlTokenize(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  const push = (kind: GqlToken['kind'], value: string): void => {
    tokens.push({ kind, value });
  };
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      push('Punct', '...');
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@|&'.includes(ch)) {
      push('Punct', ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (src.slice(i, i + 3) === '"""') {
        const end = src.indexOf('"""', i + 3);
        const value = end < 0 ? src.slice(i + 3) : src.slice(i + 3, end);
        push('String', value);
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else if (esc === 'u') {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      push('String', out);
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      const text = src.slice(i, j);
      push(text.includes('.') || text.includes('e') || text.includes('E') ? 'Float' : 'Int', text);
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j] as string)) j += 1;
      push('Name', src.slice(i, j));
      i = j;
      continue;
    }
    throw new Error(`GraphQL syntax error at offset ${i}: ${JSON.stringify(ch)}`);
  }
  push('EOF', '');
  return tokens;
}

export class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken {
    return this.tokens[this.pos] as GqlToken;
  }
  private next(): GqlToken {
    const tok = this.tokens[this.pos] as GqlToken;
    this.pos += 1;
    return tok;
  }
  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'Punct' || tok.value !== value) throw new Error(`expected '${value}', got '${tok.value}'`);
  }
  private expectName(value?: string): string {
    const tok = this.next();
    if (tok.kind !== 'Name') throw new Error(`expected a name, got '${tok.value}'`);
    if (value !== undefined && tok.value !== value) throw new Error(`expected '${value}', got '${tok.value}'`);
    return tok.value;
  }

  parseDocument(): GqlDefinition[] {
    const defs: GqlDefinition[] = [];
    while (this.peek().kind !== 'EOF') defs.push(this.parseDefinition());
    return defs;
  }

  private parseDefinition(): GqlDefinition {
    const tok = this.peek();
    if (tok.kind === 'Punct' && tok.value === '{') {
      return { kind: 'Operation', operation: 'query', name: null, variables: [], selectionSet: this.parseSelectionSet() };
    }
    if (tok.kind === 'Name' && (tok.value === 'query' || tok.value === 'mutation')) {
      const operation = this.next().value as 'query' | 'mutation';
      let name: string | null = null;
      if (this.peek().kind === 'Name') name = this.next().value;
      const variables: Array<{ name: string; defaultValue: GqlValue | null }> = [];
      if (this.peek().kind === 'Punct' && this.peek().value === '(') {
        this.next();
        while (!(this.peek().kind === 'Punct' && this.peek().value === ')')) {
          this.expectPunct('$');
          const varName = this.expectName();
          this.expectPunct(':');
          this.parseTypeRef();
          let defaultValue: GqlValue | null = null;
          if (this.peek().kind === 'Punct' && this.peek().value === '=') {
            this.next();
            defaultValue = this.parseValue();
          }
          variables.push({ name: varName, defaultValue });
        }
        this.expectPunct(')');
      }
      const selectionSet = this.parseSelectionSet();
      return { kind: 'Operation', operation, name, variables, selectionSet };
    }
    if (tok.kind === 'Name' && tok.value === 'fragment') {
      this.next();
      const name = this.expectName();
      this.expectName('on');
      const typeCondition = this.expectName();
      const selectionSet = this.parseSelectionSet();
      return { kind: 'Fragment', name, typeCondition, selectionSet };
    }
    throw new Error(`unexpected token '${tok.value}' in document`);
  }

  private parseTypeRef(): void {
    if (this.peek().kind === 'Punct' && this.peek().value === '[') {
      this.next();
      this.parseTypeRef();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.peek().kind === 'Punct' && this.peek().value === '!') this.next();
  }

  parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek().kind === 'Punct' && this.peek().value === '}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek().kind === 'Punct' && this.peek().value === '...') {
      this.next();
      if (this.peek().kind === 'Name' && this.peek().value !== 'on') {
        const name = this.next().value;
        const directives = this.parseDirectives();
        return { kind: 'FragmentSpread', name, directives };
      }
      let typeCondition: string | null = null;
      if (this.peek().kind === 'Name' && this.peek().value === 'on') {
        this.next();
        typeCondition = this.expectName();
      }
      const directives = this.parseDirectives();
      const selectionSet = this.parseSelectionSet();
      return { kind: 'InlineFragment', typeCondition, directives, selectionSet };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek().kind === 'Punct' && this.peek().value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args: Array<{ name: string; value: GqlValue }> = [];
    if (this.peek().kind === 'Punct' && this.peek().value === '(') {
      this.next();
      while (!(this.peek().kind === 'Punct' && this.peek().value === ')')) {
        const argName = this.expectName();
        this.expectPunct(':');
        args.push({ name: argName, value: this.parseValue() });
      }
      this.expectPunct(')');
    }
    const directives = this.parseDirectives();
    let selectionSet: GqlSelection[] | null = null;
    if (this.peek().kind === 'Punct' && this.peek().value === '{') selectionSet = this.parseSelectionSet();
    return { kind: 'Field', field: { name, alias, args, directives, selectionSet } };
  }

  private parseDirectives(): Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }> {
    const directives: Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }> = [];
    while (this.peek().kind === 'Punct' && this.peek().value === '@') {
      this.next();
      const name = this.expectName();
      const args: Array<{ name: string; value: GqlValue }> = [];
      if (this.peek().kind === 'Punct' && this.peek().value === '(') {
        this.next();
        while (!(this.peek().kind === 'Punct' && this.peek().value === ')')) {
          const argName = this.expectName();
          this.expectPunct(':');
          args.push({ name: argName, value: this.parseValue() });
        }
        this.expectPunct(')');
      }
      directives.push({ name, args });
    }
    return directives;
  }

  private parseValue(): GqlValue {
    const tok = this.next();
    if (tok.kind === 'Punct' && tok.value === '$') return { kind: 'Variable', name: this.expectName() };
    if (tok.kind === 'String') return { kind: 'String', value: tok.value };
    if (tok.kind === 'Int') return { kind: 'Int', value: Number(tok.value) };
    if (tok.kind === 'Float') return { kind: 'Float', value: Number(tok.value) };
    if (tok.kind === 'Name') {
      if (tok.value === 'true') return { kind: 'Boolean', value: true };
      if (tok.value === 'false') return { kind: 'Boolean', value: false };
      if (tok.value === 'null') return { kind: 'Null' };
      return { kind: 'Enum', value: tok.value };
    }
    if (tok.kind === 'Punct' && tok.value === '[') {
      const values: GqlValue[] = [];
      while (!(this.peek().kind === 'Punct' && this.peek().value === ']')) values.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'List', values };
    }
    if (tok.kind === 'Punct' && tok.value === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (!(this.peek().kind === 'Punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'Object', fields };
    }
    throw new Error(`unexpected value token '${tok.value}'`);
  }
}

function evalGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'Variable':
      return variables[value.name] ?? null;
    case 'String':
    case 'Int':
    case 'Float':
    case 'Boolean':
    case 'Enum':
      return value.value;
    case 'Null':
      return null;
    case 'List':
      return value.values.map((v) => evalGqlValue(v, variables));
    case 'Object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalGqlValue(field.value, variables);
      return out;
    }
  }
}

// --------------------------------------------------------------------------- schema

const GQL_TYPE_KINDS: Record<string, string> = {
  Query: 'OBJECT',
  Mutation: 'OBJECT',
  Repository: 'OBJECT',
  Issue: 'OBJECT',
  PullRequest: 'OBJECT',
  User: 'OBJECT',
  Ref: 'OBJECT',
  IssueConnection: 'OBJECT',
  PullRequestConnection: 'OBJECT',
  IssueEdge: 'OBJECT',
  PullRequestEdge: 'OBJECT',
  PageInfo: 'OBJECT',
  CommentConnection: 'OBJECT',
  Comment: 'OBJECT',
  CommentEdge: 'OBJECT',
  LabelConnection: 'OBJECT',
  Label: 'OBJECT',
  LabelEdge: 'OBJECT',
  PullRequestFileConnection: 'OBJECT',
  PullRequestFile: 'OBJECT',
  PullRequestFileEdge: 'OBJECT',
  CommitConnection: 'OBJECT',
  Commit: 'OBJECT',
  CommitEdge: 'OBJECT',
  CreateIssuePayload: 'OBJECT',
  CloseIssuePayload: 'OBJECT',
  CreatePullRequestPayload: 'OBJECT',
  MergePullRequestPayload: 'OBJECT',
  AddCommentPayload: 'OBJECT',
  __Type: 'OBJECT',
  __Field: 'OBJECT',
  __InputValue: 'OBJECT',
  __EnumValue: 'OBJECT',
  __Schema: 'OBJECT',
  Node: 'INTERFACE',
  RepositoryOwner: 'INTERFACE',
  IssueState: 'ENUM',
  PullRequestState: 'ENUM',
  OrderDirection: 'ENUM',
  IssueOrderField: 'ENUM',
  RepositoryPermission: 'ENUM',
  SearchType: 'ENUM',
};

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__schema', '__type'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'url', 'description', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'createdAt', 'updatedAt', 'pushedAt', 'issue', 'issues', 'pullRequest', 'pullRequests'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'author', 'createdAt', 'updatedAt', 'labels', 'comments', 'repository'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'url', 'author', 'createdAt', 'updatedAt', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files', 'commits', 'repository'],
  User: ['id', 'login', 'name', 'url'],
  Ref: ['name', 'prefix', 'target'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  CommentConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  Comment: ['id', 'body', 'author', 'createdAt', 'updatedAt', 'url'],
  CommentEdge: ['node', 'cursor'],
  LabelConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  Label: ['id', 'name', 'color', 'description'],
  LabelEdge: ['node', 'cursor'],
  PullRequestFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changes'],
  PullRequestFileEdge: ['node', 'cursor'],
  CommitConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  Commit: ['oid', 'message', 'author'],
  CommitEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'inputFields', 'possibleTypes'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __InputValue: ['name', 'description', 'type', 'defaultValue'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __Schema: ['queryType', 'mutationType', 'subscriptionType', 'types', 'directives'],
  Node: ['id'],
  RepositoryOwner: ['id', 'login', 'url'],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
};

const GQL_FIELD_ARGS: Record<string, Record<string, string[]>> = {
  Repository: {
    issue: ['number'],
    issues: ['first', 'after', 'states', 'orderBy'],
    pullRequest: ['number'],
    pullRequests: ['first', 'after', 'states', 'orderBy'],
  },
  Issue: { labels: ['first', 'after'], comments: ['first', 'after'] },
  PullRequest: { files: ['first', 'after'], commits: ['first', 'after'] },
  Query: { repository: ['owner', 'name'], node: ['id'], __type: ['name'] },
  Mutation: { createIssue: ['input'], closeIssue: ['input'], createPullRequest: ['input'], mergePullRequest: ['input'], addComment: ['input'] },
  __Type: { fields: ['includeDeprecated'], enumValues: ['includeDeprecated'] },
};

type GqlParent =
  | { __type: 'Query' }
  | { __type: 'Mutation' }
  | { __type: 'Repository'; repo: Repo }
  | { __type: 'Issue'; repo: Repo; issue: Issue }
  | { __type: 'PullRequest'; repo: Repo; pull: PullRequest }
  | { __type: 'User'; login: string; id: number }
  | { __type: 'Ref'; name: string; oid: string | null }
  | { __type: 'IssueConnection'; repo: Repo; items: Issue[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'PullRequestConnection'; repo: Repo; items: PullRequest[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'IssueEdge'; repo: Repo; issue: Issue; cursor: string }
  | { __type: 'PullRequestEdge'; repo: Repo; pull: PullRequest; cursor: string }
  | { __type: 'PageInfo'; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'CommentConnection'; repo: Repo; issue: Issue; items: IssueComment[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'Comment'; repo: Repo; issue: Issue; comment: IssueComment }
  | { __type: 'CommentEdge'; repo: Repo; issue: Issue; comment: IssueComment; cursor: string }
  | { __type: 'LabelConnection'; items: Label[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'Label'; label: Label }
  | { __type: 'LabelEdge'; label: Label; cursor: string }
  | { __type: 'PullRequestFileConnection'; items: PullFile[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'PullRequestFile'; file: PullFile }
  | { __type: 'PullRequestFileEdge'; file: PullFile; cursor: string }
  | { __type: 'CommitConnection'; repo: Repo; items: string[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null }
  | { __type: 'Commit'; repo: Repo; oid: string }
  | { __type: 'CommitEdge'; repo: Repo; oid: string; cursor: string }
  | { __type: 'CreateIssuePayload'; repo: Repo; issue: Issue | null }
  | { __type: 'CloseIssuePayload'; repo: Repo; issue: Issue | null }
  | { __type: 'CreatePullRequestPayload'; repo: Repo; pull: PullRequest | null }
  | { __type: 'MergePullRequestPayload'; repo: Repo; pull: PullRequest | null }
  | { __type: 'AddCommentPayload'; repo: Repo; issue: Issue | null; comment: IssueComment | null }
  | { __type: '__Type'; name: string }
  | { __type: '__Field'; name: string }
  | { __type: '__InputValue'; name: string }
  | { __type: '__EnumValue'; name: string }
  | { __type: '__Schema' };

function cursorOf(kind: string, seq: number): string {
  return base64Encode(`${kind}:${seq}`);
}
function cursorSeq(cursor: string | null | undefined, kind: string): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const decoded = base64Decode(cursor);
    if (!decoded.startsWith(`${kind}:`)) return null;
    const num = Number(decoded.slice(kind.length + 1));
    return Number.isInteger(num) ? num : null;
  } catch {
    return null;
  }
}

function connectionSlice<T extends { seq: number }>(
  items: T[],
  first: unknown,
  after: unknown,
  kind: string,
  direction: 'ASC' | 'DESC',
): { page: T[]; hasNext: boolean; startCursor: string | null; endCursor: string | null } {
  const ordered = direction === 'ASC' ? [...items].sort((a, b) => a.seq - b.seq) : [...items].sort((a, b) => b.seq - a.seq);
  const afterSeq = cursorSeq(typeof after === 'string' ? after : null, kind);
  let start = 0;
  if (afterSeq !== null) {
    const idx = ordered.findIndex((item) => item.seq === afterSeq);
    start = idx >= 0 ? idx + 1 : 0;
  }
  const count = typeof first === 'number' && first >= 0 ? first : ordered.length;
  const page = ordered.slice(start, start + count);
  const hasNext = start + page.length < ordered.length;
  return {
    page,
    hasNext,
    startCursor: page.length > 0 ? cursorOf(kind, (page[0] as T).seq) : null,
    endCursor: page.length > 0 ? cursorOf(kind, (page[page.length - 1] as T).seq) : null,
  };
}

export class GqlExecutor {
  private readonly forge: Forge;
  constructor(forge: Forge) {
    this.forge = forge;
  }

  executeOperation(
    operation: GqlOperation,
    fragments: Map<string, GqlFragment>,
    variables: Record<string, unknown>,
  ): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
    const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
    const root: GqlParent = operation.operation === 'mutation' ? { __type: 'Mutation' } : { __type: 'Query' };
    const validation = this.validateSelections(operation.selectionSet, rootType, fragments);
    if (validation !== null) return { data: null, errors: [{ message: validation }] };
    const data: Record<string, unknown> = {};
    const errors: Array<{ message: string }> = [];
    for (const selection of operation.selectionSet) {
      this.executeSelection(selection, rootType, root, fragments, variables, data, errors);
    }
    return { data, errors };
  }

  private validateSelections(
    selections: GqlSelection[],
    parentType: string,
    fragments: Map<string, GqlFragment>,
    seen: Set<string> = new Set(),
  ): string | null {
    for (const selection of selections) {
      if (selection.kind === 'Field') {
        const field = selection.field;
        if (field.name === '__typename') continue;
        const fields = GQL_TYPE_FIELDS[parentType];
        if (fields === undefined || !fields.includes(field.name)) {
          return `Cannot query field "${field.name}" on type "${parentType}".`;
        }
        if (field.selectionSet !== null) {
          const childType = this.childType(parentType, field.name);
          if (childType !== null) {
            const problem = this.validateSelections(field.selectionSet, childType, fragments, seen);
            if (problem !== null) return problem;
          }
        }
      } else if (selection.kind === 'FragmentSpread') {
        if (seen.has(selection.name)) continue;
        seen.add(selection.name);
        const fragment = fragments.get(selection.name);
        if (fragment === undefined) return `Unknown fragment "${selection.name}".`;
        const problem = this.validateSelections(fragment.selectionSet, fragment.typeCondition, fragments, seen);
        if (problem !== null) return problem;
      } else {
        const condition = selection.typeCondition ?? parentType;
        if (GQL_TYPE_FIELDS[condition] === undefined && GQL_TYPE_KINDS[condition] === undefined) {
          return `Unknown type "${condition}".`;
        }
        const problem = this.validateSelections(selection.selectionSet, condition, fragments, seen);
        if (problem !== null) return problem;
      }
    }
    return null;
  }

  /** The object type a field's sub-selections are validated against. */
  private childType(parentType: string, fieldName: string): string | null {
    const map: Record<string, Record<string, string>> = {
      Query: { viewer: 'User', repository: 'Repository', node: 'Node', __schema: '__Schema', __type: '__Type' },
      Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
      Repository: { owner: 'User', defaultBranchRef: 'Ref', issue: 'Issue', issues: 'IssueConnection', pullRequest: 'PullRequest', pullRequests: 'PullRequestConnection' },
      Issue: { author: 'User', labels: 'LabelConnection', comments: 'CommentConnection', repository: 'Repository' },
      PullRequest: { author: 'User', files: 'PullRequestFileConnection', commits: 'CommitConnection', repository: 'Repository' },
      IssueConnection: { nodes: 'Issue', edges: 'IssueEdge', pageInfo: 'PageInfo' },
      PullRequestConnection: { nodes: 'PullRequest', edges: 'PullRequestEdge', pageInfo: 'PageInfo' },
      IssueEdge: { node: 'Issue' },
      PullRequestEdge: { node: 'PullRequest' },
      CommentConnection: { nodes: 'Comment', edges: 'CommentEdge', pageInfo: 'PageInfo' },
      CommentEdge: { node: 'Comment' },
      Comment: { author: 'User' },
      LabelConnection: { nodes: 'Label', edges: 'LabelEdge', pageInfo: 'PageInfo' },
      LabelEdge: { node: 'Label' },
      PullRequestFileConnection: { nodes: 'PullRequestFile', edges: 'PullRequestFileEdge', pageInfo: 'PageInfo' },
      PullRequestFileEdge: { node: 'PullRequestFile' },
      CommitConnection: { nodes: 'Commit', edges: 'CommitEdge', pageInfo: 'PageInfo' },
      CommitEdge: { node: 'Commit' },
      Commit: { author: 'User' },
      Ref: { target: 'Commit' },
      CreateIssuePayload: { issue: 'Issue' },
      CloseIssuePayload: { issue: 'Issue' },
      CreatePullRequestPayload: { pullRequest: 'PullRequest' },
      MergePullRequestPayload: { pullRequest: 'PullRequest' },
      AddCommentPayload: { commentEdge: 'CommentEdge', subject: 'Issue' },
      __Type: { fields: '__Field', enumValues: '__EnumValue', inputFields: '__InputValue', possibleTypes: '__Type' },
      __Field: { args: '__InputValue', type: '__Type' },
      __InputValue: { type: '__Type' },
      __Schema: { queryType: '__Type', mutationType: '__Type', subscriptionType: '__Type', types: '__Type' },
    };
    return map[parentType]?.[fieldName] ?? null;
  }

  private executeSelection(
    selection: GqlSelection,
    parentType: string,
    parent: GqlParent,
    fragments: Map<string, GqlFragment>,
    variables: Record<string, unknown>,
    out: Record<string, unknown>,
    errors: Array<{ message: string }>,
  ): void {
    if (selection.kind === 'Field') {
      const field = selection.field;
      if (!this.directivesAllow(field.directives, variables)) return;
      const key = field.alias ?? field.name;
      // A `node` field resolves against the node's concrete type, not the interface.
      const effectiveType =
        parentType === 'Node' && typeof parent === 'object' && parent !== null && '__type' in parent
          ? (parent as { __type: string }).__type
          : parentType;
      if (field.name === '__typename') {
        out[key] = effectiveType;
        return;
      }
      const args: Record<string, unknown> = {};
      for (const arg of field.args) args[arg.name] = evalGqlValue(arg.value, variables);
      const resolved = this.resolveField(effectiveType, parent, field.name, args, variables);
      if (resolved instanceof Error) {
        errors.push({ message: resolved.message });
        out[key] = null;
        return;
      }
      out[key] = this.resolveSelectionSet(field.selectionSet, resolved, fragments, variables, errors);
      return;
    }
    if (selection.kind === 'FragmentSpread') {
      if (!this.directivesAllow(selection.directives, variables)) return;
      const fragment = fragments.get(selection.name);
      if (fragment === undefined) return;
      if (!this.fragmentApplies(fragment.typeCondition, parentType, parent)) return;
      for (const inner of fragment.selectionSet) {
        this.executeSelection(inner, fragment.typeCondition === 'Node' ? parentType : fragment.typeCondition, parent, fragments, variables, out, errors);
      }
      return;
    }
    if (!this.directivesAllow(selection.directives, variables)) return;
    const condition = selection.typeCondition ?? parentType;
    if (!this.fragmentApplies(condition, parentType, parent)) return;
    for (const inner of selection.selectionSet) {
      this.executeSelection(inner, condition === 'Node' ? parentType : condition, parent, fragments, variables, out, errors);
    }
  }

  private fragmentApplies(condition: string, parentType: string, parent: GqlParent): boolean {
    if (condition === parentType) return true;
    if (condition === 'Node') return true;
    if (condition === 'RepositoryOwner' && parentType === 'User') return true;
    void parent;
    return false;
  }

  private directivesAllow(
    directives: Array<{ name: string; args: Array<{ name: string; value: GqlValue }> }>,
    variables: Record<string, unknown>,
  ): boolean {
    for (const directive of directives) {
      const arg = directive.args.find((a) => a.name === 'if');
      if (arg === undefined) continue;
      const value = evalGqlValue(arg.value, variables);
      if (directive.name === 'skip' && value === true) return false;
      if (directive.name === 'include' && value !== true) return false;
    }
    return true;
  }

  /** Resolve one field to a (type, value) pair for sub-selection execution. */
  private resolveField(
    parentType: string,
    parent: GqlParent,
    fieldName: string,
    args: Record<string, unknown>,
    variables: Record<string, unknown>,
  ): { type: string; value: unknown } | Error {
    void variables;
    const forge = this.forge;
    switch (parentType) {
      case 'Query': {
        if (fieldName === 'viewer') return { type: 'User', value: { __type: 'User', login: forge.viewer.login, id: forge.viewer.id } satisfies GqlParent };
        if (fieldName === 'repository') {
          const owner = args.owner as string | undefined;
          const name = args.name as string | undefined;
          if (typeof owner !== 'string' || typeof name !== 'string') return new Error('repository requires owner and name');
          const repo = forge.getRepo(owner, name);
          if (repo === undefined) return { type: 'Repository', value: null };
          return { type: 'Repository', value: { __type: 'Repository', repo } satisfies GqlParent };
        }
        if (fieldName === 'node') {
          const id = args.id as string | undefined;
          if (typeof id !== 'string') return new Error('node requires id');
          return this.resolveNode(id);
        }
        if (fieldName === '__schema') return { type: '__Schema', value: { __type: '__Schema' } satisfies GqlParent };
        if (fieldName === '__type') {
          const name = args.name as string | undefined;
          if (typeof name !== 'string' || GQL_TYPE_KINDS[name] === undefined) return { type: '__Type', value: null };
          return { type: '__Type', value: { __type: '__Type', name } satisfies GqlParent };
        }
        break;
      }
      case 'Mutation': {
        if (fieldName === 'createIssue') {
          const input = (args.input ?? {}) as Record<string, unknown>;
          const repo = this.repoByNodeId(input.repositoryId);
          if (repo === null) return new Error('repository not found');
          const labels = Array.isArray(input.labelIds)
            ? (input.labelIds as unknown[]).map((id) => this.labelNameByNodeId(repo, String(id))).filter((n): n is string => n !== null)
            : [];
          const created = forge.createIssue(repo, String(input.title ?? ''), String(input.body ?? ''), labels);
          if ('error' in created) return new Error(created.error);
          return { type: 'CreateIssuePayload', value: { __type: 'CreateIssuePayload', repo, issue: created } satisfies GqlParent };
        }
        if (fieldName === 'closeIssue') {
          const input = (args.input ?? {}) as Record<string, unknown>;
          const found = this.issueByNodeId(input.issueId);
          if (found === null) return new Error('issue not found');
          found.issue.state = 'closed';
          found.issue.updatedAt = tickIso();
          return { type: 'CloseIssuePayload', value: { __type: 'CloseIssuePayload', repo: found.repo, issue: found.issue } satisfies GqlParent };
        }
        if (fieldName === 'createPullRequest') {
          const input = (args.input ?? {}) as Record<string, unknown>;
          const repo = this.repoByNodeId(input.repositoryId);
          if (repo === null) return new Error('repository not found');
          const created = forge.createPull(repo, String(input.title ?? ''), String(input.body ?? ''), String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
          if ('error' in created) return new Error(created.error);
          return { type: 'CreatePullRequestPayload', value: { __type: 'CreatePullRequestPayload', repo, pull: created } satisfies GqlParent };
        }
        if (fieldName === 'mergePullRequest') {
          const input = (args.input ?? {}) as Record<string, unknown>;
          const found = this.pullByNodeId(input.pullRequestId);
          if (found === null) return new Error('pull request not found');
          const merged = forge.mergePull(found.repo, found.pull.number);
          if ('error' in merged) return new Error(merged.error);
          return { type: 'MergePullRequestPayload', value: { __type: 'MergePullRequestPayload', repo: found.repo, pull: found.pull } satisfies GqlParent };
        }
        if (fieldName === 'addComment') {
          const input = (args.input ?? {}) as Record<string, unknown>;
          const found = this.issueByNodeId(input.subjectId);
          if (found === null) return new Error('subject not found');
          found.repo.commentSeq += 1;
          const now = tickIso();
          const comment: IssueComment = { id: found.repo.commentSeq, body: String(input.body ?? ''), user: forge.viewer.login, createdAt: now, updatedAt: now };
          found.issue.comments.push(comment);
          return { type: 'AddCommentPayload', value: { __type: 'AddCommentPayload', repo: found.repo, issue: found.issue, comment } satisfies GqlParent };
        }
        break;
      }
      case 'Repository': {
        const repo = (parent as { repo: Repo }).repo;
        switch (fieldName) {
          case 'id': return { type: 'ID', value: repo.nodeId };
          case 'databaseId': return { type: 'Int', value: repo.id };
          case 'name': return { type: 'String', value: repo.name };
          case 'nameWithOwner': return { type: 'String', value: `${repo.owner}/${repo.name}` };
          case 'owner': return { type: 'User', value: { __type: 'User', login: repo.owner, id: forge.viewer.id } satisfies GqlParent };
          case 'url': return { type: 'String', value: `https://github.com/${repo.owner}/${repo.name}` };
          case 'description': return { type: 'String', value: repo.description };
          case 'defaultBranchRef': {
            const sha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
            if (sha === undefined) return { type: 'Ref', value: null };
            return { type: 'Ref', value: { __type: 'Ref', name: repo.defaultBranch, oid: sha } satisfies GqlParent };
          }
          case 'viewerPermission': return { type: 'String', value: 'ADMIN' };
          case 'hasIssuesEnabled': return { type: 'Boolean', value: true };
          case 'createdAt': return { type: 'String', value: repo.createdAt };
          case 'updatedAt': return { type: 'String', value: repo.updatedAt };
          case 'pushedAt': return { type: 'String', value: repo.pushedAt };
          case 'issue': {
            const number = args.number as number | undefined;
            const issue = repo.issues.find((i) => i.number === number);
            if (issue === undefined) return { type: 'Issue', value: null };
            return { type: 'Issue', value: { __type: 'Issue', repo, issue } satisfies GqlParent };
          }
          case 'issues': {
            const states = Array.isArray(args.states) ? (args.states as string[]) : null;
            const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
            const direction = orderBy.direction === 'ASC' ? 'ASC' : 'DESC';
            let items = [...repo.issues];
            if (states !== null) items = items.filter((i) => states.includes(i.state.toUpperCase()));
            const sliced = connectionSlice(items, args.first, args.after, 'issue', direction);
            return { type: 'IssueConnection', value: { __type: 'IssueConnection', repo, items: sliced.page, total: items.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
          case 'pullRequest': {
            const number = args.number as number | undefined;
            const pull = repo.pulls.find((p) => p.number === number);
            if (pull === undefined) return { type: 'PullRequest', value: null };
            return { type: 'PullRequest', value: { __type: 'PullRequest', repo, pull } satisfies GqlParent };
          }
          case 'pullRequests': {
            const states = Array.isArray(args.states) ? (args.states as string[]) : null;
            const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
            const direction = orderBy.direction === 'ASC' ? 'ASC' : 'DESC';
            let items = [...repo.pulls];
            if (states !== null) {
              items = items.filter((p) => {
                const state = p.merged ? 'MERGED' : p.state.toUpperCase();
                return states.includes(state);
              });
            }
            const sliced = connectionSlice(items, args.first, args.after, 'pr', direction);
            return { type: 'PullRequestConnection', value: { __type: 'PullRequestConnection', repo, items: sliced.page, total: items.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
        }
        break;
      }
      case 'Issue': {
        const { repo, issue } = parent as { repo: Repo; issue: Issue };
        switch (fieldName) {
          case 'id': return { type: 'ID', value: nodeId('Issue', `${repo.owner}/${repo.name}#${issue.number}`) };
          case 'number': return { type: 'Int', value: issue.number };
          case 'title': return { type: 'String', value: issue.title };
          case 'state': return { type: 'String', value: issue.state.toUpperCase() };
          case 'body': return { type: 'String', value: issue.body };
          case 'url': return { type: 'String', value: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}` };
          case 'author': return { type: 'User', value: { __type: 'User', login: issue.user, id: forge.viewer.id } satisfies GqlParent };
          case 'createdAt': return { type: 'String', value: issue.createdAt };
          case 'updatedAt': return { type: 'String', value: issue.updatedAt };
          case 'repository': return { type: 'Repository', value: { __type: 'Repository', repo } satisfies GqlParent };
          case 'labels': {
            const sliced = connectionSlice(issue.labels.map((l) => ({ ...l, seq: l.id })), args.first, args.after, 'label', 'ASC');
            return { type: 'LabelConnection', value: { __type: 'LabelConnection', items: sliced.page.map((l) => repo.labels.find((x) => x.id === l.id) as Label), total: issue.labels.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
          case 'comments': {
            const items = issue.comments.map((c) => ({ ...c, seq: c.id }));
            const sliced = connectionSlice(items, args.first, args.after, 'comment', 'ASC');
            return { type: 'CommentConnection', value: { __type: 'CommentConnection', repo, issue, items: sliced.page.map((c) => issue.comments.find((x) => x.id === c.id) as IssueComment), total: issue.comments.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
        }
        break;
      }
      case 'PullRequest': {
        const { repo, pull } = parent as { repo: Repo; pull: PullRequest };
        switch (fieldName) {
          case 'id': return { type: 'ID', value: nodeId('PullRequest', `${repo.owner}/${repo.name}#${pull.number}`) };
          case 'number': return { type: 'Int', value: pull.number };
          case 'title': return { type: 'String', value: pull.title };
          case 'state': return { type: 'String', value: pull.merged ? 'MERGED' : pull.state.toUpperCase() };
          case 'body': return { type: 'String', value: pull.body };
          case 'url': return { type: 'String', value: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}` };
          case 'author': return { type: 'User', value: { __type: 'User', login: pull.user, id: forge.viewer.id } satisfies GqlParent };
          case 'createdAt': return { type: 'String', value: pull.createdAt };
          case 'updatedAt': return { type: 'String', value: pull.updatedAt };
          case 'headRefName': return { type: 'String', value: pull.head };
          case 'baseRefName': return { type: 'String', value: pull.base };
          case 'mergeable': {
            // GitHub v4: MergeableState enum, not a boolean.
            const state = pull.state !== 'open' ? 'UNKNOWN' : forge.wouldConflict(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
            return { type: 'String', value: state };
          }
          case 'merged': return { type: 'Boolean', value: pull.merged };
          case 'repository': return { type: 'Repository', value: { __type: 'Repository', repo } satisfies GqlParent };
          case 'files': {
            const items = pull.files.map((f, index) => ({ ...f, seq: index + 1 }));
            const sliced = connectionSlice(items, args.first, args.after, 'file', 'ASC');
            return { type: 'PullRequestFileConnection', value: { __type: 'PullRequestFileConnection', items: sliced.page.map((f) => pull.files[f.seq - 1] as PullFile), total: pull.files.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
          case 'commits': {
            const items = pull.commits.map((oid, index) => ({ oid, seq: index + 1 }));
            const sliced = connectionSlice(items, args.first, args.after, 'commit', 'ASC');
            return { type: 'CommitConnection', value: { __type: 'CommitConnection', repo, items: sliced.page.map((c) => c.oid), total: pull.commits.length, hasNext: sliced.hasNext, startCursor: sliced.startCursor, endCursor: sliced.endCursor } satisfies GqlParent };
          }
        }
        break;
      }
      case 'User': {
        const user = parent as { login: string; id: number };
        switch (fieldName) {
          case 'id': return { type: 'ID', value: nodeId('User', user.id) };
          case 'login': return { type: 'String', value: user.login };
          case 'name': return { type: 'String', value: user.login };
          case 'url': return { type: 'String', value: `https://github.com/${user.login}` };
        }
        break;
      }
      case 'Ref': {
        const ref = parent as { name: string; oid: string | null };
        switch (fieldName) {
          case 'name': return { type: 'String', value: ref.name };
          case 'prefix': return { type: 'String', value: 'refs/heads/' };
          case 'target': {
            if (ref.oid === null) return { type: 'Commit', value: null };
            return { type: 'Commit', value: { __type: 'Commit', repo: this.findRepoByCommit(ref.oid), oid: ref.oid } satisfies GqlParent };
          }
        }
        break;
      }
      case 'IssueConnection': {
        const conn = parent as { repo: Repo; items: Issue[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'IssueList', value: conn.items.map((issue) => ({ __type: 'Issue', repo: conn.repo, issue }) satisfies GqlParent) };
          case 'edges': return { type: 'IssueEdgeList', value: conn.items.map((issue) => ({ __type: 'IssueEdge', repo: conn.repo, issue, cursor: cursorOf('issue', issue.seq) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'PullRequestConnection': {
        const conn = parent as { repo: Repo; items: PullRequest[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'PullRequestList', value: conn.items.map((pull) => ({ __type: 'PullRequest', repo: conn.repo, pull }) satisfies GqlParent) };
          case 'edges': return { type: 'PullRequestEdgeList', value: conn.items.map((pull) => ({ __type: 'PullRequestEdge', repo: conn.repo, pull, cursor: cursorOf('pr', pull.seq) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'IssueEdge': {
        const edge = parent as { repo: Repo; issue: Issue; cursor: string };
        if (fieldName === 'node') return { type: 'Issue', value: { __type: 'Issue', repo: edge.repo, issue: edge.issue } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'PullRequestEdge': {
        const edge = parent as { repo: Repo; pull: PullRequest; cursor: string };
        if (fieldName === 'node') return { type: 'PullRequest', value: { __type: 'PullRequest', repo: edge.repo, pull: edge.pull } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'PageInfo': {
        const info = parent as { hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'hasNextPage': return { type: 'Boolean', value: info.hasNext };
          case 'hasPreviousPage': return { type: 'Boolean', value: false };
          case 'startCursor': return { type: 'String', value: info.startCursor };
          case 'endCursor': return { type: 'String', value: info.endCursor };
        }
        break;
      }
      case 'CommentConnection': {
        const conn = parent as { repo: Repo; issue: Issue; items: IssueComment[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'CommentList', value: conn.items.map((comment) => ({ __type: 'Comment', repo: conn.repo, issue: conn.issue, comment }) satisfies GqlParent) };
          case 'edges': return { type: 'CommentEdgeList', value: conn.items.map((comment) => ({ __type: 'CommentEdge', repo: conn.repo, issue: conn.issue, comment, cursor: cursorOf('comment', comment.id) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'Comment': {
        const { repo, issue, comment } = parent as { repo: Repo; issue: Issue; comment: IssueComment };
        switch (fieldName) {
          case 'id': return { type: 'ID', value: nodeId('IssueComment', `${repo.owner}/${repo.name}#${issue.number}:${comment.id}`) };
          case 'body': return { type: 'String', value: comment.body };
          case 'author': return { type: 'User', value: { __type: 'User', login: comment.user, id: forge.viewer.id } satisfies GqlParent };
          case 'createdAt': return { type: 'String', value: comment.createdAt };
          case 'updatedAt': return { type: 'String', value: comment.updatedAt };
          case 'url': return { type: 'String', value: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}` };
        }
        break;
      }
      case 'CommentEdge': {
        const edge = parent as { repo: Repo; issue: Issue; comment: IssueComment; cursor: string };
        if (fieldName === 'node') return { type: 'Comment', value: { __type: 'Comment', repo: edge.repo, issue: edge.issue, comment: edge.comment } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'LabelConnection': {
        const conn = parent as { items: Label[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'LabelList', value: conn.items.map((label) => ({ __type: 'Label', label }) satisfies GqlParent) };
          case 'edges': return { type: 'LabelEdgeList', value: conn.items.map((label) => ({ __type: 'LabelEdge', label, cursor: cursorOf('label', label.id) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'Label': {
        const { label } = parent as { label: Label };
        switch (fieldName) {
          case 'id': return { type: 'ID', value: nodeId('Label', label.id) };
          case 'name': return { type: 'String', value: label.name };
          case 'color': return { type: 'String', value: label.color };
          case 'description': return { type: 'String', value: label.description };
        }
        break;
      }
      case 'LabelEdge': {
        const edge = parent as { label: Label; cursor: string };
        if (fieldName === 'node') return { type: 'Label', value: { __type: 'Label', label: edge.label } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'PullRequestFileConnection': {
        const conn = parent as { items: PullFile[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'PullRequestFileList', value: conn.items.map((file) => ({ __type: 'PullRequestFile', file }) satisfies GqlParent) };
          case 'edges': return { type: 'PullRequestFileEdgeList', value: conn.items.map((file, i) => ({ __type: 'PullRequestFileEdge', file, cursor: cursorOf('file', i + 1) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'PullRequestFile': {
        const { file } = parent as { file: PullFile };
        switch (fieldName) {
          case 'path': return { type: 'String', value: file.filename };
          case 'additions': return { type: 'Int', value: file.additions };
          case 'deletions': return { type: 'Int', value: file.deletions };
          case 'changes': return { type: 'Int', value: file.changes };
        }
        break;
      }
      case 'PullRequestFileEdge': {
        const edge = parent as { file: PullFile; cursor: string };
        if (fieldName === 'node') return { type: 'PullRequestFile', value: { __type: 'PullRequestFile', file: edge.file } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'CommitConnection': {
        const conn = parent as { repo: Repo; items: string[]; total: number; hasNext: boolean; startCursor: string | null; endCursor: string | null };
        switch (fieldName) {
          case 'nodes': return { type: 'CommitList', value: conn.items.map((oid) => ({ __type: 'Commit', repo: conn.repo, oid }) satisfies GqlParent) };
          case 'edges': return { type: 'CommitEdgeList', value: conn.items.map((oid, i) => ({ __type: 'CommitEdge', repo: conn.repo, oid, cursor: cursorOf('commit', i + 1) }) satisfies GqlParent) };
          case 'pageInfo': return { type: 'PageInfo', value: { __type: 'PageInfo', hasNext: conn.hasNext, startCursor: conn.startCursor, endCursor: conn.endCursor } satisfies GqlParent };
          case 'totalCount': return { type: 'Int', value: conn.total };
        }
        break;
      }
      case 'Commit': {
        const { repo, oid } = parent as { repo: Repo | null; oid: string };
        const obj = this.forge.store.get(oid);
        const parts = obj?.type === 'commit' ? parseCommit(obj.data) : null;
        switch (fieldName) {
          case 'oid': return { type: 'String', value: oid };
          case 'message': return { type: 'String', value: parts?.message ?? '' };
          case 'author': return { type: 'User', value: { __type: 'User', login: VIEWER_LOGIN, id: forge.viewer.id } satisfies GqlParent };
        }
        void repo;
        break;
      }
      case 'CommitEdge': {
        const edge = parent as { repo: Repo; oid: string; cursor: string };
        if (fieldName === 'node') return { type: 'Commit', value: { __type: 'Commit', repo: edge.repo, oid: edge.oid } satisfies GqlParent };
        if (fieldName === 'cursor') return { type: 'String', value: edge.cursor };
        break;
      }
      case 'CreateIssuePayload': {
        const payload = parent as { repo: Repo; issue: Issue | null };
        if (fieldName === 'issue') return { type: 'Issue', value: payload.issue === null ? null : { __type: 'Issue', repo: payload.repo, issue: payload.issue } satisfies GqlParent };
        if (fieldName === 'clientMutationId') return { type: 'String', value: null };
        break;
      }
      case 'CloseIssuePayload': {
        const payload = parent as { repo: Repo; issue: Issue | null };
        if (fieldName === 'issue') return { type: 'Issue', value: payload.issue === null ? null : { __type: 'Issue', repo: payload.repo, issue: payload.issue } satisfies GqlParent };
        if (fieldName === 'clientMutationId') return { type: 'String', value: null };
        break;
      }
      case 'CreatePullRequestPayload': {
        const payload = parent as { repo: Repo; pull: PullRequest | null };
        if (fieldName === 'pullRequest') return { type: 'PullRequest', value: payload.pull === null ? null : { __type: 'PullRequest', repo: payload.repo, pull: payload.pull } satisfies GqlParent };
        if (fieldName === 'clientMutationId') return { type: 'String', value: null };
        break;
      }
      case 'MergePullRequestPayload': {
        const payload = parent as { repo: Repo; pull: PullRequest | null };
        if (fieldName === 'pullRequest') return { type: 'PullRequest', value: payload.pull === null ? null : { __type: 'PullRequest', repo: payload.repo, pull: payload.pull } satisfies GqlParent };
        if (fieldName === 'clientMutationId') return { type: 'String', value: null };
        break;
      }
      case 'AddCommentPayload': {
        const payload = parent as { repo: Repo; issue: Issue | null; comment: IssueComment | null };
        if (fieldName === 'commentEdge') {
          if (payload.comment === null || payload.issue === null) return { type: 'CommentEdge', value: null };
          return { type: 'CommentEdge', value: { __type: 'CommentEdge', repo: payload.repo, issue: payload.issue, comment: payload.comment, cursor: cursorOf('comment', payload.comment.id) } satisfies GqlParent };
        }
        if (fieldName === 'subject') return { type: 'Issue', value: payload.issue === null ? null : { __type: 'Issue', repo: payload.repo, issue: payload.issue } satisfies GqlParent };
        if (fieldName === 'clientMutationId') return { type: 'String', value: null };
        break;
      }
      case '__Type': {
        const { name } = parent as { name: string };
        switch (fieldName) {
          case 'name': return { type: 'String', value: name };
          case 'kind': return { type: 'String', value: GQL_TYPE_KINDS[name] ?? 'OBJECT' };
          case 'description': return { type: 'String', value: null };
          case 'fields': {
            const fields = (GQL_TYPE_FIELDS[name] ?? []).map((f) => ({ __type: '__Field', name: f }) satisfies GqlParent);
            return { type: '__FieldList', value: fields };
          }
          case 'enumValues': {
            const values = (GQL_ENUM_VALUES[name] ?? []).map((v) => ({ __type: '__EnumValue', name: v }) satisfies GqlParent);
            return { type: '__EnumValueList', value: values };
          }
          case 'inputFields': return { type: '__InputValueList', value: [] };
          case 'possibleTypes': return { type: '__TypeList', value: [] };
        }
        break;
      }
      case '__Field': {
        const { name } = parent as { name: string };
        switch (fieldName) {
          case 'name': return { type: 'String', value: name };
          case 'description': return { type: 'String', value: null };
          case 'args': return { type: '__InputValueList', value: [] };
          case 'type': return { type: '__Type', value: { __type: '__Type', name: 'String' } satisfies GqlParent };
          case 'isDeprecated': return { type: 'Boolean', value: false };
          case 'deprecationReason': return { type: 'String', value: null };
        }
        break;
      }
      case '__InputValue': {
        const { name } = parent as { name: string };
        switch (fieldName) {
          case 'name': return { type: 'String', value: name };
          case 'description': return { type: 'String', value: null };
          case 'type': return { type: '__Type', value: { __type: '__Type', name: 'String' } satisfies GqlParent };
          case 'defaultValue': return { type: 'String', value: null };
        }
        break;
      }
      case '__EnumValue': {
        const { name } = parent as { name: string };
        switch (fieldName) {
          case 'name': return { type: 'String', value: name };
          case 'description': return { type: 'String', value: null };
          case 'isDeprecated': return { type: 'Boolean', value: false };
          case 'deprecationReason': return { type: 'String', value: null };
        }
        break;
      }
      case '__Schema': {
        switch (fieldName) {
          case 'queryType': return { type: '__Type', value: { __type: '__Type', name: 'Query' } satisfies GqlParent };
          case 'mutationType': return { type: '__Type', value: { __type: '__Type', name: 'Mutation' } satisfies GqlParent };
          case 'subscriptionType': return { type: '__Type', value: null };
          case 'types': {
            const types = Object.keys(GQL_TYPE_KINDS).map((name) => ({ __type: '__Type', name }) satisfies GqlParent);
            return { type: '__TypeList', value: types };
          }
          case 'directives': return { type: 'List', value: [] };
        }
        break;
      }
    }
    return new Error(`Cannot query field "${fieldName}" on type "${parentType}".`);
  }

  /** Execute a field's sub-selections over a resolved value (null, scalar, object, list). */
  private resolveSelectionSet(
    selectionSet: GqlSelection[] | null,
    resolved: { type: string; value: unknown } | Error,
    fragments: Map<string, GqlFragment>,
    variables: Record<string, unknown>,
    errors: Array<{ message: string }>,
  ): unknown {
    if (resolved instanceof Error) {
      errors.push({ message: resolved.message });
      return null;
    }
    const { type, value } = resolved;
    if (value === null || value === undefined) return null;
    if (selectionSet === null) return value;
    if (Array.isArray(value)) {
      return value.map((item) => {
        if (item !== null && typeof item === 'object' && '__type' in (item as Record<string, unknown>)) {
          const itemType = (item as { __type: string }).__type;
          const out: Record<string, unknown> = {};
          for (const selection of selectionSet) this.executeSelection(selection, itemType, item as GqlParent, fragments, variables, out, errors);
          return out;
        }
        return item;
      });
    }
    if (typeof value === 'object' && '__type' in (value as Record<string, unknown>)) {
      const out: Record<string, unknown> = {};
      const valueType = (value as { __type: string }).__type;
      for (const selection of selectionSet) this.executeSelection(selection, valueType, value as GqlParent, fragments, variables, out, errors);
      return out;
    }
    return value;
  }

  // --------------------------------------------------------------------- node ids

  private repoByNodeId(id: unknown): Repo | null {
    if (typeof id !== 'string') return null;
    const parsed = parseNodeId(id);
    if (parsed === null || parsed.kind !== 'Repository') return null;
    const num = Number(parsed.payload);
    if (!Number.isInteger(num)) return null;
    for (const repo of this.forge.repos.values()) {
      if (repo.id === num) return repo;
    }
    return null;
  }

  private labelNameByNodeId(repo: Repo, id: string): string | null {
    const parsed = parseNodeId(id);
    if (parsed === null || parsed.kind !== 'Label') return null;
    const num = Number(parsed.payload);
    if (!Number.isInteger(num)) return null;
    return repo.labels.find((l) => l.id === num)?.name ?? null;
  }

  private issueByNodeId(id: unknown): { repo: Repo; issue: Issue } | null {
    if (typeof id !== 'string') return null;
    const decoded = base64DecodeSafe(id);
    if (decoded === null || !decoded.startsWith('Issue:')) return null;
    const rest = decoded.slice('Issue:'.length);
    const hash = rest.lastIndexOf('#');
    if (hash < 0) return null;
    const repo = this.forge.getRepo(...splitOwnerName(rest.slice(0, hash)));
    if (repo === undefined) return null;
    const number = Number(rest.slice(hash + 1));
    const issue = repo.issues.find((i) => i.number === number);
    return issue === undefined ? null : { repo, issue };
  }

  private pullByNodeId(id: unknown): { repo: Repo; pull: PullRequest } | null {
    if (typeof id !== 'string') return null;
    const decoded = base64DecodeSafe(id);
    if (decoded === null || !decoded.startsWith('PullRequest:')) return null;
    const rest = decoded.slice('PullRequest:'.length);
    const hash = rest.lastIndexOf('#');
    if (hash < 0) return null;
    const repo = this.forge.getRepo(...splitOwnerName(rest.slice(0, hash)));
    if (repo === undefined) return null;
    const number = Number(rest.slice(hash + 1));
    const pull = repo.pulls.find((p) => p.number === number);
    return pull === undefined ? null : { repo, pull };
  }

  private resolveNode(id: string): { type: string; value: unknown } | Error {
    const decoded = base64DecodeSafe(id);
    if (decoded === null) return { type: 'Node', value: null };
    const colon = decoded.indexOf(':');
    if (colon < 0) return { type: 'Node', value: null };
    const kind = decoded.slice(0, colon);
    if (kind === 'Repository') {
      const repo = this.repoByNodeId(id);
      if (repo === null) return { type: 'Node', value: null };
      return { type: 'Repository', value: { __type: 'Repository', repo } satisfies GqlParent };
    }
    if (kind === 'Issue') {
      const found = this.issueByNodeId(id);
      if (found === null) return { type: 'Node', value: null };
      return { type: 'Issue', value: { __type: 'Issue', repo: found.repo, issue: found.issue } satisfies GqlParent };
    }
    if (kind === 'PullRequest') {
      const found = this.pullByNodeId(id);
      if (found === null) return { type: 'Node', value: null };
      return { type: 'PullRequest', value: { __type: 'PullRequest', repo: found.repo, pull: found.pull } satisfies GqlParent };
    }
    if (kind === 'User') {
      return { type: 'User', value: { __type: 'User', login: this.forge.viewer.login, id: this.forge.viewer.id } satisfies GqlParent };
    }
    return { type: 'Node', value: null };
  }

  private findRepoByCommit(oid: string): Repo | null {
    for (const repo of this.forge.repos.values()) {
      for (const refOid of repo.refs.values()) {
        if (refOid === oid) return repo;
      }
    }
    return null;
  }
}

function base64DecodeSafe(text: string): string | null {
  try {
    return base64Decode(text);
  } catch {
    return null;
  }
}

function splitOwnerName(text: string): [string, string] {
  const slash = text.indexOf('/');
  if (slash < 0) return [text, ''];
  return [text.slice(0, slash), text.slice(slash + 1)];
}

/** Execute one GraphQL operation body ({query, variables} or a batch array). */
export function handleGraphQL(forge: Forge, req: HttpRequest): HttpResult {
  if (req.token === null) return errorResult(401, 'Bad credentials');
  let body: unknown;
  try {
    body = JSON.parse(req.body.toString('utf8'));
  } catch {
    return errorResult(400, 'request body is not valid JSON');
  }
  const executor = new GqlExecutor(forge);
  const runOne = (operation: unknown): Record<string, unknown> => {
    if (operation === null || typeof operation !== 'object' || Array.isArray(operation)) {
      return { data: null, errors: [{ message: 'operation must be an object with a query string' }] };
    }
    const query = (operation as Record<string, unknown>).query;
    if (typeof query !== 'string' || query.trim() === '') {
      return { data: null, errors: [{ message: 'query is required' }] };
    }
    const variables = (operation as Record<string, unknown>).variables;
    const vars: Record<string, unknown> = variables !== null && typeof variables === 'object' && !Array.isArray(variables) ? (variables as Record<string, unknown>) : {};
    const operationName = (operation as Record<string, unknown>).operationName;
    let definitions: GqlDefinition[];
    try {
      definitions = new GqlParser(gqlTokenize(query)).parseDocument();
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL syntax error' }] };
    }
    const fragments = new Map<string, GqlFragment>();
    const operations: GqlOperation[] = [];
    for (const definition of definitions) {
      if (definition.kind === 'Fragment') fragments.set(definition.name, definition);
      else operations.push(definition);
    }
    if (operations.length === 0) return { data: null, errors: [{ message: 'no operation in document' }] };
    let chosen = operations[0] as GqlOperation;
    if (typeof operationName === 'string') {
      const named = operations.find((op) => op.name === operationName);
      if (named !== undefined) chosen = named;
    }
    const mergedVars: Record<string, unknown> = { ...vars };
    for (const variable of chosen.variables) {
      if (mergedVars[variable.name] === undefined && variable.defaultValue !== null) {
        mergedVars[variable.name] = evalGqlValue(variable.defaultValue, vars);
      }
    }
    return executor.executeOperation(chosen, fragments, mergedVars);
  };
  if (Array.isArray(body)) {
    return jsonResult(200, body.map(runOne));
  }
  return jsonResult(200, runOne(body));
}

// --------------------------------------------------------------------------- MCP

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' } }, required: ['name'] },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter', enum: ['open', 'closed', 'all'] },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(value: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
}
function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(forge: Forge, name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (tool === undefined) return { __rpcError: -32602, __rpcMessage: `unknown tool ${name}` };
  const required = (tool.inputSchema.required ?? []) as string[];
  for (const key of required) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return mcpToolError(`missing required argument: ${key}`);
    }
  }
  const str = (key: string): string => String(args[key] ?? '');
  switch (name) {
    case 'create_repo': {
      const created = forge.createRepo(str('name'), {});
      if ('error' in created) return mcpToolError(created.error);
      return mcpToolResult(repoJson(forge, created));
    }
    case 'get_repo': {
      const repo = forge.getRepo(str('owner'), str('repo'));
      if (repo === undefined) return mcpToolError('repository not found');
      return mcpToolResult(repoJson(forge, repo));
    }
    case 'create_issue': {
      const repo = forge.getRepo(str('owner'), str('repo'));
      if (repo === undefined) return mcpToolError('repository not found');
      const created = forge.createIssue(repo, str('title'), typeof args.body === 'string' ? args.body : '', []);
      if ('error' in created) return mcpToolError(created.error);
      return mcpToolResult(issueJson(forge, repo, created));
    }
    case 'list_issues': {
      const repo = forge.getRepo(str('owner'), str('repo'));
      if (repo === undefined) return mcpToolError('repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = state === 'all' ? [...repo.issues] : repo.issues.filter((i) => i.state === state);
      const value = { issues: list.map((i) => issueJson(forge, repo, i)) };
      return { content: [{ type: 'text', text: JSON.stringify(value.issues) }], structuredContent: value };
    }
    case 'create_pull_request': {
      const repo = forge.getRepo(str('owner'), str('repo'));
      if (repo === undefined) return mcpToolError('repository not found');
      const created = forge.createPull(repo, str('title'), typeof args.body === 'string' ? args.body : '', str('head'), str('base'));
      if ('error' in created) return mcpToolError(created.error);
      return mcpToolResult(pullJson(forge, repo, created));
    }
    case 'merge_pull_request': {
      const repo = forge.getRepo(str('owner'), str('repo'));
      if (repo === undefined) return mcpToolError('repository not found');
      const number = Number(args.pull_number);
      const merged = forge.mergePull(repo, number);
      if ('error' in merged) return mcpToolError(merged.error);
      return mcpToolResult({ merged: true, sha: merged.commitOid, message: 'Pull request merged' });
    }
    default:
      return mcpToolError(`unknown tool ${name}`);
  }
}

export function handleMcp(forge: Forge, req: HttpRequest): HttpResult {
  const rpcHeaders: Record<string, string> = { 'content-type': 'application/json', 'x-github-request-id': requestId() };
  const rpcError = (id: unknown, code: number, message: string, status = 200): HttpResult => ({
    status,
    headers: rpcHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }),
  });
  const rpcResult = (id: unknown, result: unknown): HttpResult => ({
    status: 200,
    headers: rpcHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result }),
  });
  if (req.token === null) {
    let id: unknown = null;
    try {
      const parsed = JSON.parse(req.body.toString('utf8')) as Record<string, unknown>;
      id = parsed.id ?? null;
    } catch {
      // No id recoverable.
    }
    return rpcError(id, -32000, 'unauthorized', 401);
  }
  let body: unknown;
  try {
    body = JSON.parse(req.body.toString('utf8'));
  } catch {
    return rpcError(null, -32700, 'Parse error', 400);
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return rpcError(null, -32600, 'Invalid Request', 400);
  }
  const record = body as Record<string, unknown>;
  const id = record.id ?? null;
  const method = record.method;
  if (typeof method !== 'string') return rpcError(id, -32600, 'Invalid Request', 400);
  if (id === null || id === undefined) {
    // Notification (no id): acknowledge, no body.
    return { status: 202, headers: rpcHeaders, body: '' };
  }
  const params = (record.params ?? {}) as Record<string, unknown>;
  switch (method) {
    case 'server/discover':
      return rpcResult(id, {
        resultType: 'discover',
        supportedVersions: ['2026-07-28', '2025-11-25'],
        capabilities: { tools: {} },
        instructions: 'A GitHub-compatible forge over MCP.',
        serverInfo: { name: 'forge-mcp', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge-mcp', version: '1.0.0' } },
      });
    case 'initialize':
      return rpcResult(id, {
        protocolVersion: '2026-07-28',
        capabilities: { tools: {} },
        serverInfo: { name: 'forge-mcp', version: '1.0.0' },
      });
    case 'ping':
      return rpcResult(id, {});
    case 'tools/list':
      return rpcResult(id, { tools: MCP_TOOLS });
    case 'tools/call': {
      const toolName = params.name;
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      if (typeof toolName !== 'string') return rpcError(id, -32602, 'tools/call requires a tool name');
      const result = mcpCallTool(forge, toolName, args);
      if ('__rpcError' in result) {
        return rpcError(id, result.__rpcError as number, String(result.__rpcMessage ?? 'error'));
      }
      return rpcResult(id, result);
    }
    default:
      return rpcError(id, -32601, `method not found: ${method}`);
  }
}

// --------------------------------------------------------------------------- HTTP server

function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function bearerToken(headers: Record<string, string | string[] | undefined>): string | null {
  const auth = headerValue(headers, 'authorization');
  if (auth === undefined) return null;
  const match = /^Bearer\s+(.+)$/.exec(auth.trim());
  return match === null ? null : (match[1] as string);
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > 64 * 1024 * 1024) throw new Error('request body too large');
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

async function dispatch(forge: Forge, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const body = await readBody(req);
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const headers: Record<string, string | string[] | undefined> = {};
    for (const [key, value] of Object.entries(req.headers)) headers[key.toLowerCase()] = value;
    const httpReq: HttpRequest = {
      method: (req.method ?? 'GET').toUpperCase(),
      pathname: url.pathname,
      query: url.searchParams,
      headers,
      host: req.headers.host ?? '127.0.0.1',
      token: bearerToken(headers),
      body,
    };
    let result: HttpResult | null = null;
    // Boot probe for the local runner and the sealed env.
    if (httpReq.pathname === '/healthz' && httpReq.method === 'GET') {
      result = jsonResult(200, { status: 'ok' });
    }
    // GraphQL.
    if (result === null && httpReq.pathname === '/api/graphql' && httpReq.method === 'POST') {
      result = handleGraphQL(forge, httpReq);
    }
    // MCP.
    if (result === null && httpReq.pathname === '/mcp' && httpReq.method === 'POST') {
      result = handleMcp(forge, httpReq);
    }
    // Git smart HTTP: /<owner>/<repo>/info/refs, /git-upload-pack, /git-receive-pack.
    if (result === null) {
      const gitMatch = /^\/([^/]+)\/([^/]+)\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(httpReq.pathname);
      if (gitMatch !== null) {
        const owner = decodeURIComponent(gitMatch[1] as string);
        // Smart-HTTP paths carry a ".git" suffix (/<owner>/<repo>.git/...); the
        // repository itself is registered without it.
        let name = decodeURIComponent(gitMatch[2] as string);
        if (name.endsWith('.git')) name = name.slice(0, -4);
        const service = gitMatch[3] as string;
        const repo = forge.getRepo(owner, name);
        if (repo === undefined) {
          result = errorResult(404, 'Not Found');
        } else if (repo.privateRepo && httpReq.token === null) {
          result = errorResult(401, 'Bad credentials');
        } else if (service === 'info/refs') {
          if (httpReq.method !== 'GET') {
            result = errorResult(405, 'Method Not Allowed');
          } else {
            const serviceParam = httpReq.query.get('service') ?? '';
            if (serviceParam !== 'git-upload-pack' && serviceParam !== 'git-receive-pack') {
              result = errorResult(400, 'service is required');
            } else {
              const wantV2 = headerValue(headers, 'git-protocol') === 'version=2' && serviceParam === 'git-upload-pack';
              const advert = advertisement(forge, repo, serviceParam, wantV2);
              result = { status: 200, headers: { 'content-type': advert.contentType, 'x-github-request-id': requestId() }, body: advert.body.toString('latin1') };
              res.writeHead(200, { 'content-type': advert.contentType, 'x-github-request-id': requestId() });
              res.end(advert.body);
              return;
            }
          }
        } else if (service === 'git-upload-pack') {
          if (httpReq.method !== 'POST') {
            result = errorResult(405, 'Method Not Allowed');
          } else {
            try {
              const out = handleUploadPack(forge, repo, body);
              res.writeHead(out.status, { 'content-type': out.contentType, 'x-github-request-id': requestId() });
              res.end(out.body);
              return;
            } catch (err) {
              console.error('upload-pack error:', err instanceof Error ? err.message : String(err));
              result = errorResult(400, err instanceof Error ? err.message : 'bad request');
            }
          }
        } else {
          if (httpReq.method !== 'POST') {
            result = errorResult(405, 'Method Not Allowed');
          } else if (httpReq.token === null) {
            result = errorResult(401, 'Bad credentials');
          } else {
            try {
              const out = handleReceivePack(forge, repo, body);
              res.writeHead(out.status, { 'content-type': out.contentType, 'x-github-request-id': requestId() });
              res.end(out.body);
              return;
            } catch (err) {
              console.error('receive-pack error:', err instanceof Error ? err.message : String(err));
              result = errorResult(400, err instanceof Error ? err.message : 'bad request');
            }
          }
        }
      }
    }
    // REST v3.
    if (result === null) result = handleRest(forge, httpReq);
    // Fallback: unknown route, JSON 404.
    if (result === null) result = errorResult(404, 'Not Found');
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    console.error('request error:', err instanceof Error ? err.message : String(err));
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json', 'x-github-request-id': requestId() });
      res.end(JSON.stringify({ message: 'Internal Server Error' }));
    } else {
      res.end();
    }
  }
}

export function createForgeServer(): http.Server {
  const forge = new Forge();
  return http.createServer((req, res) => {
    void dispatch(forge, req, res);
  });
}
