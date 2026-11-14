// forge.ts — an in-memory, single-process clone of GitHub's core surface:
// git smart HTTP (upload-pack v0/v2, receive-pack, ls-refs, shallow/deepen),
// REST v3 (repos, refs, branches, commits, contents, labels, issues, pulls,
// squash merge with real three-way conflict detection), GraphQL (parser +
// executor, introspection, batch, opaque global ids, cursor pagination), and
// MCP (era 2026-07-28 server/discover + legacy initialize, six tools).
//
// Dependency-free, no git binary. Run with:
//   node --experimental-strip-types main.ts
//
// Determinism: every timestamp served comes from a monotonic counter seeded
// at 2025-01-01T00:00:00Z, never from the wall clock; every id and number
// comes from a counter in creation order. The viewer is derived from the
// public scenario seed: adaiversen, id 1000.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const ZERO_OID = '0000000000000000000000000000000000000000';
export const DEFAULT_BRANCH = 'main';
/** 2025-01-01T00:00:00Z — the seed of the deterministic clock. */
const EPOCH_SEC = 1735689600;
const FORGE_AGENT = 'forge/1.0';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text: string): string {
  return Buffer.from(text, 'base64').toString('utf8');
}

/** Monotonic deterministic clock: seconds since the epoch, +1 per call. */
let clockSec = EPOCH_SEC;
export function nextTimestampSec(): number {
  const t = clockSec;
  clockSec += 1;
  return t;
}

export function isoOf(sec: number): string {
  return new Date(sec * 1000).toISOString();
}

/** A fresh ISO timestamp from the deterministic clock. */
export function nextIso(): string {
  return isoOf(nextTimestampSec());
}

/** Compare two strings by UTF-8 bytes (git's name order). */
function cmpBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

// ---------------------------------------------------------------------------
// pkt-line codec (git's framing: 4 hex digits = length incl. the 4 digits)
// ---------------------------------------------------------------------------

export function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), body]);
}

export const FLUSH = Buffer.from('0000', 'ascii');
export const DELIM = Buffer.from('0001', 'ascii');

/** Decode a buffer of pkt-lines into {lines, flushSeen}; throws on bad framing. */
export function decodePktLines(buf: Buffer): { lines: Buffer[]; flushSeen: boolean } {
  const lines: Buffer[] = [];
  let offset = 0;
  let flushSeen = false;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('pkt-line: truncated length');
    const hex = buf.subarray(offset, offset + 4).toString('ascii');
    if (hex === '0000') {
      flushSeen = true;
      offset += 4;
      break;
    }
    if (hex === '0001') {
      // Delim packet: a separator, not a data line.
      offset += 4;
      continue;
    }
    const len = parseInt(hex, 16);
    if (!Number.isFinite(len) || len < 4 || offset + len > buf.length) {
      throw new Error(`pkt-line: bad length ${hex}`);
    }
    lines.push(buf.subarray(offset + 4, offset + len));
    offset += len;
  }
  return { lines, flushSeen };
}

// ---------------------------------------------------------------------------
// Git object model (SHA-1): blob / tree / commit / tag
// ---------------------------------------------------------------------------

export type ObjectType = 'blob' | 'tree' | 'commit' | 'tag';

export function hashObject(type: ObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([header, data]));
}

export interface CommitParts {
  tree: string;
  parents: string[];
  authorName: string;
  authorEmail: string;
  authorTs: number;
  committerName: string;
  committerEmail: string;
  committerTs: number;
  message: string;
}

export function parseCommit(data: Buffer): CommitParts {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  const parts: CommitParts = {
    tree: '',
    parents: [],
    authorName: '',
    authorEmail: '',
    authorTs: 0,
    committerName: '',
    committerEmail: '',
    committerTs: 0,
    message,
  };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) parts.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parts.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ') || line.startsWith('committer ')) {
      const m = line.match(/^(author|committer) (.*) <(.*)> (\d+) ([+-]\d{4})$/);
      if (m) {
        const key = m[1] === 'author' ? 'author' : 'committer';
        parts[`${key}Name` as 'authorName' | 'committerName'] = m[2];
        parts[`${key}Email` as 'authorEmail' | 'committerEmail'] = m[3];
        parts[`${key}Ts` as 'authorTs' | 'committerTs'] = Number(m[4]);
      }
    }
  }
  return parts;
}

export function buildCommit(parts: CommitParts): Buffer {
  let out = `tree ${parts.tree}\n`;
  for (const p of parts.parents) out += `parent ${p}\n`;
  out += `author ${parts.authorName} <${parts.authorEmail}> ${parts.authorTs} +0000\n`;
  out += `committer ${parts.committerName} <${parts.committerEmail}> ${parts.committerTs} +0000\n`;
  out += '\n';
  out += parts.message.endsWith('\n') ? parts.message : `${parts.message}\n`;
  return Buffer.from(out, 'utf8');
}

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree: bad entry');
    const mode = data.subarray(offset, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) throw new Error('tree: bad entry');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Git's tree order: directory names compare as if suffixed with '/'. */
export function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const aName = a.mode === '40000' ? `${a.name}/` : a.name;
  const bName = b.mode === '40000' ? `${b.name}/` : b.name;
  return cmpBytes(aName, bName);
}

export function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const chunks: Buffer[] = [];
  for (const e of sorted) {
    chunks.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    chunks.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(chunks);
}

export interface TagParts {
  object: string;
  type: ObjectType;
  tag: string;
  taggerName: string;
  taggerEmail: string;
  taggerTs: number;
  message: string;
}

export function parseTag(data: Buffer): TagParts {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  const parts: TagParts = {
    object: '',
    type: 'commit',
    tag: '',
    taggerName: '',
    taggerEmail: '',
    taggerTs: 0,
    message,
  };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) parts.object = line.slice(7).trim();
    else if (line.startsWith('type ')) parts.type = line.slice(5).trim() as ObjectType;
    else if (line.startsWith('tag ')) parts.tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) {
      const m = line.match(/^tagger (.*) <(.*)> (\d+) ([+-]\d{4})$/);
      if (m) {
        parts.taggerName = m[1];
        parts.taggerEmail = m[2];
        parts.taggerTs = Number(m[3]);
      }
    }
  }
  return parts;
}

// ---------------------------------------------------------------------------
// Pack files: writer (plain objects, cached deflate) and reader (plain +
// OFS/REF delta), mirroring the pack format the SDK client speaks.
// ---------------------------------------------------------------------------

const PACK_TYPE_CODES: Record<ObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPES: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** Deflate output cached per oid — the clone workload deflates the same objects 50x. */
const deflateCache = new Map<string, Buffer>();

function deflateObject(oid: string, data: Buffer): Buffer {
  const hit = deflateCache.get(oid);
  if (hit) return hit;
  const out = deflateSync(data);
  deflateCache.set(oid, out);
  return out;
}

function writePackObjectHeader(code: number, size: number): Buffer {
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Serialize plain objects into a v2 pack. `objects` is a list of [oid, type, data]. */
export function writePack(objects: Array<[string, ObjectType, Buffer]>): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  const chunks: Buffer[] = [header];
  for (const [oid, type, data] of objects) {
    chunks.push(writePackObjectHeader(PACK_TYPE_CODES[type], data.length));
    chunks.push(deflateObject(oid, data));
  }
  const withoutTrailer = Buffer.concat(chunks);
  const trailer = createHash('sha1').update(withoutTrailer).digest();
  return Buffer.concat([withoutTrailer, trailer]);
}

/** Inflate one zlib stream at `offset`; returns the object and bytes consumed. */
function inflateAt(view: Buffer, offset: number): { data: Buffer; consumed: number } {
  // With {info:true} Node returns {buffer, engine}; on the zlib engine,
  // bytesWritten is the number of INPUT bytes consumed (the compressed size).
  const result = inflateSync(view.subarray(offset), { info: true }) as unknown as {
    buffer: Buffer;
    engine?: { bytesWritten?: number };
  };
  const consumed = result.engine?.bytesWritten ?? 0;
  if (consumed <= 0) throw new Error('pack: inflate consumed 0 bytes');
  return { data: result.buffer, consumed };
}

/** Apply a git delta stream to a base object, mirroring the SDK client. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[pos++];
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const srcSize = readVarint();
  if (srcSize !== base.length) throw new Error('pack: delta source size mismatch');
  const dstSize = readVarint();
  const out: Buffer[] = [];
  let written = 0;
  while (pos < delta.length) {
    const op = delta[pos++];
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      if (op & 0x01) offset = delta[pos++];
      if (op & 0x02) offset |= delta[pos++] << 8;
      if (op & 0x04) offset |= delta[pos++] << 16;
      if (op & 0x08) offset |= delta[pos++] << 24;
      if (op & 0x10) size = delta[pos++];
      if (op & 0x20) size |= delta[pos++] << 8;
      if (op & 0x40) size |= delta[pos++] << 16;
      if (size === 0) size = 0x10000;
      out.push(base.subarray(offset, offset + size));
      written += size;
    } else if (op !== 0) {
      out.push(delta.subarray(pos, pos + op));
      pos += op;
      written += op;
    } else {
      throw new Error('pack: invalid delta opcode 0');
    }
  }
  const data = Buffer.concat(out);
  if (data.length !== dstSize || written !== dstSize) throw new Error('pack: delta output size mismatch');
  return data;
}

/**
 * Parse a v2/v3 pack into a map oid -> {type, data}. Handles plain objects and
 * OFS/REF deltas (deltas resolve against objects in the same pack, or against
 * `external` when a thin pack references an object the server already has).
 */
export function readPack(
  buf: Buffer,
  external?: Map<string, { type: ObjectType; data: Buffer }>,
): Map<string, { type: ObjectType; data: Buffer }> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('pack: bad magic');
  }
  const count = buf.readUInt32BE(8);
  interface RawEntry {
    oid: string;
    type: ObjectType;
    data: Buffer;
    baseOid?: string;
    baseOffset?: number;
    isDelta: boolean;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let offset = 12;
  for (let i = 0; i < count; i++) {
    const entryOffset = offset;
    const first = buf[offset++];
    const code = (first >> 4) & 7;
    let size = first & 0x0f;
    let shift = 4;
    while (first & 0x80) {
      const byte = buf[offset++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    let baseOid: string | undefined;
    let baseOffset: number | undefined;
    if (code === 6) {
      // OFS_DELTA: base is `offset` bytes before this entry's header.
      let byte = buf[offset++];
      let base = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[offset++];
        base = ((base + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = entryOffset - base;
    } else if (code === 7) {
      baseOid = buf.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const { data, consumed } = inflateAt(buf, offset);
    offset += consumed;
    if (data.length !== size) throw new Error('pack: declared size mismatch');
    const entry: RawEntry = {
      oid: '',
      type: code <= 4 ? PACK_CODE_TYPES[code] : 'blob',
      data,
      baseOid,
      baseOffset,
      isDelta: code === 6 || code === 7,
    };
    if (!entry.isDelta) {
      entry.oid = hashObject(entry.type, data);
    }
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolved = new Map<string, { type: ObjectType; data: Buffer }>();
  const resolve = (entry: RawEntry, seen: Set<RawEntry>): { type: ObjectType; data: Buffer } => {
    if (entry.oid) {
      const hit = resolved.get(entry.oid);
      if (hit) return hit;
      const out = { type: entry.type, data: entry.data };
      resolved.set(entry.oid, out);
      return out;
    }
    if (seen.has(entry)) throw new Error('pack: delta cycle');
    seen.add(entry);
    let base: { type: ObjectType; data: Buffer };
    if (entry.baseOid) {
      base =
        resolved.get(entry.baseOid) ??
        external?.get(entry.baseOid) ??
        (() => {
          const rawBase = raw.find((r) => r.oid === entry.baseOid);
          if (!rawBase) throw new Error('pack: delta base missing');
          return resolve(rawBase, seen);
        })();
    } else if (entry.baseOffset !== undefined) {
      const rawBase = byOffset.get(entry.baseOffset);
      if (!rawBase) throw new Error('pack: delta base offset missing');
      base = resolve(rawBase, seen);
    } else {
      throw new Error('pack: delta without base');
    }
    const data = applyDelta(base.data, entry.data);
    const out = { type: base.type, data };
    entry.oid = hashObject(out.type, data);
    resolved.set(entry.oid, out);
    return out;
  };
  for (const entry of raw) resolve(entry, new Set());
  return resolved;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

export interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  user: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  seq: number;
}

export interface Comment {
  id: number;
  body: string;
  user: string;
  createdAt: string;
}

export interface PullRequest {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeCommitSha: string | null;
  mergedAt: string | null;
  user: string;
  createdAt: string;
  updatedAt: string;
  seq: number;
  /** Files changed by this PR, fixed at creation time (base tip -> head tip). */
  files: PullFile[];
}

export interface PullFile {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

export interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  /** oid -> {type, data} */
  objects: Map<string, { type: ObjectType; data: Buffer }>;
  /** refname -> oid */
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: PullRequest[];
  /** issue number -> comments */
  comments: Map<number, Comment[]>;
  /** shared issue+PR number counter */
  nextNumber: number;
  nextCommentId: number;
  nextLabelId: number;
  /** commit oid -> parent oids, parsed once and cached */
  commitParents: Map<string, string[]>;
  /** commit oid -> flattened path -> blob oid, cached */
  commitFiles: Map<string, Map<string, string>>;
}

const store = {
  repos: new Map<string, Repo>(),
  nextRepoId: 1,
  nextObjectId: 1,
  nextRequestId: 1,
  creationSeq: 1,
};

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

export function getRepo(owner: string, name: string): Repo | undefined {
  return store.repos.get(repoKey(owner, name));
}

export function getRepoById(id: number): Repo | undefined {
  for (const repo of store.repos.values()) if (repo.id === id) return repo;
  return undefined;
}

export function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: store.nextRepoId++,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdSeq: store.creationSeq++,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    comments: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    nextLabelId: 1,
    commitParents: new Map(),
    commitFiles: new Map(),
  };
  store.repos.set(repoKey(repo.owner, repo.name), repo);
  return repo;
}

export function deleteRepoRecord(repo: Repo): void {
  store.repos.delete(repoKey(repo.owner, repo.name));
}

export function listRepos(): Repo[] {
  return [...store.repos.values()].sort((a, b) => a.createdSeq - b.createdSeq);
}

// ---------------------------------------------------------------------------
// Git object helpers over a repo's object database
// ---------------------------------------------------------------------------

export function storeObject(repo: Repo, type: ObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

export function storeBlob(repo: Repo, data: Buffer): string {
  return storeObject(repo, 'blob', data);
}

export function getObject(repo: Repo, oid: string): { type: ObjectType; data: Buffer } | undefined {
  return repo.objects.get(oid);
}

/** Parents of a commit, parsed once and cached. */
export function commitParents(repo: Repo, oid: string): string[] {
  const cached = repo.commitParents.get(oid);
  if (cached) return cached;
  const obj = repo.objects.get(oid);
  const parents = obj && obj.type === 'commit' ? parseCommit(obj.data).parents : [];
  repo.commitParents.set(oid, parents);
  return parents;
}

/** Peel a tag (possibly nested) to the commit it points at. */
export function peelToCommit(repo: Repo, oid: string): { oid: string; type: ObjectType } {
  let cur = oid;
  for (let i = 0; i < 10; i++) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tag') return { oid: cur, type: obj?.type ?? 'commit' };
    cur = parseTag(obj.data).object;
  }
  return { oid: cur, type: 'commit' };
}

/** Flatten a tree into path -> blob oid (files only). */
export function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, string>): void {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, entry.oid);
  }
}

/** Flattened file map of a commit, cached per commit oid. */
export function commitFileMap(repo: Repo, commitOid: string): Map<string, string> {
  const cached = repo.commitFiles.get(commitOid);
  if (cached) return cached;
  const obj = repo.objects.get(commitOid);
  const out = new Map<string, string>();
  if (obj && obj.type === 'commit') flattenTree(repo, parseCommit(obj.data).tree, '', out);
  repo.commitFiles.set(commitOid, out);
  return out;
}

/**
 * Build nested tree objects from a flat path -> blob oid map, storing every
 * tree in the repo. Returns the root tree oid.
 */
export function buildTreeFromMap(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, blobOid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      let child = node.dirs.get(parts[i]);
      if (!child) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(parts[i], child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1], blobOid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Create a commit object (author = committer = viewer) and store it. */
export function createCommit(
  repo: Repo,
  treeOid: string,
  parents: string[],
  message: string,
): { oid: string; ts: number } {
  const ts = nextTimestampSec();
  const parts: CommitParts = {
    tree: treeOid,
    parents,
    authorName: VIEWER_NAME,
    authorEmail: VIEWER_EMAIL,
    authorTs: ts,
    committerName: VIEWER_NAME,
    committerEmail: VIEWER_EMAIL,
    committerTs: ts,
    message,
  };
  const oid = storeObject(repo, 'commit', buildCommit(parts));
  repo.commitParents.set(oid, [...parents]);
  return { oid, ts };
}

/** True when `ancestor` is reachable from `descendant` (or they are equal). */
export function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const anc = peelToCommit(repo, ancestor).oid;
  const desc = peelToCommit(repo, descendant).oid;
  if (anc === desc) return true;
  const seen = new Set<string>();
  const stack = [desc];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (cur === anc) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const p of commitParents(repo, cur)) stack.push(p);
  }
  return false;
}

/**
 * Merge-base of two commits: the deepest commit reachable from both.
 * Walks the base side into a set, then walks the head side newest-first.
 */
export function mergeBase(repo: Repo, headOid: string, baseOid: string): string | null {
  const head = peelToCommit(repo, headOid).oid;
  const base = peelToCommit(repo, baseOid).oid;
  const baseAncestors = new Set<string>();
  const stack = [base];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (baseAncestors.has(cur)) continue;
    baseAncestors.add(cur);
    for (const p of commitParents(repo, cur)) stack.push(p);
  }
  const seen = new Set<string>();
  const headStack = [head];
  while (headStack.length > 0) {
    const cur = headStack.pop() as string;
    if (baseAncestors.has(cur)) return cur;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const p of commitParents(repo, cur)) headStack.push(p);
  }
  return null;
}

/** Resolve a ref name, branch name, or raw oid to a commit oid (peeling tags). */
export function resolveRef(repo: Repo, ref: string): string | null {
  let oid: string | undefined;
  if (repo.refs.has(ref)) oid = repo.refs.get(ref);
  else if (repo.refs.has(`refs/heads/${ref}`)) oid = repo.refs.get(`refs/heads/${ref}`);
  else if (repo.refs.has(`refs/tags/${ref}`)) oid = repo.refs.get(`refs/tags/${ref}`);
  else if (repo.objects.has(ref)) oid = ref;
  else return null;
  return peelToCommit(repo, oid).oid;
}

/** All commits reachable from `tip`, newest-first (tip first, then parents). */
export function listCommitsFrom(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (seen.has(cur)) continue;
    seen.add(cur);
    out.push(cur);
    const parents = commitParents(repo, cur);
    for (let i = parents.length - 1; i >= 0; i--) stack.push(parents[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Line diff (LCS) for pull-request file stats
// ---------------------------------------------------------------------------

function splitLines(content: string): string[] {
  if (content === '') return [];
  const lines = content.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function diffLineCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const a = splitLines(oldText);
  const b = splitLines(newText);
  // LCS via a compact DP over the shorter dimension.
  const n = a.length;
  const m = b.length;
  let prev = new Array<number>(m + 1).fill(0);
  let curr = new Array<number>(m + 1).fill(0);
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      curr[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], curr[j - 1]);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
    curr.fill(0);
  }
  const lcs = prev[m];
  return { additions: b.length - lcs, deletions: a.length - lcs };
}

/** Diff two flattened file maps into per-file change records. */
export function diffFileMaps(
  repo: Repo,
  oldFiles: Map<string, string>,
  newFiles: Map<string, string>,
): PullFile[] {
  const out: PullFile[] = [];
  const paths = new Set<string>([...oldFiles.keys(), ...newFiles.keys()]);
  for (const path of [...paths].sort()) {
    const oldOid = oldFiles.get(path);
    const newOid = newFiles.get(path);
    if (oldOid === newOid) continue;
    if (oldOid === undefined) {
      const data = repo.objects.get(newOid as string)?.data.toString('utf8') ?? '';
      const additions = splitLines(data).length;
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (newOid === undefined) {
      const data = repo.objects.get(oldOid)?.data.toString('utf8') ?? '';
      const deletions = splitLines(data).length;
      out.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else {
      const oldText = repo.objects.get(oldOid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(newOid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = diffLineCounts(oldText, newText);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Three-way merge (squash) with real conflict detection
// ---------------------------------------------------------------------------

export interface MergeResult {
  ok: boolean;
  treeOid?: string;
  mergedFiles?: Map<string, string>;
  conflictPaths?: string[];
}

/**
 * Merge `headFiles` into `currentFiles` with `baseFiles` as the common
 * ancestor. A path conflicts when both sides changed it differently from base.
 */
export function threeWayMerge(
  repo: Repo,
  baseFiles: Map<string, string>,
  headFiles: Map<string, string>,
  currentFiles: Map<string, string>,
): MergeResult {
  const merged = new Map<string, string>();
  const conflicts: string[] = [];
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys(), ...currentFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const c = currentFiles.get(path);
    if (h === b) {
      if (c !== undefined) merged.set(path, c);
    } else if (c === b) {
      if (h !== undefined) merged.set(path, h);
    } else if (h === c) {
      if (h !== undefined) merged.set(path, h);
    } else {
      conflicts.push(path);
    }
  }
  if (conflicts.length > 0) return { ok: false, conflictPaths: conflicts.sort() };
  return { ok: true, treeOid: buildTreeFromMap(repo, merged), mergedFiles: merged };
}

/** Mergeability of a PR's head against its base tip, computed live. */
export function prMergeable(repo: Repo, pr: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headTip || !baseTip) return 'UNKNOWN';
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return 'UNKNOWN';
  const result = threeWayMerge(
    repo,
    commitFileMap(repo, base),
    commitFileMap(repo, peelToCommit(repo, headTip).oid),
    commitFileMap(repo, peelToCommit(repo, baseTip).oid),
  );
  return result.ok ? 'MERGEABLE' : 'CONFLICTING';
}

// ---------------------------------------------------------------------------
// Fetch computation: which objects to send, shallow info, unshallow info
// ---------------------------------------------------------------------------

export interface FetchPlan {
  /** Objects to send: [oid, type, data]. */
  objects: Array<[string, ObjectType, Buffer]>;
  shallow: string[];
  unshallow: string[];
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  deepen: number | null;
}

/** Closure of objects reachable from `roots` (commits + trees + blobs + tags). */
function reachableObjects(
  repo: Repo,
  roots: string[],
  stopAt: Set<string>,
): { commits: Set<string>; objects: Set<string> } {
  const commits = new Set<string>();
  const objects = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) {
    const obj = repo.objects.get(root);
    if (!obj) continue;
    if (obj.type === 'tag') {
      objects.add(root);
      const peeled = parseTag(obj.data).object;
      queue.push(peeled);
    } else if (obj.type === 'commit') {
      queue.push(root);
    } else {
      objects.add(root);
    }
  }
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (commits.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    commits.add(oid);
    objects.add(oid);
    const parts = parseCommit(obj.data);
    objects.add(parts.tree);
    const treeQueue = [parts.tree];
    while (treeQueue.length > 0) {
      const treeOid = treeQueue.pop() as string;
      const treeObj = repo.objects.get(treeOid);
      if (!treeObj || treeObj.type !== 'tree') continue;
      // Every tree in the closure counts as held, including subdirectories.
      objects.add(treeOid);
      for (const entry of parseTree(treeObj.data)) {
        if (entry.mode === '40000') treeQueue.push(entry.oid);
        else objects.add(entry.oid);
      }
    }
    if (stopAt.has(oid)) continue;
    for (const p of parts.parents) queue.push(p);
  }
  return { commits, objects };
}

/**
 * Compute the fetch plan.
 *
 * - `send` = objects reachable from wants within `deepen` generations,
 *   minus objects reachable from haves (whose closure stops at shallow
 *   boundaries — parents of a shallow commit are NOT assumed present).
 * - A want that is also a have still traverses its parents up to depth
 *   (the deepen case), because the subtraction happens at object level.
 * - `shallow` = frontier commits (at exactly `deepen` generations) plus old
 *   shallow boundaries that are still shallow; `unshallow` = old shallow
 *   boundaries whose parents are now included.
 */
export function planFetch(repo: Repo, req: FetchRequest): FetchPlan {
  const oldShallow = new Set(req.shallow);
  const depth = req.deepen;

  // Objects the client already has: closure of haves, stopping at shallow boundaries.
  const haveClosure = reachableObjects(repo, req.haves, oldShallow).objects;

  // Commits reachable from wants within the depth limit, with distances.
  const dist = new Map<string, number>();
  const queue: string[] = [];
  for (const want of req.wants) {
    const obj = repo.objects.get(want);
    if (!obj) continue;
    const peeled = obj.type === 'tag' ? peelToCommit(repo, want).oid : want;
    if (!dist.has(peeled)) {
      dist.set(peeled, 0);
      queue.push(peeled);
    }
  }
  // withinDepth: commits at distance < depth from a want (all of them when
  // depth is null). boundary: within-depth commits at distance depth-1 —
  // the deepest commits sent, i.e. the new shallow boundary. Commits at
  // distance >= depth are never sent and never expanded.
  const boundary = new Set<string>();
  const withinDepth = new Set<string>();
  while (queue.length > 0) {
    // Take the lowest-distance commit (small queue; linear scan is fine).
    let bestIdx = 0;
    for (let i = 1; i < queue.length; i++) {
      if ((dist.get(queue[i]) ?? 0) < (dist.get(queue[bestIdx]) ?? 0)) bestIdx = i;
    }
    const cur = queue.splice(bestIdx, 1)[0];
    const d = dist.get(cur) ?? 0;
    if (depth !== null && d >= depth) continue;
    withinDepth.add(cur);
    if (depth !== null && d === depth - 1) boundary.add(cur);
    for (const p of commitParents(repo, cur)) {
      if (!dist.has(p)) {
        dist.set(p, d + 1);
        queue.push(p);
      }
    }
  }

  // Objects to send: the within-depth commits plus their trees and blobs
  // (NOT their parents — a depth-limited fetch never sends parent commits),
  // plus any wanted tag objects, minus what the client already has.
  const sendSet = new Set<string>();
  for (const commitOid of withinDepth) {
    sendSet.add(commitOid);
    const obj = repo.objects.get(commitOid);
    if (!obj || obj.type !== 'commit') continue;
    const parts = parseCommit(obj.data);
    const treeQueue = [parts.tree];
    while (treeQueue.length > 0) {
      const treeOid = treeQueue.pop() as string;
      if (sendSet.has(treeOid)) continue;
      sendSet.add(treeOid);
      const treeObj = repo.objects.get(treeOid);
      if (!treeObj || treeObj.type !== 'tree') continue;
      for (const entry of parseTree(treeObj.data)) {
        if (entry.mode === '40000') treeQueue.push(entry.oid);
        else sendSet.add(entry.oid);
      }
    }
  }
  for (const want of req.wants) {
    const obj = repo.objects.get(want);
    if (obj && obj.type === 'tag') sendSet.add(want);
  }
  const objects: Array<[string, ObjectType, Buffer]> = [];
  for (const oid of sendSet) {
    if (haveClosure.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) objects.push([oid, obj.type, obj.data]);
  }
  // Deterministic pack order: commits, then trees, then blobs, then tags, by oid.
  const typeRank: Record<ObjectType, number> = { commit: 0, tree: 1, blob: 2, tag: 3 };
  objects.sort((a, b) => typeRank[a[1]] - typeRank[b[1]] || (a[0] < b[0] ? -1 : 1));

  // A boundary commit is shallow (its parents were cut off by the depth
  // limit). An old shallow boundary whose parents are now included — i.e.
  // it is within depth but not on the boundary — becomes unshallow. Any
  // other old shallow boundary stays shallow.
  const unshallow: string[] = [];
  const shallow = new Set<string>(boundary);
  for (const b of oldShallow) {
    if (withinDepth.has(b) && !boundary.has(b)) unshallow.push(b);
    else shallow.add(b);
  }
  return { objects, shallow: [...shallow].sort(), unshallow: unshallow.sort() };
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

interface RefEntry {
  oid: string;
  name: string;
  peeled?: string;
  symrefTarget?: string;
  unborn?: boolean;
}

function listRefEntries(repo: Repo): RefEntry[] {
  const out: RefEntry[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (headOid) {
    out.push({ oid: headOid, name: 'HEAD', symrefTarget: headTarget });
  } else {
    out.push({ oid: ZERO_OID, name: 'HEAD', symrefTarget: headTarget, unborn: true });
  }
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const entry: RefEntry = { oid, name };
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'tag') {
      entry.peeled = peelToCommit(repo, oid).oid;
    }
    out.push(entry);
  }
  return out;
}

function uploadPackV0Caps(repo: Repo): string {
  return `symref=HEAD:refs/heads/${repo.defaultBranch} side-band-64k thin-pack ofs-delta shallow multi_ack agent=${FORGE_AGENT}`;
}

function receivePackV0Caps(): string {
  return `report-status side-band-64k delete-refs ofs-delta agent=${FORGE_AGENT}`;
}

/** GET /{owner}/{repo}.git/info/refs?service=git-upload-pack|git-receive-pack */
function handleInfoRefs(
  repo: Repo,
  service: string | null,
  isV2: boolean,
): { status: number; contentType: string; body: Buffer } {
  if (service === 'git-upload-pack') {
    if (isV2) {
      const lines = [
        'version 2\n',
        'ls-refs=unborn\n',
        'fetch=shallow thin-pack ofs-delta\n',
        'object-format=sha1\n',
        `agent=${FORGE_AGENT}\n`,
      ];
      const body = Buffer.concat([...lines.map((l) => pktLine(l)), FLUSH]);
      return { status: 200, contentType: 'application/x-git-upload-pack-advertisement', body };
    }
    const chunks: Buffer[] = [pktLine('# service=git-upload-pack\n'), FLUSH];
    const entries = listRefEntries(repo);
    const caps = uploadPackV0Caps(repo);
    entries.forEach((entry, idx) => {
      let line = `${entry.oid} ${entry.name}`;
      if (idx === 0) line += `\0${caps}`;
      chunks.push(pktLine(`${line}\n`));
      if (entry.peeled) chunks.push(pktLine(`${entry.peeled} ${entry.name}^{}\n`));
    });
    if (entries.length === 0) {
      chunks.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    }
    chunks.push(FLUSH);
    return { status: 200, contentType: 'application/x-git-upload-pack-advertisement', body: Buffer.concat(chunks) };
  }
  if (service === 'git-receive-pack') {
    if (isV2) {
      const lines = [
        'version 2\n',
        'fetch=shallow\n',
        'object-format=sha1\n',
        `agent=${FORGE_AGENT}\n`,
      ];
      const body = Buffer.concat([...lines.map((l) => pktLine(l)), FLUSH]);
      return { status: 200, contentType: 'application/x-git-receive-pack-advertisement', body };
    }
    const chunks: Buffer[] = [pktLine('# service=git-receive-pack\n'), FLUSH];
    const entries = listRefEntries(repo);
    const caps = receivePackV0Caps();
    // Receive-pack advertisement lists refs without a HEAD line.
    const refEntries = entries.filter((e) => e.name !== 'HEAD');
    refEntries.forEach((entry, idx) => {
      let line = `${entry.oid} ${entry.name}`;
      if (idx === 0) line += `\0${caps}`;
      chunks.push(pktLine(`${line}\n`));
      if (entry.peeled) chunks.push(pktLine(`${entry.peeled} ${entry.name}^{}\n`));
    });
    if (refEntries.length === 0) {
      chunks.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    }
    chunks.push(FLUSH);
    return { status: 200, contentType: 'application/x-git-receive-pack-advertisement', body: Buffer.concat(chunks) };
  }
  return { status: 404, contentType: 'application/json', body: Buffer.from(JSON.stringify({ message: 'Not Found' })) };
}

/** Parse a v2 command request body into {command, argsBeforeDelim, argsAfterDelim}. */
function parseV2Command(body: Buffer): { command: string; args: string[] } {
  const { lines } = decodePktLines(body);
  const texts = lines.map((l) => l.toString('utf8'));
  const commandLine = texts.find((t) => t.startsWith('command='));
  if (!commandLine) throw new Error('v2: missing command');
  const command = commandLine.slice('command='.length).trim();
  const args = texts.filter((t) => !t.startsWith('command=') && !t.startsWith('agent=') && !t.startsWith('object-format='));
  return { command, args: args.map((t) => t.trim()) };
}

/** POST /{owner}/{repo}.git/git-upload-pack — ls-refs and fetch, v2 and v0. */
function handleUploadPack(repo: Repo, body: Buffer, isV2: boolean): { status: number; contentType: string; body: Buffer } {
  if (isV2) {
    const { command, args } = parseV2Command(body);
    if (command === 'ls-refs') {
      const peel = args.includes('peel');
      const symrefs = args.includes('symrefs');
      const unborn = args.includes('unborn');
      const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
      const chunks: Buffer[] = [];
      for (const entry of listRefEntries(repo)) {
        if (prefixes.length > 0 && !prefixes.some((p) => entry.name.startsWith(p))) continue;
        if (entry.unborn && !unborn) continue;
        let line: string;
        if (entry.unborn) {
          line = `unborn ${entry.name}`;
          if (symrefs && entry.symrefTarget) line += ` symref-target:${entry.symrefTarget}`;
        } else {
          line = `${entry.oid} ${entry.name}`;
          if (symrefs && entry.symrefTarget) line += ` symref-target:${entry.symrefTarget}`;
          if (peel && entry.peeled) line += ` peeled:${entry.peeled}`;
        }
        chunks.push(pktLine(`${line}\n`));
      }
      chunks.push(FLUSH);
      return { status: 200, contentType: 'application/x-git-upload-pack-result', body: Buffer.concat(chunks) };
    }
    if (command === 'fetch') {
      const req: FetchRequest = { wants: [], haves: [], shallow: [], deepen: null };
      for (const arg of args) {
        if (arg.startsWith('want ')) req.wants.push(arg.slice(5).trim());
        else if (arg.startsWith('have ')) req.haves.push(arg.slice(5).trim());
        else if (arg.startsWith('shallow ')) req.shallow.push(arg.slice(8).trim());
        else if (arg.startsWith('deepen ')) req.deepen = Number(arg.slice(7).trim());
      }
      const plan = planFetch(repo, req);
      const chunks: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), FLUSH];
      if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
        chunks.push(pktLine('shallow-info\n'));
        for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
        for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
        chunks.push(FLUSH);
      }
      if (plan.objects.length > 0) {
        chunks.push(pktLine('packfile\n'));
        const pack = writePack(plan.objects);
        for (let off = 0; off < pack.length; off += 32768) {
          const slice = pack.subarray(off, Math.min(pack.length, off + 32768));
          chunks.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
        }
        chunks.push(FLUSH);
      }
      return { status: 200, contentType: 'application/x-git-upload-pack-result', body: Buffer.concat(chunks) };
    }
    throw new Error(`v2: unknown command ${command}`);
  }

  // v0 fetch: wants (caps on the first line), shallow/deepen, flush, haves, done.
  const { lines, flushSeen } = decodePktLines(body);
  const texts = lines.map((l) => l.toString('utf8'));
  const req: FetchRequest = { wants: [], haves: [], shallow: [], deepen: null };
  let seenFlush = false;
  for (const text of texts) {
    const line = text.includes('\0') ? text.slice(0, text.indexOf('\0')) : text;
    const trimmed = line.trim();
    if (trimmed === 'done') continue;
    if (trimmed.startsWith('want ')) req.wants.push(trimmed.slice(5).trim());
    else if (trimmed.startsWith('shallow ')) req.shallow.push(trimmed.slice(8).trim());
    else if (trimmed.startsWith('deepen ')) req.deepen = Number(trimmed.slice(7).trim());
    else if (trimmed.startsWith('have ')) req.haves.push(trimmed.slice(5).trim());
  }
  void seenFlush;
  void flushSeen;
  const plan = planFetch(repo, req);
  const chunks: Buffer[] = [pktLine('NAK\n')];
  for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
  if (plan.objects.length > 0) {
    const pack = writePack(plan.objects);
    for (let off = 0; off < pack.length; off += 32768) {
      const slice = pack.subarray(off, Math.min(pack.length, off + 32768));
      chunks.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
    }
  }
  chunks.push(FLUSH);
  return { status: 200, contentType: 'application/x-git-upload-pack-result', body: Buffer.concat(chunks) };
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

/** POST /{owner}/{repo}.git/git-receive-pack — unpack a pack, apply ref updates. */
function handleReceivePack(
  repo: Repo,
  body: Buffer,
): { status: number; contentType: string; body: Buffer } {
  // Parse command pkt-lines until the flush; the pack follows the flush.
  const commands: PushCommand[] = [];
  let caps = '';
  let offset = 0;
  let packStart = body.length;
  while (offset + 4 <= body.length) {
    const hex = body.subarray(offset, offset + 4).toString('ascii');
    if (hex === '0000') {
      packStart = offset + 4;
      break;
    }
    const len = parseInt(hex, 16);
    if (!Number.isFinite(len) || len < 4 || offset + len > body.length) throw new Error('receive-pack: bad pkt-line');
    const line = body.subarray(offset + 4, offset + len).toString('utf8');
    const nul = line.indexOf('\0');
    const cmdText = nul >= 0 ? line.slice(0, nul) : line;
    if (nul >= 0 && caps === '') caps = line.slice(nul + 1);
    const parts = cmdText.trim().split(' ');
    if (parts.length >= 3) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
    offset += len;
  }
  const sideband = caps.includes('side-band-64k');
  const reportLines: string[] = [];
  let unpackOk = true;
  const packBytes = body.subarray(packStart);
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch {
      unpackOk = false;
    }
  }
  if (!unpackOk) {
    reportLines.push('unpack error\n');
  } else {
    reportLines.push('unpack ok\n');
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      const currentOid = current ?? ZERO_OID;
      let reason: string | null = null;
      if (cmd.oldOid !== currentOid) {
        reason = 'non-fast-forward';
      } else if (cmd.newOid === ZERO_OID) {
        // Delete.
      } else if (cmd.oldOid === ZERO_OID) {
        // Create: the new object must exist.
        if (!repo.objects.has(cmd.newOid)) reason = 'non-fast-forward';
      } else if (cmd.ref.startsWith('refs/tags/')) {
        // Tag update: old matched, allow.
      } else if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) {
        reason = 'non-fast-forward';
      }
      if (reason) {
        reportLines.push(`ng ${cmd.ref} ${reason}\n`);
      } else {
        if (cmd.newOid === ZERO_OID) repo.refs.delete(cmd.ref);
        else repo.refs.set(cmd.ref, cmd.newOid);
        reportLines.push(`ok ${cmd.ref}\n`);
      }
    }
  }
  const reportStream = Buffer.concat(reportLines.map((l) => pktLine(l)));
  let responseBody: Buffer;
  if (sideband) {
    const chunks: Buffer[] = [];
    for (let off = 0; off < reportStream.length; off += 32768) {
      const slice = reportStream.subarray(off, Math.min(reportStream.length, off + 32768));
      chunks.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
    }
    chunks.push(FLUSH);
    responseBody = Buffer.concat(chunks);
  } else {
    responseBody = Buffer.concat([reportStream, FLUSH]);
  }
  return { status: 200, contentType: 'application/x-git-receive-pack-result', body: responseBody };
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

function isAuthorized(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const token = h.slice('Bearer '.length).trim();
  if (token === '') return false;
  if (SHOP_TOKEN !== '') return token === SHOP_TOKEN;
  return true;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function requestId(): string {
  return `forge-${store.nextRequestId++}`;
}

function sendJson(res: ServerResponse, status: number, value: unknown, extra?: Record<string, string>): void {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-github-request-id': requestId(),
    ...extra,
  });
  res.end(body);
}

function sendRestError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function parseJsonBody(body: Buffer): unknown {
  if (body.length === 0) return {};
  return JSON.parse(body.toString('utf8'));
}

function viewerJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: b64encode(`User:${VIEWER_ID}`),
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    type: 'User',
    site_admin: false,
    html_url: `https://example.invalid/${VIEWER_LOGIN}`,
    url: `/api/v3/users/${VIEWER_LOGIN}`,
  };
}

function repoJson(repo: Repo): Record<string, unknown> {
  const createdAt = isoOf(EPOCH_SEC + repo.createdSeq);
  return {
    id: repo.id,
    node_id: b64encode(`Repository:${repo.id}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: createdAt,
    updated_at: createdAt,
    pushed_at: createdAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    git_url: `git://example.invalid/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@example.invalid:${repo.owner}/${repo.name}.git`,
    fork: false,
    archived: false,
    disabled: false,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return { id: label.id, name: label.name, color: label.color, description: label.description };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: b64encode(`Issue:${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map(labelJson),
    user: { login: issue.user, id: VIEWER_ID, type: 'User' },
    assignee: null,
    assignees: [],
    locked: false,
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}

function pullJson(repo: Repo, pr: PullRequest): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: b64encode(`PullRequest:${repo.id}:${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    mergeable: prMergeable(repo, pr) === 'MERGEABLE',
    head: { ref: pr.headRef, sha: pr.headSha, label: `${repo.owner}:${pr.headRef}` },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${repo.owner}:${pr.baseRef}` },
    user: { login: pr.user, id: VIEWER_ID, type: 'User' },
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
    closed_at: pr.mergedAt,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
  };
}

function commentJson(repo: Repo, issueNumber: number, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: b64encode(`IssueComment:${repo.id}:${issueNumber}:${comment.id}`),
    body: comment.body,
    user: { login: comment.user, id: VIEWER_ID, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issueNumber}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issueNumber}/comments/${comment.id}`,
  };
}

function commitDisplayMessage(data: Buffer): string {
  const msg = parseCommit(data).message;
  return msg.endsWith('\n') ? msg.slice(0, -1) : msg;
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const obj = repo.objects.get(oid);
  const parts = obj ? parseCommit(obj.data) : null;
  const message = obj ? commitDisplayMessage(obj.data) : '';
  const author = {
    name: parts?.authorName ?? VIEWER_NAME,
    email: parts?.authorEmail ?? VIEWER_EMAIL,
    date: isoOf(parts?.authorTs ?? EPOCH_SEC),
  };
  const committer = {
    name: parts?.committerName ?? VIEWER_NAME,
    email: parts?.committerEmail ?? VIEWER_EMAIL,
    date: isoOf(parts?.committerTs ?? EPOCH_SEC),
  };
  return {
    sha: oid,
    node_id: b64encode(`Commit:${repo.id}:${oid}`),
    commit: { message, author, committer, tree: { sha: parts?.tree ?? ZERO_OID } },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    parents: (parts?.parents ?? []).map((p) => ({ sha: p })),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

/** Paginate a list; returns the page and a Link header value (or null). */
function paginate<T>(items: T[], url: URL, req: IncomingMessage): { page: T[]; link: string | null } {
  const perPageRaw = Number(url.searchParams.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const pageRaw = Number(url.searchParams.get('page') ?? '1');
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const base = `http://${req.headers.host}${url.pathname}`;
  const links: string[] = [];
  if (page < totalPages) links.push(`<${base}?per_page=${perPage}&page=${page + 1}>; rel="next"`);
  if (totalPages > 1) links.push(`<${base}?per_page=${perPage}&page=${totalPages}>; rel="last"`);
  if (page > 1) links.push(`<${base}?per_page=${perPage}&page=1>; rel="first"`);
  return { page: items.slice(start, start + perPage), link: links.length > 0 ? links.join(', ') : null };
}

function linkHeader(link: string | null): Record<string, string> {
  return link ? { link } : {};
}

/** Tree oid of the directory at `path` inside a commit ('' = root tree). */
function subtreeOid(repo: Repo, commitOid: string, path: string): string | null {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return null;
  if (path === '') return parseCommit(obj.data).tree;
  const files = commitFileMap(repo, commitOid);
  const sub = new Map<string, string>();
  for (const [p, oid] of files) {
    if (p.startsWith(`${path}/`)) sub.set(p.slice(path.length + 1), oid);
  }
  if (sub.size === 0) return null;
  return buildTreeFromMap(repo, sub);
}

/** Commit a new file-tree state on a branch; returns the new commit oid. */
function commitFileState(
  repo: Repo,
  branch: string,
  files: Map<string, string>,
  message: string,
  parentOverride?: string,
): string {
  const tipRef = `refs/heads/${branch}`;
  const tip = repo.refs.get(tipRef);
  // A branch that does not exist yet starts from its parent override
  // (the default branch tip), not from a root commit.
  const parents = tip ? [peelToCommit(repo, tip).oid] : parentOverride ? [parentOverride] : [];
  const treeOid = buildTreeFromMap(repo, files);
  const { oid } = createCommit(repo, treeOid, parents, message);
  repo.refs.set(tipRef, oid);
  return oid;
}

interface RestCtx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  method: string;
  segments: string[];
  body: Buffer;
}

/** The /api/v3/* dispatcher. Returns true when it handled the request. */
async function handleRest(ctx: RestCtx): Promise<boolean> {
  const { req, res, url, method } = ctx;
  const seg = ctx.segments; // segments after /api/v3
  const q = url.searchParams;

  const needRepo = (): Repo | null => {
    const owner = seg[1] ?? '';
    const name = seg[2] ?? '';
    const repo = getRepo(owner, name);
    return repo ?? null;
  };
  const repoOr404 = (): Repo | null => {
    const repo = needRepo();
    if (!repo) sendRestError(res, 404, 'Not Found');
    return repo;
  };

  // GET /api/v3/
  if (seg.length === 0) {
    if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      user_url: '/api/v3/users/{user}',
      repository_url: '/api/v3/repos/{owner}/{repo}',
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  // GET /api/v3/meta
  if (seg.length === 1 && seg[0] === 'meta') {
    if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
    sendJson(res, 200, { installed_version: '1.0.0' });
    return true;
  }

  // GET /api/v3/user, GET/POST /api/v3/user/repos
  if (seg[0] === 'user') {
    if (seg.length === 1) {
      if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
      sendJson(res, 200, viewerJson());
      return true;
    }
    if (seg.length === 2 && seg[1] === 'repos') {
      if (method === 'GET') {
        const { page, link } = paginate(listRepos().map(repoJson), url, req);
        sendJson(res, 200, page, linkHeader(link));
        return true;
      }
      if (method === 'POST') {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        const name = typeof input.name === 'string' ? input.name : '';
        if (name === '') return sendRestError(res, 422, 'Validation Failed: name is required'), true;
        if (getRepo(VIEWER_LOGIN, name)) {
          return sendRestError(res, 422, 'Repository already exists'), true;
        }
        const repo = createRepoRecord(
          name,
          input.private === true,
          typeof input.description === 'string' ? input.description : '',
        );
        sendJson(res, 201, repoJson(repo));
        return true;
      }
    }
    return sendRestError(res, 404, 'Not Found'), true;
  }

  // /api/v3/repos/{owner}/{repo}[/*]
  if (seg[0] === 'repos' && seg.length >= 3) {
    const repo = repoOr404();
    if (!repo) return true;
    const rest = seg.slice(3);

    // GET/PATCH/DELETE /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (typeof input.description === 'string') repo.description = input.description;
        if (input.private === true || input.private === false) repo.isPrivate = input.private;
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        deleteRepoRecord(repo);
        res.writeHead(204, { 'x-github-request-id': requestId() });
        res.end();
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // branches
    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const out = [...repo.refs.keys()]
          .filter((n) => n.startsWith('refs/heads/'))
          .sort()
          .map((n) => ({
            name: n.slice('refs/heads/'.length),
            commit: { sha: repo.refs.get(n) as string },
            protected: false,
          }));
        sendJson(res, 200, out);
        return true;
      }
      if (rest.length >= 2 && method === 'GET') {
        const branch = decodeURIComponent(rest.slice(1).join('/'));
        const oid = repo.refs.get(`refs/heads/${branch}`);
        if (!oid) return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, { name: branch, commit: { sha: oid }, protected: false });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        const ref = typeof input.ref === 'string' ? input.ref : '';
        const sha = typeof input.sha === 'string' ? input.sha : '';
        if (!ref.startsWith('refs/') || sha === '') {
          return sendRestError(res, 422, 'Validation Failed'), true;
        }
        if (repo.refs.has(ref)) return sendRestError(res, 422, 'Reference already exists'), true;
        const peeled = resolveRef(repo, sha);
        if (peeled === null) return sendRestError(res, 422, 'Validation Failed: sha does not exist'), true;
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
        return true;
      }
      if (method === 'GET' && rest.length >= 3) {
        const ref = `refs/${decodeURIComponent(rest.slice(2).join('/'))}`;
        const oid = repo.refs.get(ref);
        if (!oid) return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, { ref, object: { sha: oid, type: 'commit' } });
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const out = [...repo.refs.keys()].sort().map((n) => ({ ref: n, object: { sha: repo.refs.get(n) as string, type: 'commit' } }));
        sendJson(res, 200, out);
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // commits
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = q.get('sha');
      const tip = shaParam ? resolveRef(repo, shaParam) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (!tip) {
        sendJson(res, 200, []);
        return true;
      }
      const out = listCommitsFrom(repo, tip).map((oid) => commitJson(repo, oid));
      const { page, link } = paginate(out, url, req);
      sendJson(res, 200, page, linkHeader(link));
      return true;
    }

    // contents
    if (rest[0] === 'contents') {
      const path = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      const refParam = q.get('ref');
      const resolveBranch = (): string | null => {
        if (refParam) {
          const tip = resolveRef(repo, refParam);
          if (tip === null) return null;
          return refParam;
        }
        return repo.defaultBranch;
      };
      if (method === 'GET') {
        const branch = resolveBranch();
        if (branch === null) return sendRestError(res, 404, 'Not Found'), true;
        const tip = resolveRef(repo, branch);
        if (!tip) return sendRestError(res, 404, 'Not Found'), true;
        const files = commitFileMap(repo, tip);
        if (path === '') {
          // Root listing.
          const children = new Map<string, { dir: boolean; oid: string }>();
          for (const [p, oid] of files) {
            const first = p.split('/')[0];
            if (p.includes('/')) {
              if (!children.has(first)) {
                const dirOid = subtreeOid(repo, tip, first);
                if (dirOid) children.set(first, { dir: true, oid: dirOid });
              }
            } else {
              children.set(first, { dir: false, oid });
            }
          }
          const out = [...children.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, c]) => ({
            type: c.dir ? 'dir' : 'file',
            name,
            path: name,
            sha: c.oid,
            size: c.dir ? 0 : (repo.objects.get(c.oid)?.data.length ?? 0),
          }));
          sendJson(res, 200, out);
          return true;
        }
        const blobOid = files.get(path);
        if (blobOid !== undefined) {
          const data = repo.objects.get(blobOid)?.data ?? Buffer.alloc(0);
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            content: data.toString('base64'),
            sha: blobOid,
            size: data.length,
            name: path.split('/').pop() ?? path,
            path,
          });
          return true;
        }
        // Directory?
        const dirOid = subtreeOid(repo, tip, path);
        if (dirOid !== null) {
          const children = new Map<string, { dir: boolean; oid: string }>();
          for (const [p, oid] of files) {
            if (!p.startsWith(`${path}/`)) continue;
            const restPath = p.slice(path.length + 1);
            const first = restPath.split('/')[0];
            if (restPath.includes('/')) {
              if (!children.has(first)) {
                const childOid = subtreeOid(repo, tip, `${path}/${first}`);
                if (childOid) children.set(first, { dir: true, oid: childOid });
              }
            } else {
              children.set(first, { dir: false, oid });
            }
          }
          const out = [...children.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, c]) => ({
            type: c.dir ? 'dir' : 'file',
            name,
            path: `${path}/${name}`,
            sha: c.oid,
            size: c.dir ? 0 : (repo.objects.get(c.oid)?.data.length ?? 0),
          }));
          sendJson(res, 200, out);
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      if (method === 'PUT') {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        const message = typeof input.message === 'string' ? input.message : '';
        const contentB64 = typeof input.content === 'string' ? input.content : '';
        const branch = typeof input.branch === 'string' && input.branch !== '' ? input.branch : repo.defaultBranch;
        const shaParam = typeof input.sha === 'string' ? input.sha : undefined;
        const data = Buffer.from(contentB64, 'base64');
        let tip = repo.refs.get(`refs/heads/${branch}`);
        let files: Map<string, string>;
        let parentOverride: string | undefined;
        if (tip === undefined) {
          // Branch does not exist: start from the default branch tip (or empty).
          const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          if (defaultTip) {
            parentOverride = peelToCommit(repo, defaultTip).oid;
            files = new Map(commitFileMap(repo, parentOverride));
          } else {
            files = new Map();
          }
        } else {
          files = new Map(commitFileMap(repo, peelToCommit(repo, tip).oid));
        }
        const existed = files.has(path);
        if (existed && shaParam !== undefined && shaParam !== files.get(path)) {
          return sendRestError(res, 409, 'Conflict: sha does not match the current file'), true;
        }
        const blobOid = storeBlob(repo, data);
        files.set(path, blobOid);
        const commitOid = commitFileState(repo, branch, files, message, parentOverride);
        sendJson(res, existed ? 200 : 201, {
          content: {
            name: path.split('/').pop() ?? path,
            path,
            sha: blobOid,
            size: data.length,
            encoding: 'base64',
            content: contentB64,
            type: 'file',
          },
          commit: { sha: commitOid, message },
        });
        return true;
      }
      if (method === 'DELETE') {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        const message = typeof input.message === 'string' ? input.message : '';
        const branch = typeof input.branch === 'string' && input.branch !== '' ? input.branch : repo.defaultBranch;
        const shaParam = typeof input.sha === 'string' ? input.sha : undefined;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip) return sendRestError(res, 404, 'Not Found'), true;
        const files = new Map(commitFileMap(repo, peelToCommit(repo, tip).oid));
        if (!files.has(path)) return sendRestError(res, 404, 'Not Found'), true;
        if (shaParam !== undefined && shaParam !== files.get(path)) {
          return sendRestError(res, 409, 'Conflict: sha does not match the current file'), true;
        }
        files.delete(path);
        const commitOid = commitFileState(repo, branch, files, message);
        sendJson(res, 200, { content: null, commit: { sha: commitOid, message } });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // labels
    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map(labelJson));
        return true;
      }
      if (method === 'POST' && rest.length === 1) {
        let input: Record<string, unknown>;
        try {
          input = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        const name = typeof input.name === 'string' ? input.name : '';
        if (name === '') return sendRestError(res, 422, 'Validation Failed: name is required'), true;
        const existing = repo.labels.get(name);
        if (existing) {
          sendJson(res, 201, labelJson(existing));
          return true;
        }
        const label: Label = {
          id: repo.nextLabelId++,
          name,
          color: typeof input.color === 'string' ? input.color : 'ededed',
          description: typeof input.description === 'string' ? input.description : '',
        };
        repo.labels.set(name, label);
        sendJson(res, 201, labelJson(label));
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = q.get('state') ?? 'open';
          const sort = q.get('sort') ?? 'created';
          const direction = q.get('direction') ?? 'desc';
          let items = [...repo.issues];
          if (state !== 'all') items = items.filter((i) => i.state === state);
          if (sort === 'created') {
            items.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          }
          const { page, link } = paginate(items.map((i) => issueJson(repo, i)), url, req);
          sendJson(res, 200, page, linkHeader(link));
          return true;
        }
        if (method === 'POST') {
          let input: Record<string, unknown>;
          try {
            input = parseJsonBody(ctx.body) as Record<string, unknown>;
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          const title = typeof input.title === 'string' ? input.title : '';
          if (title === '') return sendRestError(res, 422, 'Validation Failed: title is required'), true;
          const labelNames = Array.isArray(input.labels) ? input.labels.filter((l): l is string => typeof l === 'string') : [];
          const labels: Label[] = [];
          for (const name of labelNames) {
            const label = repo.labels.get(name);
            if (!label) return sendRestError(res, 422, `Validation Failed: label "${name}" does not exist`), true;
            labels.push(label);
          }
          const now = nextIso();
          const issue: Issue = {
            id: store.nextObjectId++,
            number: repo.nextNumber++,
            title,
            body: typeof input.body === 'string' ? input.body : '',
            state: 'open',
            labels,
            user: VIEWER_LOGIN,
            createdAt: now,
            updatedAt: now,
            closedAt: null,
            seq: store.creationSeq++,
          };
          repo.issues.push(issue);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
      }
      const num = Number(rest[1]);
      if (rest.length >= 2 && Number.isInteger(num)) {
        const issue = repo.issues.find((i) => i.number === num);
        if (!issue) return sendRestError(res, 404, 'Not Found'), true;
        if (rest.length === 2) {
          if (method === 'GET') {
            sendJson(res, 200, issueJson(repo, issue));
            return true;
          }
          if (method === 'PATCH') {
            let input: Record<string, unknown>;
            try {
              input = parseJsonBody(ctx.body) as Record<string, unknown>;
            } catch {
              return sendRestError(res, 400, 'Invalid JSON'), true;
            }
            if (typeof input.title === 'string') issue.title = input.title;
            if (typeof input.body === 'string') issue.body = input.body;
            if (input.state === 'open' || input.state === 'closed') {
              issue.state = input.state;
              issue.closedAt = input.state === 'closed' ? nextIso() : null;
            }
            issue.updatedAt = nextIso();
            sendJson(res, 200, issueJson(repo, issue));
            return true;
          }
          return sendRestError(res, 404, 'Not Found'), true;
        }
        if (rest.length === 3 && rest[2] === 'comments') {
          if (method === 'GET') {
            const list = repo.comments.get(num) ?? [];
            sendJson(res, 200, list.map((c) => commentJson(repo, num, c)));
            return true;
          }
          if (method === 'POST') {
            let input: Record<string, unknown>;
            try {
              input = parseJsonBody(ctx.body) as Record<string, unknown>;
            } catch {
              return sendRestError(res, 400, 'Invalid JSON'), true;
            }
            const bodyText = typeof input.body === 'string' ? input.body : '';
            if (bodyText === '') return sendRestError(res, 422, 'Validation Failed: body is required'), true;
            const comment: Comment = {
              id: repo.nextCommentId++,
              body: bodyText,
              user: VIEWER_LOGIN,
              createdAt: nextIso(),
            };
            const list = repo.comments.get(num) ?? [];
            list.push(comment);
            repo.comments.set(num, list);
            sendJson(res, 201, commentJson(repo, num, comment));
            return true;
          }
          return sendRestError(res, 404, 'Not Found'), true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = q.get('state') ?? 'open';
          let items = [...repo.pulls];
          if (state !== 'all') items = items.filter((p) => p.state === state);
          const { page, link } = paginate(items.map((p) => pullJson(repo, p)), url, req);
          sendJson(res, 200, page, linkHeader(link));
          return true;
        }
        if (method === 'POST') {
          let input: Record<string, unknown>;
          try {
            input = parseJsonBody(ctx.body) as Record<string, unknown>;
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          const title = typeof input.title === 'string' ? input.title : '';
          const head = typeof input.head === 'string' ? input.head : '';
          const base = typeof input.base === 'string' ? input.base : '';
          if (title === '' || head === '' || base === '') {
            return sendRestError(res, 422, 'Validation Failed: title, head and base are required'), true;
          }
          const headTip = resolveRef(repo, head);
          const baseTip = resolveRef(repo, base);
          if (headTip === null || baseTip === null) {
            return sendRestError(res, 422, 'Validation Failed: head or base branch does not exist'), true;
          }
          const headFiles = commitFileMap(repo, headTip);
          const baseFiles = commitFileMap(repo, baseTip);
          const now = nextIso();
          const pr: PullRequest = {
            id: store.nextObjectId++,
            number: repo.nextNumber++,
            title,
            body: typeof input.body === 'string' ? input.body : '',
            state: 'open',
            merged: false,
            headRef: head,
            baseRef: base,
            headSha: headTip,
            baseSha: baseTip,
            mergeCommitSha: null,
            mergedAt: null,
            user: VIEWER_LOGIN,
            createdAt: now,
            updatedAt: now,
            seq: store.creationSeq++,
            files: diffFileMaps(repo, baseFiles, headFiles),
          };
          repo.pulls.push(pr);
          sendJson(res, 201, pullJson(repo, pr));
          return true;
        }
      }
      const num = Number(rest[1]);
      if (rest.length >= 2 && Number.isInteger(num)) {
        const pr = repo.pulls.find((p) => p.number === num);
        if (!pr) return sendRestError(res, 404, 'Not Found'), true;
        if (rest.length === 2 && method === 'GET') {
          sendJson(res, 200, pullJson(repo, pr));
          return true;
        }
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          sendJson(res, 200, pr.files);
          return true;
        }
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (pr.merged) return sendRestError(res, 405, 'Pull request already merged'), true;
          const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
          const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
          if (!headTip || !baseTip) return sendRestError(res, 404, 'Not Found'), true;
          const headCommit = peelToCommit(repo, headTip).oid;
          const baseCommit = peelToCommit(repo, baseTip).oid;
          const base = mergeBase(repo, headCommit, baseCommit);
          if (base === null) return sendRestError(res, 405, 'Merge conflict'), true;
          const merged = threeWayMerge(
            repo,
            commitFileMap(repo, base),
            commitFileMap(repo, headCommit),
            commitFileMap(repo, baseCommit),
          );
          if (!merged.ok) return sendRestError(res, 405, 'Merge conflict'), true;
          const message = `${pr.title} (#${pr.number})`;
          const { oid } = createCommit(repo, merged.treeOid as string, [baseCommit], message);
          repo.refs.set(`refs/heads/${pr.baseRef}`, oid);
          pr.state = 'closed';
          pr.merged = true;
          pr.mergeCommitSha = oid;
          pr.mergedAt = nextIso();
          pr.updatedAt = pr.mergedAt;
          sendJson(res, 200, { merged: true, sha: oid, message });
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    return sendRestError(res, 404, 'Not Found'), true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// GraphQL: hand-written parser + executor for the documented subset
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<[string, GqlValue]> };

interface GqlSelection {
  kind: 'field' | 'fragment';
  alias?: string;
  name?: string;
  args?: Array<[string, GqlValue]>;
  selections?: GqlSelection[];
  typeCondition?: string;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name?: string;
  variables: Record<string, GqlValue>;
  selections: GqlSelection[];
}

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i++;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@'.includes(c)) {
      tokens.push(c);
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j++;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    throw new Error(`graphql: unexpected character ${c}`);
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private tokens: string[];

  constructor(tokens: string[]) {
    this.tokens = tokens;
  }

  peek(): string | undefined {
    return this.tokens[this.pos];
  }
  next(): string {
    const t = this.tokens[this.pos];
    this.pos++;
    return t;
  }
  expect(t: string): void {
    const got = this.next();
    if (got !== t) throw new Error(`graphql: expected ${t}, got ${got}`);
  }

  parseDocument(): { operations: GqlOperation[]; fragments: Record<string, GqlSelection> } {
    const operations: GqlOperation[] = [];
    const fragments: Record<string, GqlSelection> = {};
    while (this.pos < this.tokens.length) {
      const t = this.peek();
      if (t === 'query' || t === 'mutation') {
        operations.push(this.parseOperation());
      } else if (t === 'fragment') {
        this.next();
        const name = this.next();
        this.expect('on');
        const typeCondition = this.next();
        const selections = this.parseSelectionSet();
        fragments[name] = { kind: 'fragment', typeCondition, selections };
      } else if (t === '{') {
        operations.push({ kind: 'query', variables: {}, selections: this.parseSelectionSet() });
      } else {
        throw new Error(`graphql: unexpected token ${t}`);
      }
    }
    return { operations, fragments };
  }

  parseOperation(): GqlOperation {
    const kind = this.next() as 'query' | 'mutation';
    let name: string | undefined;
    if (this.peek() !== undefined && this.peek() !== '(' && this.peek() !== '{') {
      name = this.next();
    }
    const variables: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        this.expect('$');
        const varName = this.next();
        this.expect(':');
        // Type: a name, possibly wrapped in [ ] and suffixed with !. Skip it.
        let depth = 0;
        while (this.peek() !== undefined && this.peek() !== ')' && this.peek() !== '$') {
          const tok = this.next();
          if (tok === '[') depth++;
          else if (tok === ']') depth--;
          else if (tok === '=') {
            // Default value: skip one value.
            this.parseValue();
            break;
          }
          if (depth === 0 && (this.peek() === ')' || this.peek() === '$')) break;
        }
        variables[varName] = { kind: 'null' };
      }
      this.expect(')');
    }
    const selections = this.parseSelectionSet();
    return { kind, name, variables, selections };
  }

  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === '...') {
        this.next();
        if (this.peek() === 'on') {
          this.next();
          const typeCondition = this.next();
          const selections = this.parseSelectionSet();
          out.push({ kind: 'fragment', typeCondition, selections });
        } else {
          // Named fragment spread: the name follows; directives skipped.
          const name = this.next();
          out.push({ kind: 'fragment', name, selections: [] });
        }
        continue;
      }
      out.push(this.parseField());
    }
    this.expect('}');
    return out;
  }

  parseField(): GqlSelection {
    let name = this.next();
    let alias: string | undefined;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Array<[string, GqlValue]> = [];
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const argName = this.next();
        this.expect(':');
        args.push([argName, this.parseValue()]);
      }
      this.expect(')');
    }
    // Directives (@...) — skip.
    while (this.peek() === '@') {
      this.next();
      this.next();
      if (this.peek() === '(') {
        this.next();
        let depth = 1;
        while (depth > 0) {
          const t = this.next();
          if (t === '(') depth++;
          else if (t === ')') depth--;
        }
      }
    }
    let selections: GqlSelection[] | undefined;
    if (this.peek() === '{') selections = this.parseSelectionSet();
    return { kind: 'field', alias, name, args, selections };
  }

  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') return { kind: 'variable', name: this.next() };
    if (t === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', values };
    }
    if (t === '{') {
      const fields: Array<[string, GqlValue]> = [];
      while (this.peek() !== '}') {
        const key = this.next();
        this.expect(':');
        fields.push([key, this.parseValue()]);
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (t === 'true') return { kind: 'boolean', value: true };
    if (t === 'false') return { kind: 'boolean', value: false };
    if (t === 'null') return { kind: 'null' };
    if (t.startsWith('"')) return { kind: 'string', value: JSON.parse(t) as string };
    if (/^-?\d+$/.test(t)) return { kind: 'int', value: Number(t) };
    if (/^-?[\d.]+$/.test(t)) return { kind: 'float', value: Number(t) };
    return { kind: 'enum', value: t };
  }
}

function gqlResolveValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'variable':
      return variables[v.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return v.value;
    case 'null':
      return null;
    case 'enum':
      return v.value;
    case 'list':
      return v.values.map((x) => gqlResolveValue(x, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of v.fields) out[k] = gqlResolveValue(val, variables);
      return out;
    }
  }
}

function gqlArg(args: Array<[string, GqlValue]> | undefined, name: string, variables: Record<string, unknown>): unknown {
  if (!args) return undefined;
  for (const [k, v] of args) if (k === name) return gqlResolveValue(v, variables);
  return undefined;
}

// ---------------------------------------------------------------------------
// GraphQL type tables (introspection) and global ids
// ---------------------------------------------------------------------------

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'author', 'createdAt', 'updatedAt', 'closedAt', 'labels', 'comments', 'url', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'author', 'createdAt', 'updatedAt', 'mergedAt', 'mergeCommit', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'url', 'createdAt'],
  User: ['id', 'login', 'name', 'email', 'url'],
  SearchType: [],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE'],
};

function globalId(type: string, key: string): string {
  return b64encode(`${type}:${key}`);
}

function decodeGlobalId(id: string): { type: string; key: string } | null {
  try {
    const text = b64decode(id);
    const idx = text.indexOf(':');
    if (idx <= 0) return null;
    return { type: text.slice(0, idx), key: text.slice(idx + 1) };
  } catch {
    return null;
  }
}

function issueStateGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function prStateGql(pr: PullRequest): string {
  if (pr.merged) return 'MERGED';
  return pr.state === 'open' ? 'OPEN' : 'CLOSED';
}

// ---------------------------------------------------------------------------
// GraphQL executor
// ---------------------------------------------------------------------------

interface GqlNode {
  __typename: string;
  [key: string]: unknown;
}

function userNode(): GqlNode {
  return {
    __typename: 'User',
    login: VIEWER_LOGIN,
    id: globalId('User', String(VIEWER_ID)),
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    url: `https://example.invalid/${VIEWER_LOGIN}`,
    databaseId: VIEWER_ID,
  };
}

function repoNode(repo: Repo): GqlNode {
  return {
    __typename: 'Repository',
    __repo: repo,
    id: globalId('Repository', String(repo.id)),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    description: repo.description,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    url: `https://example.invalid/${repo.owner}/${repo.name}`,
    createdAt: isoOf(EPOCH_SEC + repo.createdSeq),
  };
}

function issueNode(repo: Repo, issue: Issue): GqlNode {
  return {
    __typename: 'Issue',
    __repo: repo,
    __issue: issue,
    id: globalId('Issue', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issueStateGql(issue.state),
    createdAt: issue.createdAt,
    updatedAt: issue.updatedAt,
    closedAt: issue.closedAt,
    url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function prNode(repo: Repo, pr: PullRequest): GqlNode {
  return {
    __typename: 'PullRequest',
    __repo: repo,
    __pr: pr,
    id: globalId('PullRequest', `${repo.id}:${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: prStateGql(pr),
    merged: pr.merged,
    mergeable: prMergeable(repo, pr),
    headRefName: pr.headRef,
    baseRefName: pr.baseRef,
    headRefOid: pr.headSha,
    baseRefOid: pr.baseSha,
    createdAt: pr.createdAt,
    updatedAt: pr.updatedAt,
    mergedAt: pr.mergedAt,
    url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
  };
}

function commentNode(repo: Repo, issueNumber: number, comment: Comment): GqlNode {
  return {
    __typename: 'IssueComment',
    id: globalId('IssueComment', `${repo.id}:${issueNumber}:${comment.id}`),
    body: comment.body,
    createdAt: comment.createdAt,
    url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issueNumber}#issuecomment-${comment.id}`,
  };
}

/** Opaque cursor: base64 of `cursor:<offset>` (offset = items consumed). */
function encodeCursor(offset: number): string {
  return b64encode(`cursor:${offset}`);
}

function decodeCursor(cursor: string | null | undefined): number {
  if (!cursor) return 0;
  try {
    const text = b64decode(cursor);
    if (text.startsWith('cursor:')) {
      const n = Number(text.slice('cursor:'.length));
      return Number.isFinite(n) && n >= 0 ? n : 0;
    }
  } catch {
    // Not a cursor we made: treat as start.
  }
  return 0;
}

class GqlError extends Error {
  constructor(message: string) {
    super(message);
  }
}

function executeSelections(
  node: GqlNode,
  selections: GqlSelection[],
  variables: Record<string, unknown>,
  fragments: Record<string, GqlSelection>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'fragment') {
      if (sel.typeCondition && sel.typeCondition !== node.__typename) continue;
      if (sel.name) {
        const frag = fragments[sel.name];
        if (!frag) continue;
        if (frag.typeCondition && frag.typeCondition !== node.__typename) continue;
        Object.assign(out, executeSelections(node, frag.selections ?? [], variables, fragments));
        continue;
      }
      Object.assign(out, executeSelections(node, sel.selections ?? [], variables, fragments));
      continue;
    }
    const key = sel.alias ?? (sel.name as string);
    out[key] = resolveField(node, sel, variables, fragments);
  }
  return out;
}

function resolveField(
  node: GqlNode,
  sel: GqlSelection,
  variables: Record<string, unknown>,
  fragments: Record<string, GqlSelection>,
): unknown {
  const name = sel.name as string;
  const selections = sel.selections ?? [];
  const args = sel.args;

  if (name === '__typename') return node.__typename;

  // ---- Query root ----
  if (node.__typename === 'Query') {
    if (name === 'viewer') {
      return executeSelections(userNode(), selections, variables, fragments);
    }
    if (name === 'repository') {
      const owner = gqlArg(args, 'owner', variables) as string | undefined;
      const repoName = gqlArg(args, 'name', variables) as string | undefined;
      if (!owner || !repoName) return null;
      const repo = getRepo(owner, repoName);
      if (!repo) return null;
      return executeSelections(repoNode(repo), selections, variables, fragments);
    }
    if (name === 'node') {
      const id = gqlArg(args, 'id', variables) as string | undefined;
      if (!id) return null;
      const decoded = decodeGlobalId(id);
      if (!decoded) return null;
      if (decoded.type === 'Repository') {
        const repo = getRepoById(Number(decoded.key));
        if (!repo) return null;
        return executeSelections(repoNode(repo), selections, variables, fragments);
      }
      if (decoded.type === 'Issue') {
        const [repoId, num] = decoded.key.split(':');
        const repo = getRepoById(Number(repoId));
        const issue = repo?.issues.find((i) => i.number === Number(num));
        if (!repo || !issue) return null;
        return executeSelections(issueNode(repo, issue), selections, variables, fragments);
      }
      if (decoded.type === 'PullRequest') {
        const [repoId, num] = decoded.key.split(':');
        const repo = getRepoById(Number(repoId));
        const pr = repo?.pulls.find((p) => p.number === Number(num));
        if (!repo || !pr) return null;
        return executeSelections(prNode(repo, pr), selections, variables, fragments);
      }
      return null;
    }
    if (name === '__type') {
      const typeName = gqlArg(args, 'name', variables) as string | undefined;
      if (!typeName) return null;
      const fields = GQL_TYPE_FIELDS[typeName];
      const enums = GQL_ENUM_VALUES[typeName];
      if (fields === undefined && enums === undefined) return null;
      return executeSelections(
        {
          __typename: '__Type',
          name: typeName,
          fields: fields ? fields.map((f) => ({ __typename: '__Field', name: f })) : null,
          enumValues: enums ? enums.map((e) => ({ __typename: '__EnumValue', name: e })) : null,
        },
        selections,
        variables,
        fragments,
      );
    }
    if (name === '__schema') {
      return executeSelections(
        { __typename: '__Schema', queryType: { __typename: '__Type', name: 'Query' } },
        selections,
        variables,
        fragments,
      );
    }
    throw new GqlError(`Cannot query field "${name}" on type "Query".`);
  }

  // ---- Mutation root ----
  if (node.__typename === 'Mutation') {
    if (name === 'createIssue') {
      const input = gqlArg(args, 'input', variables) as Record<string, unknown>;
      const repoId = decodeGlobalId(String(input?.repositoryId ?? ''));
      const repo = repoId?.type === 'Repository' ? getRepoById(Number(repoId.key)) : undefined;
      if (!repo) throw new GqlError('createIssue: repository not found');
      const title = String(input?.title ?? '');
      const body = typeof input?.body === 'string' ? input.body : '';
      const now = nextIso();
      const issue: Issue = {
        id: store.nextObjectId++,
        number: repo.nextNumber++,
        title,
        body,
        state: 'open',
        labels: [],
        user: VIEWER_LOGIN,
        createdAt: now,
        updatedAt: now,
        closedAt: null,
        seq: store.creationSeq++,
      };
      repo.issues.push(issue);
      return executeSelections(
        { __typename: 'CreateIssuePayload', issue: issueNode(repo, issue) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'closeIssue') {
      const input = gqlArg(args, 'input', variables) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input?.issueId ?? ''));
      if (!decoded || decoded.type !== 'Issue') throw new GqlError('closeIssue: issue not found');
      const [repoId, num] = decoded.key.split(':');
      const repo = getRepoById(Number(repoId));
      const issue = repo?.issues.find((i) => i.number === Number(num));
      if (!repo || !issue) throw new GqlError('closeIssue: issue not found');
      issue.state = 'closed';
      issue.closedAt = nextIso();
      issue.updatedAt = issue.closedAt;
      return executeSelections(
        { __typename: 'CloseIssuePayload', issue: issueNode(repo, issue) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'createPullRequest') {
      const input = gqlArg(args, 'input', variables) as Record<string, unknown>;
      const repoId = decodeGlobalId(String(input?.repositoryId ?? ''));
      const repo = repoId?.type === 'Repository' ? getRepoById(Number(repoId.key)) : undefined;
      if (!repo) throw new GqlError('createPullRequest: repository not found');
      const baseRef = String(input?.baseRefName ?? '');
      const headRef = String(input?.headRefName ?? '');
      const title = String(input?.title ?? '');
      const headTip = resolveRef(repo, headRef);
      const baseTip = resolveRef(repo, baseRef);
      if (headTip === null || baseTip === null) {
        throw new GqlError('createPullRequest: head or base branch does not exist');
      }
      const now = nextIso();
      const pr: PullRequest = {
        id: store.nextObjectId++,
        number: repo.nextNumber++,
        title,
        body: typeof input?.body === 'string' ? input.body : '',
        state: 'open',
        merged: false,
        headRef,
        baseRef,
        headSha: headTip,
        baseSha: baseTip,
        mergeCommitSha: null,
        mergedAt: null,
        user: VIEWER_LOGIN,
        createdAt: now,
        updatedAt: now,
        seq: store.creationSeq++,
        files: diffFileMaps(repo, commitFileMap(repo, baseTip), commitFileMap(repo, headTip)),
      };
      repo.pulls.push(pr);
      return executeSelections(
        { __typename: 'CreatePullRequestPayload', pullRequest: prNode(repo, pr) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'mergePullRequest') {
      const input = gqlArg(args, 'input', variables) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input?.pullRequestId ?? ''));
      if (!decoded || decoded.type !== 'PullRequest') throw new GqlError('mergePullRequest: pull request not found');
      const [repoId, num] = decoded.key.split(':');
      const repo = getRepoById(Number(repoId));
      const pr = repo?.pulls.find((p) => p.number === Number(num));
      if (!repo || !pr) throw new GqlError('mergePullRequest: pull request not found');
      if (pr.merged) throw new GqlError('mergePullRequest: pull request already merged');
      const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
      const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
      if (!headTip || !baseTip) throw new GqlError('mergePullRequest: branch missing');
      const headCommit = peelToCommit(repo, headTip).oid;
      const baseCommit = peelToCommit(repo, baseTip).oid;
      const base = mergeBase(repo, headCommit, baseCommit);
      if (base === null) throw new GqlError('mergePullRequest: merge conflict');
      const merged = threeWayMerge(
        repo,
        commitFileMap(repo, base),
        commitFileMap(repo, headCommit),
        commitFileMap(repo, baseCommit),
      );
      if (!merged.ok) throw new GqlError('mergePullRequest: merge conflict');
      const message = `${pr.title} (#${pr.number})`;
      const { oid } = createCommit(repo, merged.treeOid as string, [baseCommit], message);
      repo.refs.set(`refs/heads/${pr.baseRef}`, oid);
      pr.state = 'closed';
      pr.merged = true;
      pr.mergeCommitSha = oid;
      pr.mergedAt = nextIso();
      pr.updatedAt = pr.mergedAt;
      return executeSelections(
        { __typename: 'MergePullRequestPayload', pullRequest: prNode(repo, pr) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'addComment') {
      const input = gqlArg(args, 'input', variables) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input?.subjectId ?? ''));
      if (!decoded || decoded.type !== 'Issue') throw new GqlError('addComment: subject not found');
      const [repoId, num] = decoded.key.split(':');
      const repo = getRepoById(Number(repoId));
      const issue = repo?.issues.find((i) => i.number === Number(num));
      if (!repo || !issue) throw new GqlError('addComment: subject not found');
      const comment: Comment = {
        id: repo.nextCommentId++,
        body: String(input?.body ?? ''),
        user: VIEWER_LOGIN,
        createdAt: nextIso(),
      };
      const list = repo.comments.get(issue.number) ?? [];
      list.push(comment);
      repo.comments.set(issue.number, list);
      return executeSelections(
        {
          __typename: 'AddCommentPayload',
          commentEdge: { __typename: 'IssueCommentEdge', node: commentNode(repo, issue.number, comment) },
        },
        selections,
        variables,
        fragments,
      );
    }
    throw new GqlError(`Cannot query field "${name}" on type "Mutation".`);
  }

  // ---- User ----
  if (node.__typename === 'User') {
    if (name === 'login' || name === 'name' || name === 'email' || name === 'url' || name === 'id' || name === 'databaseId') {
      return node[name];
    }
    throw new GqlError(`Cannot query field "${name}" on type "User".`);
  }

  // ---- Repository ----
  if (node.__typename === 'Repository') {
    const repo = node.__repo as Repo;
    if (name === 'id' || name === 'databaseId' || name === 'name' || name === 'nameWithOwner' || name === 'description' || name === 'viewerPermission' || name === 'hasIssuesEnabled' || name === 'url' || name === 'createdAt') {
      return node[name];
    }
    if (name === 'owner') {
      return executeSelections(userNode(), selections, variables, fragments);
    }
    if (name === 'defaultBranchRef') {
      return executeSelections({ __typename: 'Ref', name: repo.defaultBranch }, selections, variables, fragments);
    }
    if (name === 'issue') {
      const num = gqlArg(args, 'number', variables) as number | undefined;
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) return null;
      return executeSelections(issueNode(repo, issue), selections, variables, fragments);
    }
    if (name === 'issues') {
      const first = (gqlArg(args, 'first', variables) as number | undefined) ?? 30;
      const after = gqlArg(args, 'after', variables) as string | null | undefined;
      const states = gqlArg(args, 'states', variables) as string[] | undefined;
      const orderBy = gqlArg(args, 'orderBy', variables) as Record<string, unknown> | undefined;
      let items = [...repo.issues];
      if (states && states.length > 0) {
        const wanted = new Set(states.map((s) => (s === 'OPEN' ? 'open' : s === 'CLOSED' ? 'closed' : s)));
        items = items.filter((i) => wanted.has(i.state));
      }
      if (orderBy && orderBy.field === 'CREATED_AT') {
        items.sort((a, b) => (orderBy.direction === 'DESC' ? b.seq - a.seq : a.seq - b.seq));
      } else {
        items.sort((a, b) => a.seq - b.seq);
      }
      const offset = decodeCursor(after);
      const pageItems = items.slice(offset, offset + first);
      const endOffset = offset + pageItems.length;
      const connection: GqlNode = {
        __typename: 'IssueConnection',
        nodes: pageItems.map((i) => issueNode(repo, i)),
        pageInfo: {
          __typename: 'PageInfo',
          hasNextPage: endOffset < items.length,
          endCursor: pageItems.length > 0 ? encodeCursor(endOffset) : null,
          hasPreviousPage: offset > 0,
          startCursor: pageItems.length > 0 ? encodeCursor(offset + 1) : null,
        },
        totalCount: items.length,
      };
      return executeSelections(connection, selections, variables, fragments);
    }
    if (name === 'pullRequests') {
      const first = (gqlArg(args, 'first', variables) as number | undefined) ?? 30;
      const after = gqlArg(args, 'after', variables) as string | null | undefined;
      const items = [...repo.pulls].sort((a, b) => b.seq - a.seq);
      const offset = decodeCursor(after);
      const pageItems = items.slice(offset, offset + first);
      const endOffset = offset + pageItems.length;
      const connection: GqlNode = {
        __typename: 'PullRequestConnection',
        nodes: pageItems.map((p) => prNode(repo, p)),
        pageInfo: {
          __typename: 'PageInfo',
          hasNextPage: endOffset < items.length,
          endCursor: pageItems.length > 0 ? encodeCursor(endOffset) : null,
          hasPreviousPage: offset > 0,
          startCursor: pageItems.length > 0 ? encodeCursor(offset + 1) : null,
        },
        totalCount: items.length,
      };
      return executeSelections(connection, selections, variables, fragments);
    }
    if (name === 'pullRequest') {
      const num = gqlArg(args, 'number', variables) as number | undefined;
      const pr = repo.pulls.find((p) => p.number === num);
      if (!pr) return null;
      return executeSelections(prNode(repo, pr), selections, variables, fragments);
    }
    throw new GqlError(`Cannot query field "${name}" on type "Repository".`);
  }

  // ---- Issue ----
  if (node.__typename === 'Issue') {
    if (name === 'id' || name === 'number' || name === 'title' || name === 'body' || name === 'state' || name === 'createdAt' || name === 'updatedAt' || name === 'closedAt' || name === 'url') {
      return node[name];
    }
    if (name === 'author') return executeSelections(userNode(), selections, variables, fragments);
    if (name === 'labels') {
      const issue = node.__issue as Issue;
      return executeSelections(
        { __typename: 'LabelConnection', nodes: issue.labels.map((l) => ({ __typename: 'Label', name: l.name, color: l.color })) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'comments') {
      const repo = node.__repo as Repo;
      const issue = node.__issue as Issue;
      const list = repo.comments.get(issue.number) ?? [];
      return executeSelections(
        { __typename: 'IssueCommentConnection', nodes: list.map((c) => commentNode(repo, issue.number, c)) },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'repository') {
      const repo = node.__repo as Repo;
      return executeSelections(repoNode(repo), selections, variables, fragments);
    }
    throw new GqlError(`Cannot query field "${name}" on type "Issue".`);
  }

  // ---- PullRequest ----
  if (node.__typename === 'PullRequest') {
    if (
      name === 'id' || name === 'number' || name === 'title' || name === 'body' || name === 'state' ||
      name === 'merged' || name === 'mergeable' || name === 'headRefName' || name === 'baseRefName' ||
      name === 'headRefOid' || name === 'baseRefOid' || name === 'createdAt' || name === 'updatedAt' ||
      name === 'mergedAt' || name === 'url'
    ) {
      return node[name];
    }
    if (name === 'files') {
      const pr = node.__pr as PullRequest;
      const first = (gqlArg(args, 'first', variables) as number | undefined) ?? 30;
      const nodes = pr.files.slice(0, first).map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename }));
      return executeSelections(
        { __typename: 'PullRequestChangedFileConnection', nodes, totalCount: pr.files.length },
        selections,
        variables,
        fragments,
      );
    }
    if (name === 'author') return executeSelections(userNode(), selections, variables, fragments);
    if (name === 'mergeCommit') {
      const pr = node.__pr as PullRequest;
      if (!pr.mergeCommitSha) return null;
      const repo = node.__repo as Repo;
      return executeSelections(
        { __typename: 'Commit', oid: pr.mergeCommitSha, message: pr.title, __repo: repo },
        selections,
        variables,
        fragments,
      );
    }
    throw new GqlError(`Cannot query field "${name}" on type "PullRequest".`);
  }

  // ---- Connections / edges / introspection types: plain field access ----
  if (node.__typename === 'IssueConnection' || node.__typename === 'PullRequestConnection' || node.__typename === 'PullRequestChangedFileConnection' || node.__typename === 'LabelConnection' || node.__typename === 'IssueCommentConnection') {
    if (name === 'nodes' || name === 'edges' || name === 'totalCount' || name === 'pageInfo') {
      const value = node[name] as unknown;
      if (name === 'nodes' && Array.isArray(value)) {
        return value.map((child) => {
          if (child && typeof child === 'object' && '__typename' in (child as Record<string, unknown>)) {
            return executeSelections(child as GqlNode, selections, variables, fragments);
          }
          return child;
        });
      }
      if (name === 'pageInfo' && value && typeof value === 'object') {
        return executeSelections(value as GqlNode, selections, variables, fragments);
      }
      return value;
    }
    throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
  }
  if (node.__typename === 'PageInfo') {
    if (name === 'hasNextPage' || name === 'hasPreviousPage' || name === 'endCursor' || name === 'startCursor') return node[name];
    throw new GqlError(`Cannot query field "${name}" on type "PageInfo".`);
  }
  if (node.__typename === '__Type') {
    if (name === 'name') return node.name;
    if (name === 'fields') {
      const fields = node.fields as GqlNode[] | null;
      if (!fields) return null;
      return fields.map((f) => executeSelections(f, selections, variables, fragments));
    }
    if (name === 'enumValues') {
      const enums = node.enumValues as GqlNode[] | null;
      if (!enums) return null;
      return enums.map((e) => executeSelections(e, selections, variables, fragments));
    }
    throw new GqlError(`Cannot query field "${name}" on type "__Type".`);
  }
  if (node.__typename === '__Field' || node.__typename === '__EnumValue' || node.__typename === '__InputValue') {
    if (name === 'name') return node.name;
    throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
  }
  if (node.__typename === '__Schema') {
    if (name === 'queryType') {
      return executeSelections(node.queryType as GqlNode, selections, variables, fragments);
    }
    throw new GqlError(`Cannot query field "${name}" on type "__Schema".`);
  }
  if (node.__typename === 'Ref') {
    if (name === 'name') return node.name;
    throw new GqlError(`Cannot query field "${name}" on type "Ref".`);
  }
  if (node.__typename === 'IssueCommentEdge') {
    if (name === 'node') return executeSelections(node.node as GqlNode, selections, variables, fragments);
    throw new GqlError(`Cannot query field "${name}" on type "IssueCommentEdge".`);
  }
  if (node.__typename === 'IssueComment' || node.__typename === 'Label' || node.__typename === 'PullRequestChangedFile' || node.__typename === 'Commit') {
    if (name in node && name !== '__typename') return node[name];
    throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
  }
  if (node.__typename === 'CreateIssuePayload' || node.__typename === 'CloseIssuePayload') {
    if (name === 'issue') return executeSelections(node.issue as GqlNode, selections, variables, fragments);
    throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
  }
  if (node.__typename === 'CreatePullRequestPayload' || node.__typename === 'MergePullRequestPayload') {
    if (name === 'pullRequest') return executeSelections(node.pullRequest as GqlNode, selections, variables, fragments);
    throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
  }
  if (node.__typename === 'AddCommentPayload') {
    if (name === 'commentEdge') return executeSelections(node.commentEdge as GqlNode, selections, variables, fragments);
    throw new GqlError(`Cannot query field "${name}" on type "AddCommentPayload".`);
  }

  throw new GqlError(`Cannot query field "${name}" on type "${node.__typename}".`);
}

/** Execute one GraphQL operation; returns {data, errors?}. */
function executeGraphQLOperation(
  query: string,
  variables: Record<string, unknown>,
  operationName?: string,
): Record<string, unknown> {
  let parsed: { operations: GqlOperation[]; fragments: Record<string, GqlSelection> };
  try {
    parsed = new GqlParser(gqlTokenize(query)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
  }
  const op = operationName
    ? parsed.operations.find((o) => o.name === operationName)
    : parsed.operations[0];
  if (!op) {
    return { data: null, errors: [{ message: `Unknown operation named "${operationName}".` }] };
  }
  const root: GqlNode = { __typename: op.kind === 'mutation' ? 'Mutation' : 'Query' };
  try {
    const data = executeSelections(root, op.selections, variables, parsed.fragments);
    return { data };
  } catch (err) {
    if (err instanceof GqlError) {
      return { data: null, errors: [{ message: err.message }] };
    }
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Internal error' }] };
  }
}

/** POST /api/graphql — single operation or a batch array. */
function handleGraphQL(body: Buffer): { status: number; value: unknown } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return { status: 400, value: { errors: [{ message: 'Invalid JSON' }] } };
  }
  const runOne = (op: unknown): Record<string, unknown> => {
    const rec = op as Record<string, unknown>;
    const query = typeof rec.query === 'string' ? rec.query : '';
    const variables = (rec.variables as Record<string, unknown>) ?? {};
    const operationName = typeof rec.operationName === 'string' ? rec.operationName : undefined;
    return executeGraphQLOperation(query, variables, operationName);
  };
  if (Array.isArray(parsed)) {
    return { status: 200, value: parsed.map(runOne) };
  }
  return { status: 200, value: runOne(parsed) };
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol, era 2026-07-28 + legacy initialize)
// ---------------------------------------------------------------------------

const MCP_SERVER_NAME = 'github-core-clone-forge';
const MCP_SERVER_VERSION = '1.0.0';
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25'];

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

/** The six tools, in a fixed order — byte-identical across calls. */
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The name of the repository.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        title: { type: 'string', description: 'The title of the issue.' },
        body: { type: 'string', description: 'The body of the issue.' },
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
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        state: { type: 'string', description: 'Issue state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        title: { type: 'string', description: 'The title of the pull request.' },
        head: { type: 'string', description: 'The name of the head branch.' },
        base: { type: 'string', description: 'The name of the base branch.' },
        body: { type: 'string', description: 'The body of the pull request.' },
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
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        pull_number: { type: 'number', description: 'The number of the pull request.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

interface McpToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: unknown;
  isError: boolean;
}

function mcpOk(result: unknown): McpToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false };
}

function mcpErr(message: string): McpToolResult {
  return { content: [{ type: 'text', text: message }], structuredContent: { error: message }, isError: true };
}

function mcpRequire(args: Record<string, unknown>, name: string): string | null {
  const v = args[name];
  if (v === undefined || v === null || v === '') return `Missing required argument: ${name}`;
  return null;
}

/** Shared merge logic for REST and MCP: squash-merge a PR, or return an error. */
function squashMergePr(repo: Repo, pr: PullRequest): { ok: true; sha: string } | { ok: false; message: string } {
  if (pr.merged) return { ok: false, message: 'Pull request already merged' };
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headTip || !baseTip) return { ok: false, message: 'Branch missing' };
  const headCommit = peelToCommit(repo, headTip).oid;
  const baseCommit = peelToCommit(repo, baseTip).oid;
  const base = mergeBase(repo, headCommit, baseCommit);
  if (base === null) return { ok: false, message: 'Merge conflict' };
  const merged = threeWayMerge(
    repo,
    commitFileMap(repo, base),
    commitFileMap(repo, headCommit),
    commitFileMap(repo, baseCommit),
  );
  if (!merged.ok) return { ok: false, message: 'Merge conflict' };
  const message = `${pr.title} (#${pr.number})`;
  const { oid } = createCommit(repo, merged.treeOid as string, [baseCommit], message);
  repo.refs.set(`refs/heads/${pr.baseRef}`, oid);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergeCommitSha = oid;
  pr.mergedAt = nextIso();
  pr.updatedAt = pr.mergedAt;
  return { ok: true, sha: oid };
}

function mcpCallTool(name: string, args: Record<string, unknown>): McpToolResult {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return mcpErr(`Unknown tool: ${name}`);
  for (const required of tool.inputSchema.required) {
    const missing = mcpRequire(args, required);
    if (missing) return mcpErr(missing);
  }
  const owner = String(args.owner ?? VIEWER_LOGIN);
  const repoName = String(args.repo ?? args.name ?? '');
  if (name === 'create_repo') {
    const repoNameArg = String(args.name ?? '');
    const existing = getRepo(VIEWER_LOGIN, repoNameArg);
    if (existing) return mcpOk(repoJson(existing));
    const repo = createRepoRecord(
      repoNameArg,
      args.private === true,
      typeof args.description === 'string' ? args.description : '',
    );
    return mcpOk(repoJson(repo));
  }
  const repo = getRepo(owner, repoName);
  if (!repo) return mcpErr(`Repository not found: ${owner}/${repoName}`);
  if (name === 'get_repo') {
    return mcpOk(repoJson(repo));
  }
  if (name === 'create_issue') {
    const now = nextIso();
    const issue: Issue = {
      id: store.nextObjectId++,
      number: repo.nextNumber++,
      title: String(args.title ?? ''),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      user: VIEWER_LOGIN,
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      seq: store.creationSeq++,
    };
    repo.issues.push(issue);
    return mcpOk(issueJson(repo, issue));
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let items = [...repo.issues];
    if (state !== 'all') items = items.filter((i) => i.state === state);
    return mcpOk(items.map((i) => issueJson(repo, i)));
  }
  if (name === 'create_pull_request') {
    const head = String(args.head ?? '');
    const base = String(args.base ?? '');
    const headTip = resolveRef(repo, head);
    const baseTip = resolveRef(repo, base);
    if (headTip === null || baseTip === null) {
      return mcpErr('Head or base branch does not exist');
    }
    const now = nextIso();
    const pr: PullRequest = {
      id: store.nextObjectId++,
      number: repo.nextNumber++,
      title: String(args.title ?? ''),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      headRef: head,
      baseRef: base,
      headSha: headTip,
      baseSha: baseTip,
      mergeCommitSha: null,
      mergedAt: null,
      user: VIEWER_LOGIN,
      createdAt: now,
      updatedAt: now,
      seq: store.creationSeq++,
      files: diffFileMaps(repo, commitFileMap(repo, baseTip), commitFileMap(repo, headTip)),
    };
    repo.pulls.push(pr);
    return mcpOk(pullJson(repo, pr));
  }
  if (name === 'merge_pull_request') {
    const num = Number(args.pull_number);
    const pr = repo.pulls.find((p) => p.number === num);
    if (!pr) return mcpErr(`Pull request not found: ${num}`);
    const result = squashMergePr(repo, pr);
    if (!result.ok) return mcpErr(result.message);
    return mcpOk({ merged: true, sha: result.sha, number: pr.number, message: `${pr.title} (#${pr.number})` });
  }
  return mcpErr(`Unknown tool: ${name}`);
}

/** POST /mcp — JSON-RPC 2.0 over Streamable HTTP (plain JSON responses). */
function handleMcp(body: Buffer): { status: number; value: unknown | null } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return {
      status: 400,
      value: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
    };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      status: 400,
      value: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
    };
  }
  const req = parsed as Record<string, unknown>;
  const id = 'id' in req ? req.id : undefined;
  const method = typeof req.method === 'string' ? req.method : '';
  const params = (req.params as Record<string, unknown>) ?? {};

  const ok = (result: unknown): { status: number; value: unknown | null } => ({
    status: 200,
    value: { jsonrpc: '2.0', id: id ?? null, result },
  });
  const err = (code: number, message: string): { status: number; value: unknown | null } => ({
    status: 200,
    value: { jsonrpc: '2.0', id: id ?? null, error: { code, message } },
  });

  // Notifications carry no id and expect no response body.
  if (id === undefined) {
    return { status: 202, value: null };
  }

  if (method === 'server/discover') {
    return ok({
      supportedVersions: [...MCP_SUPPORTED_VERSIONS],
      capabilities: { tools: {} },
      serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION } },
    });
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const protocolVersion = MCP_SUPPORTED_VERSIONS.includes(offered) ? offered : '2026-07-28';
    return ok({
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
    });
  }
  if (method === 'tools/list') {
    return ok({ tools: MCP_TOOLS });
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments as Record<string, unknown>) ?? {};
    if (toolName === '') return err(-32602, 'Missing tool name');
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) return err(-32602, `Unknown tool: ${toolName}`);
    const result = mcpCallTool(toolName, args);
    return ok(result);
  }
  return err(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// HTTP server + routing
// ---------------------------------------------------------------------------

function sendGitResponse(res: ServerResponse, result: { status: number; contentType: string; body: Buffer }): void {
  res.writeHead(result.status, { 'content-type': result.contentType });
  res.end(result.body);
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const rawUrl = req.url ?? '/';
  const url = new URL(rawUrl, 'http://127.0.0.1');
  let pathname = url.pathname;
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
  const method = req.method ?? 'GET';

  // Health check: no auth, always up.
  if (pathname === '/healthz') {
    sendJson(res, 200, { ok: true });
    return;
  }

  // Git smart HTTP: /{owner}/{repo}.git/...
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(pathname);
  if (gitMatch) {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    const owner = decodeURIComponent(gitMatch[1]);
    const repoName = decodeURIComponent(gitMatch[2]);
    const repo = getRepo(owner, repoName);
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    const rest = gitMatch[3] ?? '';
    const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    try {
      if (rest === '/info/refs') {
        const service = url.searchParams.get('service');
        sendGitResponse(res, handleInfoRefs(repo, service, isV2));
        return;
      }
      if (rest === '/git-upload-pack' && method === 'POST') {
        const body = await readBody(req);
        sendGitResponse(res, handleUploadPack(repo, body, isV2));
        return;
      }
      if (rest === '/git-receive-pack' && method === 'POST') {
        const body = await readBody(req);
        sendGitResponse(res, handleReceivePack(repo, body));
        return;
      }
    } catch (err) {
      // Malformed git requests must not take the server down.
      process.stderr.write(`[forge] git handler error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      sendJson(res, 400, { message: 'Bad Request' });
      return;
    }
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }

  // GraphQL
  if (pathname === '/api/graphql' && method === 'POST') {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    const body = await readBody(req);
    const { status, value } = handleGraphQL(body);
    sendJson(res, status, value);
    return;
  }

  // MCP
  if (pathname === '/mcp') {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    if (method === 'DELETE') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    if (method !== 'POST') {
      sendJson(res, 405, { message: 'Method Not Allowed' });
      return;
    }
    const body = await readBody(req);
    const { status, value } = handleMcp(body);
    if (value === null) {
      res.writeHead(status);
      res.end();
      return;
    }
    sendJson(res, status, value);
    return;
  }

  // REST v3
  if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    const body = await readBody(req);
    const segments = pathname.slice('/api/v3'.length).split('/').filter((s) => s !== '');
    const handled = await handleRest({ req, res, url, method, segments, body });
    if (!handled) sendRestError(res, 404, 'Not Found');
    return;
  }

  // Anything else: 404 JSON.
  sendJson(res, 404, { message: 'Not Found' });
}

export function createForgeServer(): Server {
  const server = createServer((req, res) => {
    void handleRequest(req, res).catch((err: unknown) => {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: err instanceof Error ? err.message : 'Internal error' }));
      } else {
        res.destroy();
      }
    });
  });
  return server;
}
