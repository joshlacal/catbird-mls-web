/**
 * catbird-mls-web TypeScript bridge — typed async wrappers over WASM exports.
 *
 * Usage:
 *   import { initMls, setAuth, listConversations } from 'catbird-mls-web/ts/bridge'
 *
 *   await initMls({ baseUrl: 'https://api.catbird.blue' })
 *   setAuth(did, token)
 *   const convos = await listConversations()
 */

import type {
  InitConfig,
  Conversation,
  Message,
  GroupMember,
  ProfileView,
  SearchResult,
  OptInStatus,
} from './types'

export type {
  InitConfig,
  Conversation,
  Message,
  GroupMember,
  ProfileView,
  SearchResult,
  OptInStatus,
}

// ---------------------------------------------------------------------------
// Lazy WASM loader
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _wasmReady: Promise<any> | null = null

/**
 * Lazily load the catbird-mls-web WASM binary and return the module exports.
 * Safe to call multiple times — only loads once.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function getWasm(): Promise<any> {
  if (!_wasmReady) {
    _wasmReady = import('catbird-mls-web').then(async (mod) => {
      await mod.default()
      return mod
    })
  }
  return _wasmReady
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/**
 * Initialize the MLS WASM module. Must be called once at app startup.
 *
 * Loads the WASM binary, then calls `catbird_mls_init(config)`.
 */
export async function initMls(config: InitConfig): Promise<void> {
  const wasm = await getWasm()
  await wasm.catbird_mls_init(config)
}

/**
 * Smoke test — returns "catbird-mls-web ready" if WASM loaded successfully.
 */
export async function ping(): Promise<string> {
  const wasm = await getWasm()
  return wasm.catbird_mls_ping()
}

// ---------------------------------------------------------------------------
// Auth injection
// ---------------------------------------------------------------------------

/**
 * Set auth credentials. The host app calls this after its own login flow.
 * Persists the session to localStorage for future restores.
 */
export async function setAuth(did: string, token: string): Promise<void> {
  const wasm = await getWasm()
  wasm.catbird_mls_set_auth(did, token)
}

/**
 * Clear auth credentials and session storage.
 */
export async function clearAuth(): Promise<void> {
  const wasm = await getWasm()
  wasm.catbird_mls_clear_auth()
}

/**
 * Try to restore a previously saved session from localStorage.
 * Returns true if a session was restored, false otherwise.
 */
export async function tryRestoreSession(): Promise<boolean> {
  const wasm = await getWasm()
  return wasm.catbird_mls_try_restore_session()
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

export async function listConversations(): Promise<Conversation[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_list_conversations()
}

export async function createConversation(
  name: string,
  memberDids: string[],
): Promise<Conversation> {
  const wasm = await getWasm()
  return wasm.catbird_mls_create_conversation(name, memberDids)
}

export async function subscribe(
  convoId: string,
  onMessage: (msg: string) => void,
  onEvent: (evt: string) => void,
  onStatus: (status: string) => void,
): Promise<{ close(): void }> {
  const wasm = await getWasm()
  return wasm.catbird_mls_subscribe(convoId, onMessage, onEvent, onStatus)
}

export async function unsubscribe(
  convoId: string,
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_unsubscribe(convoId)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

export async function sendMessage(
  convoId: string,
  content: string,
): Promise<Message> {
  const wasm = await getWasm()
  return wasm.catbird_mls_send_message(convoId, content)
}

export async function messages(
  convoId: string,
  before?: string,
): Promise<Message[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_messages(convoId, before)
}

export async function fetchNewMessages(
  convoId: string,
): Promise<Message[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_fetch_new_messages(convoId)
}

export async function sendReaction(
  conversationId: string,
  messageId: string,
  emoji: string,
  action: 'add' | 'remove',
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_send_reaction(conversationId, messageId, emoji, action)
}

export async function updateCursor(
  conversationId: string,
  cursor: string,
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_update_cursor(conversationId, cursor)
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

export async function getMembers(
  conversationId: string,
): Promise<GroupMember[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_get_members(conversationId)
}

export async function addParticipants(
  conversationId: string,
  targetDid: string,
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_add_participants(conversationId, targetDid)
}

export async function demoteMember(
  conversationId: string,
  targetDid: string,
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_demote_member(conversationId, targetDid)
}

export async function removeParticipants(
  conversationId: string,
  targetDid: string,
): Promise<void> {
  const wasm = await getWasm()
  return wasm.catbird_mls_remove_participants(conversationId, targetDid)
}

// ---------------------------------------------------------------------------
// Profiles & Search
// ---------------------------------------------------------------------------

export async function getProfiles(dids: string[]): Promise<ProfileView[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_get_profiles(dids)
}

export async function searchUsers(query: string): Promise<SearchResult[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_search_users(query)
}

export async function checkOptInStatus(
  dids: string[],
): Promise<OptInStatus[]> {
  const wasm = await getWasm()
  return wasm.catbird_mls_check_opt_in_status(dids)
}

// ---------------------------------------------------------------------------
// Group metadata (encrypted-only path; MLS metadata cutover)
// ---------------------------------------------------------------------------

/**
 * Decrypted group metadata payload returned by `bootstrapGroupMetadata`
 * and `getGroupMetadata`. Mirrors `GroupMetadataV1` in the Rust core.
 *
 * `avatarBytesBase64` is the raw decoded avatar image bytes encoded as
 * base64 — render via `Blob`/`URL.createObjectURL`. See
 * `avatarBytesToObjectUrl` below.
 */
export interface GroupMetadata {
  title: string
  description: string
  avatarBlobLocator?: string | null
  avatarContentType?: string | null
  avatarBytesBase64?: string | null
  metadataVersion?: number
  epoch?: number
}

export interface UpdateMetadataResult {
  commitBytes: string
  ciphertext: string
  reference: {
    schema: string
    metadata_version: number
    blob_locator: string
    ciphertext_hash: number[]
  }
  metadataVersion: number
  epoch: number
}

/**
 * Bootstrap group metadata after a Welcome / external join / commit-merge.
 *
 * Hosts MUST call this:
 *   - After `process_welcome` returns successfully (new group joined).
 *   - After `merge_incoming_commit` for any incoming commit (an
 *     `updateMetadata` commit from a peer is otherwise invisible in JS).
 *   - After `create_external_commit` + merge during rejoin / first-responder
 *     reset bootstrap.
 *
 * Returns `null` if the group has no `MetadataReference` set (typical for
 * groups that haven't yet had an `updateMetadata` commit).
 *
 * The decrypted result is also persisted to the local OPFS-SQLite cache
 * so subsequent `listConversations` / `getGroupMetadata` calls return
 * the title / description / avatar without re-fetching.
 */
export async function bootstrapGroupMetadata(
  groupIdHex: string,
): Promise<GroupMetadata | null> {
  const wasm = await getWasm()
  const result = await wasm.wasm_bootstrap_group_metadata(groupIdHex)
  return result ?? null
}

/**
 * Update a group's title / description / avatar via the encrypted-blob
 * path. Stages a `GroupContextExtensions` commit, sends `updateMetadata`
 * to the server, merges locally, then encrypts and uploads the new blob.
 *
 * `avatarBytes` is raw image bytes (e.g. the contents of a File). If you
 * pass `avatarBytes`, also pass `avatarBlobLocator` (a fresh UUIDv4 lower-
 * case string) and `avatarContentType` (e.g. `"image/jpeg"`).
 */
export async function updateGroupMetadata(args: {
  conversationId: string
  title?: string
  description?: string
  avatarBlobLocator?: string
  avatarContentType?: string
  avatarBytes?: Uint8Array
}): Promise<UpdateMetadataResult> {
  const wasm = await getWasm()
  return wasm.catbird_mls_update_group_metadata(
    args.conversationId,
    args.title,
    args.description,
    args.avatarBlobLocator,
    args.avatarContentType,
    args.avatarBytes,
  )
}

/**
 * Read locally cached decrypted metadata for a group. Returns `null` if no
 * bootstrap has run yet for this group.
 */
export async function getGroupMetadata(
  conversationId: string,
): Promise<GroupMetadata | null> {
  const wasm = await getWasm()
  const result = wasm.catbird_mls_get_group_metadata(conversationId)
  return result ?? null
}

/**
 * Re-publish encrypted metadata after a server-initiated group reset.
 *
 * Call this from the reset-handling flow once the new group is joined and
 * the local epoch is stable. Re-encrypts the previously cached title /
 * description / avatar under the new group's epoch exporter and uploads
 * the blobs to the server.
 *
 * Returns `null` if there's nothing to republish (e.g. the conversation
 * never had any metadata).
 */
export async function republishMetadataAfterReset(
  newGroupIdHex: string,
  resetGeneration?: number | bigint,
): Promise<GroupMetadata | null> {
  const wasm = await getWasm()
  const arg =
    typeof resetGeneration === 'number'
      ? BigInt(resetGeneration)
      : resetGeneration
  const result = await wasm.wasm_republish_metadata_after_reset(
    newGroupIdHex,
    arg,
  )
  return result ?? null
}

/**
 * Convert base64-encoded avatar bytes (as returned by `bootstrapGroupMetadata`
 * / `getGroupMetadata`) into a Blob URL suitable for `<img src>`. Caller is
 * responsible for `URL.revokeObjectURL` when the avatar is no longer
 * displayed (e.g. on conversation header unmount).
 */
export function avatarBytesToObjectUrl(
  avatarBytesBase64: string,
  contentType: string | null | undefined,
): string {
  const binary = atob(avatarBytesBase64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  const blob = new Blob([bytes], { type: contentType ?? 'application/octet-stream' })
  return URL.createObjectURL(blob)
}

// ---------------------------------------------------------------------------
// Clean-chat signer bridge (Task 11)
// ---------------------------------------------------------------------------

/**
 * A prepared clean-chat request. `body` is present for POSTs (signed or
 * unsigned) and absent for GETs; `authorization`/`dpop` are intentionally not
 * exposed — the host attaches its own transport credentials.
 */
export interface PreparedCleanChatRequest {
  operation: string
  method: 'GET' | 'POST'
  path: string
  body?: string
}

/**
 * Install the browser-owned non-exporting Ed25519 signer for canonical
 * clean-chat preparation.
 *
 * The `CryptoKey` must be a **non-extractable, sign-only Ed25519 private key**
 * (e.g. generated with `crypto.subtle.generateKey({ name: 'Ed25519' }, false,
 * ['sign'])`). Extractable or raw-imported keys are rejected before any WASM
 * bridge state is installed. Only the public key and a signing callback cross
 * into WASM — no private key bytes, access token, DPoP proof, or JKT is ever
 * exported.
 */
export async function installCleanChatSigner(params: {
  actorDid: string
  deviceId: string
  dpopJkt: string
  publicKey: Uint8Array
  key: CryptoKey
  authGeneration?: bigint
}): Promise<void> {
  assertSignerKeyCustody(params.key)
  const wasm = await getWasm()
  const sign = (transcript: Uint8Array): Promise<Uint8Array> => {
    // Copy into an ArrayBuffer-backed view so WebCrypto's BufferSource
    // requirement is satisfied regardless of the caller's buffer type.
    const buffer = new Uint8Array(transcript)
    return crypto.subtle
      .sign({ name: 'Ed25519' }, params.key, buffer)
      .then((signature) => new Uint8Array(signature))
  }
  wasm.catbird_mls_set_signer_bridge(
    sign,
    params.key,
    params.actorDid,
    params.deviceId,
    params.dpopJkt,
    params.publicKey,
    params.authGeneration ?? null,
  )
}

/**
 * Throw unless `key` satisfies the clean-chat signer custody contract: a
 * private, non-extractable, sign-only Ed25519 `CryptoKey`.
 */
export function assertSignerKeyCustody(key: CryptoKey): void {
  if (key.type !== 'private') {
    throw new Error('clean-chat signer key must be a private CryptoKey')
  }
  if (key.extractable) {
    throw new Error(
      'clean-chat signer key must be non-extractable (extractable or raw-imported keys are rejected)',
    )
  }
  if (key.algorithm.name !== 'Ed25519') {
    throw new Error('clean-chat signer key must use the Ed25519 algorithm')
  }
  const usages = Array.from(key.usages)
  if (usages.length !== 1 || usages[0] !== 'sign') {
    throw new Error(
      'clean-chat signer key must be sign-only (usages exactly ["sign"])',
    )
  }
}

/** Clear the installed clean-chat signer bridge (if any). */
export async function clearCleanChatSigner(): Promise<void> {
  const wasm = await getWasm()
  wasm.catbird_mls_clear_signer_bridge()
}

/** Whether a clean-chat signer bridge is currently installed. */
export async function hasCleanChatSigner(): Promise<boolean> {
  const wasm = await getWasm()
  return Boolean(wasm.catbird_mls_has_signer_bridge())
}

/**
 * Prepare an unsigned generated clean-chat request (reads and
 * `getSubscriptionTicket`). Unknown raw query keys are rejected.
 */
export async function prepareUnsignedCleanChatRequest(
  operation: string,
  requestJson: string,
): Promise<PreparedCleanChatRequest> {
  const wasm = await getWasm()
  return wasm.catbird_mls_prepare_unsigned_request(operation, requestJson) as PreparedCleanChatRequest
}

/**
 * Prepare a signed clean-chat mutation through the approved Rust strict
 * projector. Validation structurally precedes signing; the signer bridge must
 * already be installed via `installCleanChatSigner`.
 */
export async function prepareSignedCleanChatRequest(
  operation: string,
  requestJson: string,
): Promise<PreparedCleanChatRequest> {
  const wasm = await getWasm()
  return (await wasm.catbird_mls_prepare_signed_request(
    operation,
    requestJson,
  )) as PreparedCleanChatRequest
}
