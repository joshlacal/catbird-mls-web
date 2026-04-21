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
