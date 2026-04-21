/**
 * catbird-mls-web shared TypeScript types.
 *
 * These mirror the Rust `#[wasm_bindgen]` data structures in lib.rs.
 * Any web app consuming the universal package should import types from here.
 */

export interface InitConfig {
  baseUrl: string
  /** localStorage key prefix. Default: "catbird_mls" */
  storagePrefix?: string
  /** IndexedDB / SQLite name prefix. Default: "catbird-mls" */
  dbPrefix?: string
}

export interface Conversation {
  id: string
  displayName: string
  members: string[]
  lastMessage?: string
  lastMessageAt?: string
  unreadCount: number
  isGroup: boolean
}

export interface Message {
  id: string
  conversationId: string
  senderDid: string
  senderHandle: string
  content: string
  timestamp: string
  status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed'
  messageType?: 'text' | 'system' | 'event'
  reactions?: Record<string, string[]>
}

export interface GroupMember {
  did: string
  handle: string
  displayName?: string
  role: string
}

export interface ProfileView {
  did: string
  handle: string
  displayName?: string
  avatar?: string
}

export interface SearchResult {
  did: string
  handle: string
  displayName?: string
  avatar?: string
}

export interface OptInStatus {
  did: string
  optedIn: boolean
}
