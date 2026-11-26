import { randomBytes } from 'node:crypto'
import {
  deriveLoginHash,
  deriveLoginHashV1,
  deriveVaultKey,
  deriveVaultKeyV1,
  openBody,
  openSelfWrap,
  openWrap,
  parsePublicKeySet,
  sealBody,
  sealSelfWrap,
  sealWrap,
  unwrapKeySet,
  type PrivateKeySet,
  type PublicKeySet,
} from '@secria/crypto'

export type Folder = 'inbox' | 'sent' | 'drafts' | 'archive' | 'trash' | 'starred' | 'all'

export interface ListOptions {
  folder?: Folder
  query?: string
  limit?: number
  unreadOnly?: boolean
  messageId?: string
}

export interface DecryptedMessage {
  id: string
  messageId: string
  threadId?: string
  from?: string
  to?: string | string[]
  subject?: string
  date?: string
  body: string
  format: 1 | 2
  unread?: boolean
  starred?: boolean
  flags?: Record<string, unknown>
}

export interface SendOptions {
  to: string[]
  subject: string
  body: string
  cc?: string[]
  replyTo?: string
}

interface ApiResponse {
  success?: boolean
  data?: any
  [key: string]: unknown
}

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64')
const unb64 = (value: unknown): Uint8Array => {
  if (typeof value !== 'string' || value.length === 0) return new Uint8Array(0)
  return new Uint8Array(Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
}

/**
 * A small client for the same REST API the Secria web app uses.
 * Decryption and message wrapping use Secria's published secria-crypto package,
 * so the server never asks Secria's servers for plaintext or private keys.
 */
export class SecriaClient {
  private readonly email: string
  private readonly password: string
  private readonly baseUrl: string
  private cookies = new Map<string, string>()
  private csrfToken?: string
  private keys?: PrivateKeySet
  private publicKeys?: PublicKeySet
  private user: any
  private loginPromise?: Promise<void>

  constructor(opts: { email: string; password: string; baseUrl?: string }) {
    this.email = opts.email.trim().toLowerCase()
    this.password = opts.password
    this.baseUrl = (opts.baseUrl ?? 'https://app.secria.me/api').replace(/\/$/, '')
    if (!this.email || !this.password) throw new Error('SECRIA_EMAIL and SECRIA_PASSWORD are required')
  }

  private async request(method: string, path: string, body?: unknown): Promise<ApiResponse> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (this.cookies.size) {
      headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
    }
    if (this.csrfToken && method !== 'GET') headers['X-CSRF-Token'] = this.csrfToken

    const response = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    })

    for (const raw of response.headers.getSetCookie()) {
      const first = raw.split(';', 1)[0]
      const at = first.indexOf('=')
      if (at > 0) {
        const name = first.slice(0, at).trim()
        const value = first.slice(at + 1).trim()
        if (value) this.cookies.set(name, value)
        else this.cookies.delete(name)
      }
    }
    if (response.status === 401 || response.status === 403) {
      this.keys = undefined
      throw new Error(`Secria session expired (HTTP ${response.status}). Re-login is required.`)
    }
    if (!response.ok) {
      const text = await response.text().catch(() => '')
      throw new Error(`Secria API ${method} ${path} failed: HTTP ${response.status} ${text.slice(0, 300)}`)
    }
    return (await response.json()) as ApiResponse
  }

  private async refreshCsrf(): Promise<void> {
    // The web app fetches a token for some admin routes. Mutating user routes
    // may or may not require it, so treat it as best-effort.
    try {
      const res = await this.request('GET', '/csrf/token')
      const token = res.csrf_token ?? (res.data as any)?.csrf_token
      if (typeof token === 'string') this.csrfToken = token
    } catch {
      this.csrfToken = undefined
    }
  }

  async login(): Promise<void> {
    if (this.keys) return
    if (!this.loginPromise) {
      this.loginPromise = this.doLogin().finally(() => {
        this.loginPromise = undefined
      })
    }
    return this.loginPromise
  }

  private async doLogin(): Promise<void> {
    await this.refreshCsrf()
    const [password, passwordV2] = await Promise.all([
      deriveLoginHashV1(this.email, this.password),
      deriveLoginHash(this.email, this.password),
    ])
    const res = await this.request('POST', '/auth/login', {
      email: this.email,
      password,
      password_v2: passwordV2,
      keep_signed_in: true,
      recovery_gate: true,
    })
    if (!res.success || !res.data) {
      throw new Error(`Secria login failed: ${String(res.data ?? res.error ?? 'unknown error')}`)
    }
    this.user = res.data
    // Now that the session cookie exists, refresh the CSRF token if the app issues one.
    await this.refreshCsrf()

    const v2 = res.data.main_key_v2
    const v1 = res.data.main_key
    const main = v2?.key_id ? v2 : v1
    if (!main?.key_id) throw new Error('Secria account has no usable key set')

    const vaultKey = v2?.key_id
      ? await deriveVaultKey(this.email, this.password)
      : await deriveVaultKeyV1(this.email, this.password)

    this.publicKeys = parsePublicKeySet(unb64(main.dh_public_key), unb64(main.mlkem_public_key))
    this.keys = await unwrapKeySet(
      vaultKey,
      {
        x25519: unb64(main.dh_private_key_encrypted),
        mlkem1024: unb64(main.mlkem_private_key_encrypted),
        self: unb64(main.sent_key),
      },
      this.publicKeys,
    )
  }

  private async decrypt(row: any): Promise<DecryptedMessage | null> {
    if (!this.keys) await this.login()
    if (!row) return null
    if (row.body === undefined || row.body === null || row.body === '') {
      // Some server-side notices carry no encrypted body.
      return {
        id: String(row.id ?? row.message_id ?? ''),
        messageId: String(row.message_id ?? ''),
        threadId: row.thread_id ? String(row.thread_id) : undefined,
        from: row.from,
        to: row.to,
        subject: row.subject,
        date: row.date ?? row.sent_at ?? row.created_at,
        body: '',
        format: row.cipher === 2 ? 2 : 1,
        unread: row.read === false,
        starred: !!row.starred,
      }
    }
    try {
      const hasRecipientWrap = !!row.ciphertext && !!row.dh_public && !!row.encrypted_key && !!row.salt
      const messageKey = hasRecipientWrap
        ? await openWrap(this.keys!, unb64(row.dh_public), {
            kemCiphertext: unb64(row.ciphertext),
            salt: unb64(row.salt),
            wrappedKey: unb64(row.encrypted_key),
          })
        : await openSelfWrap(this.keys!.selfKey, {
            salt: unb64(row.salt),
            wrappedKey: unb64(row.encrypted_key),
          })
      const opened = await openBody(messageKey, unb64(row.body), row.cipher === 2 ? 'v2-only' : 'auto')
      const body = new TextDecoder().decode(opened.plaintext).replace(/\r\n/g, '\n')
      return {
        id: String(row.id ?? row.message_id ?? ''),
        messageId: String(row.message_id ?? ''),
        threadId: row.thread_id ? String(row.thread_id) : undefined,
        from: row.from,
        to: row.to,
        subject: row.subject,
        date: row.date ?? row.sent_at ?? row.created_at,
        body,
        format: opened.format,
        unread: row.read === false,
        starred: !!row.starred,
        flags: {
          draft: !!row.draft,
          archived: !!row.archived,
          deleted: !!row.deleted,
          flagged: !!row.flagged,
          attachments: Array.isArray(row.attachments) ? row.attachments.length : 0,
        },
      }
    } catch (error) {
      // One undecryptable row must not hide the rest of the folder.
      return {
        id: String(row.id ?? row.message_id ?? ''),
        messageId: String(row.message_id ?? ''),
        from: row.from,
        to: row.to,
        subject: row.subject,
        date: row.date ?? row.sent_at ?? row.created_at,
        body: `[undecryptable: ${error instanceof Error ? error.message : String(error)}]`,
        format: row.cipher === 2 ? 2 : 1,
        flags: { decryptError: true },
      }
    }
  }

  async listMessages(opts: ListOptions = {}): Promise<DecryptedMessage[]> {
    await this.login()
    const limit = Math.min(Math.max(opts.limit ?? 25, 1), 100)
    const params = new URLSearchParams({ count: String(limit), skip: '0' })
    switch (opts.folder ?? 'inbox') {
      case 'sent':
        params.set('sent', 'true')
        break
      case 'drafts':
        params.set('draft', 'true')
        break
      case 'archive':
        params.set('archived', 'true')
        break
      case 'trash':
        params.set('deleted', 'true')
        break
      case 'starred':
        params.set('starred', 'true')
        break
      case 'all':
        break
      default:
        params.set('sent', 'false')
    }
    if (opts.unreadOnly) params.set('read', 'false')
    if (opts.query) {
      params.set('search', b64(new TextEncoder().encode(opts.query)))
    }
    if (opts.messageId) {
      params.set('message_id', b64(new TextEncoder().encode(opts.messageId)))
      params.set('threading', 'true')
    }

    const res = await this.request('GET', `/user/query?${params.toString()}`)
    if (!res.success) throw new Error(`Secria query failed: ${String(res.data ?? 'unknown error')}`)
    const rows = Array.isArray(res.data) ? res.data : []
    const out: DecryptedMessage[] = []
    for (const row of rows) {
      const message = await this.decrypt(row)
      if (message) out.push(message)
    }
    return out
  }

  async readThread(messageId: string, limit = 20): Promise<DecryptedMessage[]> {
    return this.listMessages({ messageId, limit })
  }

  async getMe(): Promise<Record<string, unknown>> {
    await this.login()
    return {
      email: this.email,
      addresses: this.user?.addresses ?? [],
      displayNames: this.user?.address_display_names ?? [],
      plan: this.user?.plan ?? this.user?.plan_config,
    }
  }

  async sendMessage(opts: SendOptions): Promise<Record<string, unknown>> {
    await this.login()
    if (!this.keys || !this.publicKeys) throw new Error('Secria keys are not available')
    const to = opts.to.map((a) => a.trim().toLowerCase()).filter(Boolean)
    const cc = (opts.cc ?? []).map((a) => a.trim().toLowerCase()).filter(Boolean)
    if (!to.length) throw new Error('At least one recipient is required')
    if (!opts.subject?.trim()) throw new Error('A subject is required')
    if (!opts.body?.trim()) throw new Error('A message body is required')

    const uniqueRecipients = [...new Set([...to, ...cc])]
    let directory: any[] = []
    try {
      const info = await this.request('POST', '/user/keys', { users: uniqueRecipients })
      if (info.success && Array.isArray(info.data)) directory = info.data
    } catch {
      // An address outside Secria has no directory entry; treat it as external.
    }
    const directoryByEmail = new Map(directory.map((u) => [String(u.email).toLowerCase(), u]))

    const messageKey = new Uint8Array(randomBytes(32))
    const sealed = b64(await sealBody(messageKey, new TextEncoder().encode(opts.body)))
    const selfWrap = await sealSelfWrap(this.keys.selfKey, messageKey)

    const recipients: any[] = []
    for (const address of uniqueRecipients) {
      const entry: any = {
        email: address,
        to: to.includes(address) || undefined,
        cc: cc.includes(address) || undefined,
      }
      const remote = directoryByEmail.get(address)
      if (remote?.mlkem_public && remote?.dh_public) {
        try {
          const pub = parsePublicKeySet(unb64(remote.dh_public), unb64(remote.mlkem_public))
          const wrap = await sealWrap(this.keys.x25519, pub, messageKey)
          entry.ciphertext = b64(wrap.kemCiphertext)
          entry.encrypted_key = b64(wrap.wrappedKey)
          entry.salt = b64(wrap.salt)
          entry.key_used = b64(pub.keyId)
          entry.plaintext = false
        } catch {
          // Fall back to a plaintext outside copy if the directory entry is unusable.
          entry.plaintext = true
        }
      } else {
        entry.plaintext = true
      }
      recipients.push(entry)
    }
    recipients.push({
      email: this.email,
      sender: true,
      encrypted_key: b64(selfWrap.wrappedKey),
      salt: b64(selfWrap.salt),
      key_used: b64(this.keys.publicKey.keyId),
      plaintext: false,
    })

    const hasOutside = recipients.some((r) => r.plaintext === true)
    let outsideBody: string | undefined
    let encryptionKey: string | undefined
    if (hasOutside) {
      // Secria's server needs a plaintext outside copy for non-Secria recipients.
      const outsideKey = new Uint8Array(randomBytes(32))
      outsideBody = b64(await sealBody(outsideKey, new TextEncoder().encode(opts.body)))
      encryptionKey = b64(outsideKey)
    }

    const payload: Record<string, unknown> = {
      used_address: this.email,
      to: recipients,
      public_key: b64(this.publicKeys.x25519),
      subject: opts.subject,
      body: sealed,
      cipher: 2,
      content_type: 'text/plain; charset=utf-8',
      boundary: `secria_${randomBytes(16).toString('hex')}`,
      reply_to: opts.replyTo,
      outside_body: outsideBody,
      encryption_key: encryptionKey,
      client_id: randomBytes(12).toString('hex'),
    }
    const res = await this.request('POST', '/user/send_private', payload)
    if (!res.success) throw new Error(`Secria send failed: ${String(res.data ?? 'unknown error')}`)
    return {
      success: true,
      data: res.data,
      secriaRecipients: recipients.filter((r) => r.plaintext === false).map((r) => r.email),
      outsideRecipients: recipients.filter((r) => r.plaintext === true).map((r) => r.email),
    }
  }
}
