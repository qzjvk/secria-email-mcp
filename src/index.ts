import { timingSafeEqual } from 'node:crypto'
import express from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'
import { SecriaClient } from './secria-client.js'

const PORT = Number(process.env.PORT ?? 8787)
const API_KEY = process.env.MCP_API_KEY
if (!API_KEY) {
  console.error('MCP_API_KEY must be set')
  process.exit(1)
}
if (!process.env.SECRIA_EMAIL || !process.env.SECRIA_PASSWORD) {
  console.error('SECRIA_EMAIL and SECRIA_PASSWORD must be set')
  process.exit(1)
}

const secria = new SecriaClient({
  email: process.env.SECRIA_EMAIL,
  password: process.env.SECRIA_PASSWORD,
  baseUrl: process.env.SECRIA_BASE_URL,
})

const toolResult = (value: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }],
})
const toolError = (error: unknown) => ({
  isError: true as const,
  content: [
    {
      type: 'text' as const,
      text: `Secria MCP error: ${error instanceof Error ? error.message : String(error)}`,
    },
  ],
})

function registerTools(server: McpServer): void {
  server.registerTool(
    'secria_get_me',
    {
      title: 'Secria account info',
      description: 'Show the signed-in Secria address and its aliases. Use this to choose a sender address.',
      inputSchema: {},
    },
    async () => {
      try {
        return toolResult(await secria.getMe())
      } catch (error) {
        return toolError(error)
      }
    },
  )

  server.registerTool(
    'secria_list_messages',
    {
      title: 'List Secria mail',
      description:
        'List messages from a Secria Mail folder with decrypted, readable bodies. Folders: inbox, sent, drafts, archive, trash, starred, all.',
      inputSchema: {
        folder: z
          .enum(['inbox', 'sent', 'drafts', 'archive', 'trash', 'starred', 'all'])
          .optional()
          .describe('Folder to list. Defaults to inbox.'),
        query: z.string().optional().describe('Server-side search string.'),
        limit: z.number().int().min(1).max(100).optional().describe('Maximum messages, 1-100.'),
        unreadOnly: z.boolean().optional().describe('Only return unread messages.'),
      },
    },
    async ({ folder, query, limit, unreadOnly }) => {
      try {
        const messages = await secria.listMessages({ folder, query, limit, unreadOnly })
        return toolResult({ count: messages.length, messages })
      } catch (error) {
        return toolError(error)
      }
    },
  )

  server.registerTool(
    'secria_search_messages',
    {
      title: 'Search Secria mail',
      description: 'Search all Secria mail for a phrase and return decrypted matching messages.',
      inputSchema: {
        query: z.string().min(1).describe('Text to search for.'),
        folder: z
          .enum(['inbox', 'sent', 'drafts', 'archive', 'trash', 'starred', 'all'])
          .optional()
          .describe('Limit the search to one folder.'),
        limit: z.number().int().min(1).max(100).optional().describe('Maximum messages, 1-100.'),
      },
    },
    async ({ query, folder, limit }) => {
      try {
        const messages = await secria.listMessages({ query, folder: folder ?? 'all', limit })
        return toolResult({ query, count: messages.length, messages })
      } catch (error) {
        return toolError(error)
      }
    },
  )

  server.registerTool(
    'secria_read_thread',
    {
      title: 'Read a Secria thread',
      description: 'Read every decrypted message in a Secria thread by message id.',
      inputSchema: {
        messageId: z.string().min(1).describe('Message id from secria_list_messages or search.'),
        limit: z.number().int().min(1).max(50).optional().describe('Maximum messages in the thread.'),
      },
    },
    async ({ messageId, limit }) => {
      try {
        const messages = await secria.readThread(messageId, limit)
        return toolResult({ messageId, count: messages.length, messages })
      } catch (error) {
        return toolError(error)
      }
    },
  )

  server.registerTool(
    'secria_send_message',
    {
      title: 'Send Secria mail',
      description:
        'Compose and send a message from your Secria address. Call once without confirm to preview, then again with confirm=true to actually send. Secria recipients stay end-to-end encrypted; outside recipients get the plaintext body.',
      inputSchema: {
        to: z.array(z.string().email()).min(1).describe('Recipient email addresses.'),
        subject: z.string().min(1).describe('Message subject.'),
        body: z.string().min(1).describe('Plain-text message body.'),
        cc: z.array(z.string().email()).optional().describe('Carbon-copy addresses.'),
        replyTo: z.string().email().optional().describe('Optional reply-to address.'),
        confirm: z
          .boolean()
          .optional()
          .describe('Must be true to send. Omit or false to only preview the message.'),
      },
      annotations: { destructiveHint: true },
    },
    async ({ to, subject, body, cc, replyTo, confirm }) => {
      if (!confirm) {
        return toolResult({
          previewOnly: true,
          message: 'Nothing was sent. Call again with confirm=true to send.',
          to,
          cc,
          subject,
          body,
        })
      }
      try {
        const sent = await secria.sendMessage({ to, subject, body, cc, replyTo })
        return toolResult(sent)
      } catch (error) {
        return toolError(error)
      }
    },
  )
}

async function main(): Promise<void> {
  const app = express()
  app.disable('x-powered-by')
  app.use(express.json({ limit: '2mb' }))

  app.get('/healthz', (_req, res) => res.json({ ok: true }))

  app.use((req, res, next) => {
    const header = req.header('authorization') ?? ''
    const bearer = header.toLowerCase().startsWith('bearer ') ? header.slice(7) : ''
    const supplied = req.header('x-api-key') ?? bearer
    const expected = Buffer.from(API_KEY!)
    const actual = Buffer.from(supplied ?? '')
    const ok =
      actual.length === expected.length &&
      timingSafeEqual(actual, expected) &&
      actual.length > 0
    if (!ok) {
      res.status(401).json({ error: 'Invalid or missing API key' })
      return
    }
    next()
  })

  const createServer = (): McpServer => {
    const server = new McpServer({ name: 'secria-email-mcp', version: '1.0.0' })
    registerTools(server)
    return server
  }

  // Stateless Streamable HTTP: each request gets its own server + transport.
  app.post('/mcp', async (req, res) => {
    const server = createServer()
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    })
    try {
      await server.connect(transport)
      await transport.handleRequest(req, res, req.body)
    } catch (error) {
      console.error('MCP request failed:', error)
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        })
      }
    } finally {
      res.on('close', () => {
        void transport.close()
        void server.close()
      })
    }
  })

  app.get('/mcp', (_req, res) => {
    res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed.' },
      id: null,
    })
  })
  app.delete('/mcp', (_req, res) => {
    res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed.' },
      id: null,
    })
  })

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Secria email MCP listening on http://0.0.0.0:${PORT}/mcp`)
  })
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
