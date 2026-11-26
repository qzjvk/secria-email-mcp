# Secria Email MCP

A Dockerised, API-key-protected MCP server that gives an AI assistant **read, search and compose/send** access to a Secria Mail inbox.

It speaks Secria's own REST API and uses [Secria's published crypto library](https://github.com/Secria/secria-crypto) to derive your login hash and vault key on the server and decrypt messages locally. It does **not** scrape the web UI and it does **not** ask Secria's servers for plaintext or private keys.

## Disclaimer — read before using

This is an **unofficial, experimental project**. It is not built by, affiliated with, or endorsed by Secria. It relies on Secria's undocumented internal web-app API, which can change without notice and may stop working at any time.

**It handles your mail in decrypted form.** Secria is a zero-access service: normally only your own device can read your mailbox. This server deliberately breaks that property on purpose. It signs in with your password, derives your keys, and decrypts messages **inside the Docker container**. Anyone who can access that host, the container, its logs, its filesystem, or the API key can potentially read your mail and send mail as you. A bug, a bad configuration, an exposed port, a stolen API key, or a change in Secria's service could expose private messages or send mail you did not intend to send. Sending to an address outside Secria necessarily sends a plaintext copy through Secria's mail server.

Use it only on hardware and a network you trust, with a dedicated API key, and understand the risks before putting real credentials into it.

**No warranty; no responsibility.** This software is provided "as is", without warranty of any kind, express or implied. The author is not responsible for any loss of data, unintended messages, exposure of private information, security incidents, service interruptions, or any other damage arising from its use. You assume all risk.

## Tools

| Tool | What it does |
| --- | --- |
| `secria_get_me` | Signed-in address and aliases |
| `secria_list_messages` | List/decrypt a folder (inbox, sent, drafts, archive, trash, starred, all) |
| `secria_search_messages` | Server-side search + decrypt results |
| `secria_read_thread` | Read every decrypted message in a thread |
| `secria_send_message` | **Two-step send**: preview first, then `confirm: true` |

## Deploy on the Docker host

Copy this directory to `~/docker/secria-mcp` on the host, then:

```sh
cd ~/docker/secria-mcp
cp .env.example .env
# edit .env: set SECRIA_EMAIL, SECRIA_PASSWORD and a fresh MCP_API_KEY
docker compose up -d --build
curl http://127.0.0.1:8787/healthz
```

`MCP_API_KEY` is the key **your client** presents to this server. Generate one with:

```sh
openssl rand -hex 32
```

Port is configurable via `PORT` (default `8787`).

## Connect OpenCode

Remote MCP servers use OAuth by default, so set `oauth: false` for this API-key server. Prefer an environment variable over writing the key in config:

```jsonc title="~/.config/opencode/opencode.jsonc"
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "secria": {
        "type": "remote",
        "url": "http://192.168.1.126:8787/mcp",
        "oauth": false,
        "headers": {
          "Authorization": "Bearer {env:MCP_API_KEY}"
        }
      }
    }
  }
}
```

Or from the CLI:

```sh
opencode mcp add secria --global \
  --url http://192.168.1.126:8787/mcp \
  --header 'Authorization=Bearer {env:MCP_API_KEY}'
opencode mcp list
```

Set `MCP_API_KEY` in the environment where OpenCode runs. Config changes hot-reload; use `/reload` to force it.

## Security notes

- The container binds `0.0.0.0:8787`. Put it behind a firewall, a VPN, or a reverse proxy if the LAN is not trusted. The API key is the only client credential.
- Your Secria password is only used at startup to derive keys. It is passed through `.env`, never baked into the image.
- Sending to a non-Secria address necessarily sends a plaintext copy through Secria's server. The tool reports which recipients were Secria-encrypted and which were outside.

## Limitations

- Sending is plain text only; no attachments, HTML, drafts, or scheduled sends yet.
- Archived key sets are not loaded, so mail wrapped to an old key set after an account reset may not decrypt.
- The server relies on Secria's web-app API, which is undocumented and can change. If logins or reads start failing after a Secria update, that is the first place to look.
