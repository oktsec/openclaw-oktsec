# @oktsec/openclaw

[![npm version](https://img.shields.io/npm/v/@oktsec/openclaw)](https://www.npmjs.com/package/@oktsec/openclaw)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![oktsec](https://img.shields.io/badge/powered%20by-oktsec-8b7cf7)](https://github.com/oktsec/oktsec)

Runtime security plugin for OpenClaw. Intercepts agent tool calls and messages, scans through 188 detection rules, and blocks threats before execution.

## Install

```bash
openclaw plugins install @oktsec/openclaw
```

## Prerequisites

oktsec gateway must be running:

```bash
brew install oktsec/tap/oktsec
oktsec run
```

## Quick start

1. Install the plugin: `openclaw plugins install @oktsec/openclaw`
2. Start oktsec: `oktsec run`
3. Start OpenClaw: `openclaw gateway`
4. Send a message via Telegram, Discord, or the web chat
5. Open the oktsec dashboard to see every event in real-time

## What it intercepts

| Event | Hook | Direction |
|-------|------|-----------|
| Incoming messages | `message_received` | User -> Agent |
| Outgoing messages | `message_sending` / `message_sent` | Agent -> User |
| Tool calls (before) | `before_tool_call` | Agent -> Tool |
| Tool results (after) | `after_tool_call` | Tool -> Agent |

Every intercepted event is scanned through oktsec's security pipeline:

- **188 detection rules** across 15 categories (prompt injection, credential leaks, data exfiltration, supply chain, MCP attacks, and more)
- **4 verdicts**: clean, flag, quarantine, block
- **Tamper-evident audit trail** with SHA-256 hash chain and Ed25519 signatures
- **Real-time dashboard** and terminal UI

In enforce mode, threats are blocked before they execute. In observe mode, everything is logged without blocking.

## Configuration

The plugin works out of the box with default settings. To customize, edit your OpenClaw config:

```json
{
  "plugins": {
    "entries": {
      "oktsec": {
        "enabled": true,
        "config": {
          "gatewayUrl": "http://127.0.0.1:9090",
          "mode": "enforce",
          "agent": "openclaw"
        }
      }
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `gatewayUrl` | `http://127.0.0.1:9090` | oktsec gateway endpoint |
| `mode` | `enforce` | `enforce` blocks threats, `observe` logs only |
| `agent` | `openclaw` | Agent name in oktsec dashboard |

## Commands

### Chat (slash command)

```
/oktsec status     # Pipeline health, stats, dashboard URL
/oktsec dashboard  # Show dashboard URL
```

### CLI

```bash
openclaw oktsec status       # Gateway health and pipeline stats
openclaw oktsec logs -f      # Stream audit events in real-time
openclaw oktsec dashboard    # Open dashboard in browser
```

## How it works

```
User (Telegram/Discord/Web)
  │
  ▼
OpenClaw Gateway
  │
  ├── oktsec plugin ──► oktsec gateway (188 rules)
  │                         │
  │                     allow / block
  │                         │
  ▼                         ▼
Agent (Claude/GPT)      Audit trail
  │                    (SHA-256 + Ed25519)
  ├── tool call ──► oktsec plugin ──► scan ──► allow/block
  │
  ▼
Response
```

The plugin is a thin TypeScript client. All detection, policy enforcement, and audit logging runs in the oktsec Go binary. If the oktsec gateway is unreachable, the plugin fails open and does not block agent work.

## Works with NemoClaw

oktsec and NemoClaw are complementary OpenClaw plugins:

| Layer | NemoClaw | oktsec |
|-------|----------|--------|
| **What** | Sandbox isolation + NVIDIA inference | Content detection + audit trail |
| **How** | Container boundaries, network allowlists | 188 detection rules, tool-level scanning |
| **Blocks** | Unauthorized network connections | Prompt injection, credential leaks, exfiltration |

Install both for defense in depth:

```bash
openclaw plugins install @oktsec/openclaw
openclaw plugins install nemoclaw
```

## Links

- [oktsec](https://github.com/oktsec/oktsec) - Runtime security for AI agents
- [oktsec.com](https://oktsec.com) - Product website
- [OpenClaw](https://openclaw.ai) - AI agent framework
- [NemoClaw](https://github.com/NVIDIA/NemoClaw) - NVIDIA sandbox plugin

## License

Apache 2.0
