/**
 * oktsec plugin for OpenClaw.
 * Uses api.on() hooks for tool call interception and message scanning.
 */

import { OktsecClient, type OktsecConfig } from "./client.js";

interface OpenClawPluginApi {
  id: string;
  name: string;
  version: string;
  config: Record<string, unknown>;
  pluginConfig: Record<string, unknown>;
  logger: {
    info(msg: string): void;
    warn(msg: string): void;
    error(msg: string): void;
    debug(msg: string): void;
  };
  registerCommand: (...args: unknown[]) => void;
  on: (hookName: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }) => void;
  [key: string]: unknown;
}

function resolveConfig(api: OpenClawPluginApi): OktsecConfig {
  const pc = api.pluginConfig || {};
  return {
    gatewayUrl: (pc.gatewayUrl as string) || "http://127.0.0.1:9090",
    dashboardUrl: (pc.dashboardUrl as string) || "http://127.0.0.1:8080/dashboard",
    agent: (pc.agent as string) || "openclaw",
    mode: ((pc.mode as string) || "enforce") as "enforce" | "observe",
  };
}

export default function register(api: OpenClawPluginApi) {
  const config = resolveConfig(api);
  const client = new OktsecClient(config);
  const log = api.logger;

  // 1. Intercept tool calls BEFORE execution
  api.on("before_tool_call", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = ctx as Record<string, unknown>;
    const toolName = String(e.toolName || e.name || "unknown");
    const toolInput = JSON.stringify(e.input || e.args || {});

    log.info(`oktsec: before_tool_call ${toolName}`);

    try {
      const decision = await client.sendToolEvent({
        tool_name: toolName,
        tool_input: toolInput,
        event: "pre_tool_call",
        agent: String(c.agentId || config.agent),
        session_id: String(c.sessionKey || ""),
      });

      log.info(`oktsec: decision=${decision.decision} for ${toolName}`);

      if (decision.decision === "block" && config.mode === "enforce") {
        log.warn(`oktsec BLOCKED tool ${toolName}: ${decision.reason}`);
        return { block: true, message: `oktsec: ${decision.reason}` };
      }
    } catch (err) {
      log.warn(`oktsec: forward failed: ${err}`);
    }
    return undefined;
  });

  // 2. Scan incoming messages
  api.on("message_received", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = ctx as Record<string, unknown>;
    const content = String(e.content || e.body || "");

    log.info(`oktsec: message_received len=${content.length} from=${c.channelId || "web"}`);

    if (!content) return;

    try {
      const decision = await client.sendToolEvent({
        tool_name: "message",
        tool_input: content,
        event: "pre_tool_call",
        agent: String(c.senderId || config.agent),
        session_id: String(c.sessionKey || ""),
      });

      log.info(`oktsec: message decision=${decision.decision}`);

      if (decision.decision === "block" && config.mode === "enforce") {
        log.warn(`oktsec BLOCKED message: ${decision.reason}`);
      }
    } catch (err) {
      log.warn(`oktsec: message forward failed: ${err}`);
    }
  });

  // 3. Audit outgoing messages
  api.on("message_sent", async (event: unknown) => {
    const e = event as Record<string, unknown>;
    const content = String(e.content || e.body || "");
    if (!content) return;

    try {
      await client.sendToolEvent({
        tool_name: "message_out",
        tool_input: content,
        event: "post_tool_call",
        agent: config.agent,
      });
      log.info("oktsec: message_sent forwarded");
    } catch (err) {
      log.warn(`oktsec: message_sent forward failed: ${err}`);
    }
  });

  // 4. LLM input monitoring
  api.on("llm_input", async (event: unknown, ctx: unknown) => {
    const c = ctx as Record<string, unknown>;
    log.info(`oktsec: llm_input agent=${c.agentId || "main"}`);
  });

  // 5. Slash command
  try {
    api.registerCommand({
      name: "oktsec",
      description: "Security status and controls",
      handler: async (ctx: Record<string, unknown>) => {
        const args = String(ctx.args || "").trim().split(/\s+/)[0] || "status";
        if (args === "status") {
          const health = await client.health();
          if (!health) return { reply: "oktsec gateway not reachable. Start with: oktsec run" };
          const stats = await client.stats();
          let out = `oktsec: ${health.status} (${config.mode} mode)\n`;
          if (stats) {
            out += `Pipeline: ${stats.total} events, ${stats.blocked} blocked, ${stats.quarantined} quarantined\n`;
          }
          out += `Dashboard: ${config.dashboardUrl}`;
          return { reply: out };
        }
        return { reply: "Usage: /oktsec [status|dashboard]" };
      },
    });
  } catch (e) {
    log.warn("oktsec: registerCommand failed: " + String(e));
  }

  log.info(`oktsec plugin loaded (${config.mode} mode, gateway: ${config.gatewayUrl})`);
}
