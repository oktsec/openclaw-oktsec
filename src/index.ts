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

/** Safely extract a string from nested unknown objects */
function str(obj: unknown, ...keys: string[]): string {
  let current = obj as Record<string, unknown> | undefined;
  for (const k of keys) {
    if (!current || typeof current !== "object") return "";
    current = current[k] as Record<string, unknown> | undefined;
  }
  return current ? String(current) : "";
}

/** Summarize an unknown object's top-level keys for debug */
function keys(obj: unknown): string {
  if (!obj || typeof obj !== "object") return "null";
  return Object.keys(obj as Record<string, unknown>).join(",");
}

export default function register(api: OpenClawPluginApi) {
  const config = resolveConfig(api);
  const client = new OktsecClient(config);
  const log = api.logger;

  async function forward(toolName: string, toolInput: string, event: string, agent: string, sessionId?: string) {
    try {
      const decision = await client.sendToolEvent({
        tool_name: toolName,
        tool_input: toolInput,
        event: event as "pre_tool_call" | "post_tool_call",
        agent: agent || config.agent,
        session_id: sessionId,
      });
      log.info(`oktsec: ${toolName} -> ${decision.decision}`);
      return decision;
    } catch (err) {
      log.warn(`oktsec: forward ${toolName} failed: ${err}`);
      return { decision: "allow" as const };
    }
  }

  // 1. Intercept tool calls BEFORE execution (can block)
  api.on("before_tool_call", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;
    log.info(`oktsec: before_tool_call keys=[${keys(e)}] ctx=[${keys(c)}]`);

    const toolName = String(e.toolName || e.name || e.tool || "unknown");
    const input = e.input || e.args || e.arguments || e.toolInput || {};
    const toolInput = typeof input === "string" ? input : JSON.stringify(input);
    const agentId = String(c.agentId || c.agent || "main");
    const agent = `openclaw-${agentId}`;
    const session = String(c.sessionKey || c.sessionId || "");

    log.info(`oktsec: before_tool_call ${toolName} agent=${agent} session=${session}`);
    const decision = await forward(toolName, toolInput, "pre_tool_call", agent, session);

    if (decision.decision === "block" && config.mode === "enforce") {
      log.warn(`oktsec: BLOCKED ${toolName}: ${decision.reason}`);
      return { block: true, message: `oktsec: ${decision.reason}` };
    }
    return undefined;
  });

  // 2. Audit tool calls AFTER execution
  api.on("after_tool_call", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;
    log.info(`oktsec: after_tool_call keys=[${keys(e)}]`);

    const toolName = String(e.toolName || e.name || e.tool || "unknown");
    const result = e.result || e.output || e.content || "";
    const toolOutput = typeof result === "string" ? result : JSON.stringify(result);
    const agentId = String(c.agentId || c.agent || "main");
    const agent = `openclaw-${agentId}`;
    const session = String(c.sessionKey || c.sessionId || "");

    await forward(toolName + "_result", toolOutput, "post_tool_call", agent, session);
  });

  // 3. Scan incoming messages
  api.on("message_received", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;

    const content = String(e.content || e.body || e.text || e.message || "");
    const from = String(c.channelId || c.channel || c.senderId || "telegram");
    const agent = String(c.senderId || c.from || config.agent);
    const session = String(c.sessionKey || c.sessionId || "");

    if (!content) {
      log.info(`oktsec: message_received EMPTY keys=[${keys(e)}] ctx=[${keys(c)}]`);
      return;
    }

    log.info(`oktsec: message_received len=${content.length} from=${from}`);
    const decision = await forward("message", content, "pre_tool_call", agent, session);

    if (decision.decision === "block" && config.mode === "enforce") {
      log.warn(`oktsec: BLOCKED message: ${decision.reason}`);
    }
  });

  // 4. Scan outgoing messages (agent responses)
  api.on("message_sending", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;
    log.warn(`oktsec: >>> message_sending FIRED keys=[${keys(e)}] ctx=[${keys(c)}]`);

    const content = String(e.content || e.body || e.text || e.message || "");
    if (!content) return;

    const session = String(c.sessionKey || c.sessionId || "");
    const agentId = String(c.agentId || c.agent || "main");
    const decision = await forward("message_out", content, "pre_tool_call", `openclaw-${agentId}`, session);

    if (decision.decision === "block" && config.mode === "enforce") {
      log.warn(`oktsec: BLOCKED outgoing: ${decision.reason}`);
      return { block: true, reason: `oktsec: ${decision.reason}` };
    }
    return undefined;
  });

  // 5. Audit sent messages
  api.on("message_sent", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;
    log.warn(`oktsec: >>> message_sent FIRED keys=[${keys(e)}] ctx=[${keys(c)}]`);

    const content = String(e.content || e.body || e.text || e.message || "");
    if (!content) return;

    const session = String(c.sessionKey || c.sessionId || "");
    const agentId = String(c.agentId || c.agent || "main");
    await forward("message_sent", content, "post_tool_call", `openclaw-${agentId}`, session);
  });

  // 6. LLM output = agent response. This is how we capture what the agent says,
  // since message_sending/message_sent hooks don't fire for Telegram.
  // We DON'T scan llm_input (system prompts trigger false positives).
  api.on("llm_output", async (event: unknown, ctx: unknown) => {
    const e = event as Record<string, unknown>;
    const c = (ctx || {}) as Record<string, unknown>;

    // Extract assistant response text
    const texts = e.assistantTexts || e.content || e.text || e.response || "";
    let content = "";
    if (Array.isArray(texts)) {
      content = (texts as string[]).join("\n");
    } else if (typeof texts === "string") {
      content = texts;
    } else {
      content = JSON.stringify(texts);
    }

    if (!content || content.length < 3) return;

    const agentId = String(c.agentId || c.agent || "main");
    const session = String(c.sessionKey || c.sessionId || "");

    log.info(`oktsec: llm_output len=${content.length} agent=${agentId}`);
    await forward("agent_response", content.slice(0, 2000), "post_tool_call", `openclaw-${agentId}`, session);
  });

  // 7. Slash command
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
