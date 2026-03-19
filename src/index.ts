/**
 * oktsec plugin for OpenClaw.
 * Minimal version for initial integration testing.
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
  registerHook: (...args: unknown[]) => void;
  registerCli: (...args: unknown[]) => void;
  registerService: (...args: unknown[]) => void;
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

  log.info(`oktsec plugin loaded (${config.mode} mode, gateway: ${config.gatewayUrl})`);

  // Register /oktsec command
  try {
    api.registerCommand({
      name: "oktsec",
      description: "Security status and controls",
      handler: async (ctx: Record<string, unknown>) => {
        const args = ((ctx && ctx.args) || "") as string;
        const cmd = args.trim().split(/\s+/)[0] || "status";

        if (cmd === "status") {
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

  // Register message hooks
  try {
    api.registerHook("message:received", async (event: Record<string, unknown>) => {
      const ctx = (event && event.context) as Record<string, unknown> | undefined;
      if (!ctx || !ctx.content) return;

      const decision = await client.sendToolEvent({
        tool_name: "message",
        tool_input: String(ctx.content),
        event: "pre_tool_call",
        agent: String(ctx.from || config.agent),
      });

      if (decision.decision === "block" && config.mode === "enforce") {
        log.warn(`oktsec blocked message from ${ctx.from}: ${decision.reason}`);
      }
    });
  } catch (e) {
    log.warn("oktsec: registerHook failed: " + String(e));
  }
}
