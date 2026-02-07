import type { IncomingMessage, ServerResponse } from "node:http";
import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../config/config.js";
import { getMemorySearchManager } from "../memory/search-manager.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";
import {
  readJsonBodyOrError,
  sendJson,
  sendMethodNotAllowed,
  sendUnauthorized,
} from "./http-common.js";
import { getBearerToken, getHeader } from "./http-utils.js";
import { loadSessionEntry, listAgentsForGateway } from "./session-utils.js";
import { readSessionMessages } from "./session-utils.fs.js";

type AgentosHttpOptions = {
  auth: ResolvedGatewayAuth;
  trustedProxies?: string[];
};

export async function handleAgentosHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/v1/memory/status") {
    return handleMemoryStatus(req, res, opts);
  }
  if (url.pathname === "/v1/memory/search") {
    return handleMemorySearch(req, res, opts);
  }
  if (url.pathname === "/v1/agents") {
    return handleAgentsList(req, res, opts);
  }
  if (url.pathname === "/v1/history") {
    return handleHistory(req, res, opts);
  }
  if (url.pathname === "/v1/memory/files") {
    return handleMemoryFiles(req, res, opts);
  }

  return false;
}

async function authorize(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  const token = getBearerToken(req);
  const result = await authorizeGatewayConnect({
    auth: opts.auth,
    connectAuth: { token, password: token },
    req,
    trustedProxies: opts.trustedProxies,
  });
  if (!result.ok) {
    sendUnauthorized(res);
    return false;
  }
  return true;
}

async function handleMemoryStatus(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }
  if (!(await authorize(req, res, opts))) {
    return true;
  }

  try {
    const cfg = loadConfig();
    const { manager } = await getMemorySearchManager({ cfg, agentId: "main" });
    if (!manager) {
      sendJson(res, 200, { status: "unavailable", memories: [] });
      return true;
    }
    const status = manager.status();
    sendJson(res, 200, { status: "ok", provider: status });
  } catch (err) {
    sendJson(res, 500, { error: { message: String(err), type: "api_error" } });
  }
  return true;
}

async function handleMemorySearch(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  if (req.method !== "POST") {
    sendMethodNotAllowed(res);
    return true;
  }
  if (!(await authorize(req, res, opts))) {
    return true;
  }

  const body = await readJsonBodyOrError(req, res, 64 * 1024);
  if (body === undefined) {
    return true;
  }

  const payload = body as { query?: string; limit?: number };
  const query = typeof payload.query === "string" ? payload.query.trim() : "";
  if (!query) {
    sendJson(res, 400, { error: { message: "Missing `query`.", type: "invalid_request_error" } });
    return true;
  }

  try {
    const cfg = loadConfig();
    const { manager } = await getMemorySearchManager({ cfg, agentId: "main" });
    if (!manager) {
      sendJson(res, 200, { results: [] });
      return true;
    }
    const maxResults = typeof payload.limit === "number" ? payload.limit : 10;
    const results = await manager.search(query, { maxResults });
    sendJson(res, 200, { results });
  } catch (err) {
    sendJson(res, 500, { error: { message: String(err), type: "api_error" } });
  }
  return true;
}

async function handleAgentsList(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }
  if (!(await authorize(req, res, opts))) {
    return true;
  }

  try {
    const cfg = loadConfig();
    const { agents, defaultId } = listAgentsForGateway(cfg);
    sendJson(res, 200, { agents, defaultId });
  } catch (err) {
    sendJson(res, 500, { error: { message: String(err), type: "api_error" } });
  }
  return true;
}

type ContentPart = { type?: string; text?: string };

function extractText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return (content as ContentPart[])
      .filter((p) => typeof p?.text === "string")
      .map((p) => p.text!)
      .join("\n");
  }
  return "";
}

/** Strip Discord metadata lines from user messages.
 *  e.g. "[Discord ai_nate user id:... UTC] actual message\n[message_id: ...]" → "actual message" */
function stripDiscordMeta(text: string): string {
  // Remove leading "[Discord ... UTC] " prefix
  let cleaned = text.replace(/^\[Discord [^\]]*\]\s*/s, "");
  // Remove trailing "[message_id: ...]" line
  cleaned = cleaned.replace(/\n?\[message_id:\s*\d+\]\s*$/, "");
  return cleaned.trim();
}

async function handleHistory(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }
  if (!(await authorize(req, res, opts))) {
    return true;
  }

  try {
    const sessionKey = getHeader(req, "x-openclaw-session-key")?.trim() ?? "";
    if (!sessionKey) {
      sendJson(res, 400, {
        error: { message: "Missing X-OpenClaw-Session-Key header.", type: "invalid_request_error" },
      });
      return true;
    }

    const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);
    const limitParam = url.searchParams.get("limit");
    const limit = limitParam ? Math.min(Math.max(parseInt(limitParam, 10) || 50, 1), 200) : 50;

    const loaded = loadSessionEntry(sessionKey);
    if (!loaded?.entry?.sessionId) {
      sendJson(res, 200, { messages: [] });
      return true;
    }

    const raw = readSessionMessages(loaded.entry.sessionId, loaded.storePath, loaded.entry.sessionFile);
    // Map to simplified message format, only user + assistant, take last N
    const messages: Array<{ role: string; content: string }> = [];
    for (const msg of raw) {
      const m = msg as { role?: string; content?: unknown };
      if (m.role !== "user" && m.role !== "assistant") continue;
      let text = extractText(m.content);
      if (m.role === "user") text = stripDiscordMeta(text);
      if (!text.trim()) continue;
      messages.push({ role: m.role, content: text });
    }

    sendJson(res, 200, { messages: messages.slice(-limit) });
  } catch (err) {
    sendJson(res, 500, { error: { message: String(err), type: "api_error" } });
  }
  return true;
}

async function handleMemoryFiles(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AgentosHttpOptions,
): Promise<boolean> {
  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }
  if (!(await authorize(req, res, opts))) {
    return true;
  }

  try {
    const cfg = loadConfig();
    const workspace = cfg.agents?.defaults?.workspace
      ?? path.join(process.env.HOME ?? "/tmp", ".openclaw", "workspace");

    const files: Array<{ name: string; content: string; size: number; modified: string }> = [];

    // Read MEMORY.md
    const memoryMd = path.join(workspace, "MEMORY.md");
    if (fs.existsSync(memoryMd)) {
      const stat = fs.statSync(memoryMd);
      files.push({
        name: "MEMORY.md",
        content: fs.readFileSync(memoryMd, "utf-8"),
        size: stat.size,
        modified: stat.mtime.toISOString(),
      });
    }

    // Read memory/*.md
    const memoryDir = path.join(workspace, "memory");
    if (fs.existsSync(memoryDir)) {
      for (const entry of fs.readdirSync(memoryDir)) {
        if (!entry.endsWith(".md")) continue;
        const filePath = path.join(memoryDir, entry);
        const stat = fs.statSync(filePath);
        files.push({
          name: `memory/${entry}`,
          content: fs.readFileSync(filePath, "utf-8"),
          size: stat.size,
          modified: stat.mtime.toISOString(),
        });
      }
    }

    sendJson(res, 200, { files });
  } catch (err) {
    sendJson(res, 500, { error: { message: String(err), type: "api_error" } });
  }
  return true;
}
