import type { IncomingMessage, ServerResponse } from "node:http";
import { loadConfig } from "../config/config.js";
import { getMemorySearchManager } from "../memory/search-manager.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";
import {
  readJsonBodyOrError,
  sendJson,
  sendMethodNotAllowed,
  sendUnauthorized,
} from "./http-common.js";
import { getBearerToken } from "./http-utils.js";
import { listAgentsForGateway } from "./session-utils.js";

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
