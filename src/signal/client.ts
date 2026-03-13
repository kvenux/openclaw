import { resolveFetch } from "../infra/fetch.js";
import { isBlockedHostname } from "../infra/net/ssrf.js";
import { generateSecureUuid } from "../infra/secure-random.js";
import { fetchWithTimeout } from "../utils/fetch-timeout.js";

export type SignalRpcOptions = {
  baseUrl: string;
  timeoutMs?: number;
};

export type SignalRpcError = {
  code?: number;
  message?: string;
  data?: unknown;
};

export type SignalRpcResponse<T> = {
  jsonrpc?: string;
  result?: T;
  error?: SignalRpcError;
  id?: string | number | null;
};

export type SignalSseEvent = {
  event?: string;
  data?: string;
  id?: string;
};

const DEFAULT_TIMEOUT_MS = 10_000;

// Cloud metadata and link-local IPs that are never legitimate signal-cli targets.
// We intentionally allow loopback (127.x) and private networks (10.x, 172.16.x,
// 192.168.x) because signal-cli runs as a local daemon by default.
const BLOCKED_SIGNAL_METADATA_PREFIXES = [
  "169.254.", // link-local / cloud metadata (AWS, Azure, GCP)
];

const BLOCKED_SIGNAL_METADATA_IPS = new Set(["0.0.0.0", "[::ffff:169.254.169.254]"]);

// Hostnames that are allowed for Signal despite being blocked by the general
// SSRF policy. Signal-cli runs as a local daemon, so localhost is expected.
const SIGNAL_ALLOWED_HOSTNAMES = new Set(["localhost"]);

/**
 * Validate that a Signal base URL does not target cloud metadata endpoints
 * or other known-dangerous destinations (CWE-918).
 *
 * Signal legitimately talks to a local daemon, so loopback and private
 * networks are allowed. Only cloud metadata / link-local IPs and
 * dangerous hostnames (*.internal, *.local, metadata.google.internal)
 * are blocked.
 */
export function assertSignalBaseUrlAllowed(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid Signal base URL: ${url}`);
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  // Block link-local / cloud metadata IPs
  if (BLOCKED_SIGNAL_METADATA_IPS.has(hostname)) {
    throw new Error(`Signal base URL targets a blocked address: ${hostname}`);
  }
  for (const prefix of BLOCKED_SIGNAL_METADATA_PREFIXES) {
    if (hostname.startsWith(prefix)) {
      throw new Error(`Signal base URL targets a link-local/metadata address: ${hostname}`);
    }
  }

  // Block dangerous hostnames, but allow localhost for signal-cli
  if (!SIGNAL_ALLOWED_HOSTNAMES.has(hostname) && isBlockedHostname(hostname)) {
    throw new Error(`Signal base URL targets a blocked hostname: ${hostname}`);
  }
}

function normalizeBaseUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new Error("Signal base URL is required");
  }
  const normalized = /^https?:\/\//i.test(trimmed)
    ? trimmed.replace(/\/+$/, "")
    : `http://${trimmed}`.replace(/\/+$/, "");
  assertSignalBaseUrlAllowed(normalized);
  return normalized;
}

function getRequiredFetch(): typeof fetch {
  const fetchImpl = resolveFetch();
  if (!fetchImpl) {
    throw new Error("fetch is not available");
  }
  return fetchImpl;
}

function parseSignalRpcResponse<T>(text: string, status: number): SignalRpcResponse<T> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Signal RPC returned malformed JSON (status ${status})`, { cause: err });
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Signal RPC returned invalid response envelope (status ${status})`);
  }

  const rpc = parsed as SignalRpcResponse<T>;
  const hasResult = Object.hasOwn(rpc, "result");
  if (!rpc.error && !hasResult) {
    throw new Error(`Signal RPC returned invalid response envelope (status ${status})`);
  }
  return rpc;
}

export async function signalRpcRequest<T = unknown>(
  method: string,
  params: Record<string, unknown> | undefined,
  opts: SignalRpcOptions,
): Promise<T> {
  const baseUrl = normalizeBaseUrl(opts.baseUrl);
  const id = generateSecureUuid();
  const body = JSON.stringify({
    jsonrpc: "2.0",
    method,
    params,
    id,
  });
  const res = await fetchWithTimeout(
    `${baseUrl}/api/v1/rpc`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    },
    opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    getRequiredFetch(),
  );
  if (res.status === 201) {
    return undefined as T;
  }
  const text = await res.text();
  if (!text) {
    throw new Error(`Signal RPC empty response (status ${res.status})`);
  }
  const parsed = parseSignalRpcResponse<T>(text, res.status);
  if (parsed.error) {
    const code = parsed.error.code ?? "unknown";
    const msg = parsed.error.message ?? "Signal RPC error";
    throw new Error(`Signal RPC ${code}: ${msg}`);
  }
  return parsed.result as T;
}

export async function signalCheck(
  baseUrl: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<{ ok: boolean; status?: number | null; error?: string | null }> {
  const normalized = normalizeBaseUrl(baseUrl);
  try {
    const res = await fetchWithTimeout(
      `${normalized}/api/v1/check`,
      { method: "GET" },
      timeoutMs,
      getRequiredFetch(),
    );
    if (!res.ok) {
      return { ok: false, status: res.status, error: `HTTP ${res.status}` };
    }
    return { ok: true, status: res.status, error: null };
  } catch (err) {
    return {
      ok: false,
      status: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function streamSignalEvents(params: {
  baseUrl: string;
  account?: string;
  abortSignal?: AbortSignal;
  onEvent: (event: SignalSseEvent) => void;
}): Promise<void> {
  const baseUrl = normalizeBaseUrl(params.baseUrl);
  const url = new URL(`${baseUrl}/api/v1/events`);
  if (params.account) {
    url.searchParams.set("account", params.account);
  }

  const fetchImpl = resolveFetch();
  if (!fetchImpl) {
    throw new Error("fetch is not available");
  }
  const res = await fetchImpl(url, {
    method: "GET",
    headers: { Accept: "text/event-stream" },
    signal: params.abortSignal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`Signal SSE failed (${res.status} ${res.statusText || "error"})`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent: SignalSseEvent = {};

  const flushEvent = () => {
    if (!currentEvent.data && !currentEvent.event && !currentEvent.id) {
      return;
    }
    params.onEvent({
      event: currentEvent.event,
      data: currentEvent.data,
      id: currentEvent.id,
    });
    currentEvent = {};
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    let lineEnd = buffer.indexOf("\n");
    while (lineEnd !== -1) {
      let line = buffer.slice(0, lineEnd);
      buffer = buffer.slice(lineEnd + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }

      if (line === "") {
        flushEvent();
        lineEnd = buffer.indexOf("\n");
        continue;
      }
      if (line.startsWith(":")) {
        lineEnd = buffer.indexOf("\n");
        continue;
      }
      const [rawField, ...rest] = line.split(":");
      const field = rawField.trim();
      const rawValue = rest.join(":");
      const value = rawValue.startsWith(" ") ? rawValue.slice(1) : rawValue;
      if (field === "event") {
        currentEvent.event = value;
      } else if (field === "data") {
        currentEvent.data = currentEvent.data ? `${currentEvent.data}\n${value}` : value;
      } else if (field === "id") {
        currentEvent.id = value;
      }
      lineEnd = buffer.indexOf("\n");
    }
  }

  flushEvent();
}
