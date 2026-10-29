import { serializeTelemetryData } from "../telemetry.js";

export type RemoteFailureClass = "http" | "network" | "deadline" | "body-too-large" | "invalid-json" | "data-limit";

export class RemoteRequestFailure extends Error {
  constructor(readonly failure: RemoteFailureClass, readonly status = 0) {
    super(failure);
  }
}

export function remoteFailureDetails(error: unknown): { failure: RemoteFailureClass; status: number } {
  return error instanceof RemoteRequestFailure
    ? { failure: error.failure, status: error.status }
    : { failure: "network", status: 0 };
}

export function remoteFailureResponse(service: "MISP" | "TheHive", error: unknown) {
  const { failure, status } = remoteFailureDetails(error);
  return {
    content: [{ type: "text" as const, text: `${service} request failed: ${failure} (status ${status}).` }],
    isError: true,
  };
}

// A failed acknowledgement can follow an applied write. Preserve only validated
// local progress and require reconciliation rather than suggesting a retry.
export function remoteMutationFailureResponse(
  service: "MISP" | "TheHive",
  error: unknown,
  progress: {
    eventId?: string | number;
    alertId?: string;
    caseId?: string;
    confirmedTaskCount?: number;
    confirmedObservableCount?: number;
    unconfirmedOperation?: { kind: "alert" | "case" | "task" | "observable"; index?: number };
  } = {},
) {
  return {
    content: [{ type: "text" as const, text: remoteOutput({
      success: false,
      outcome: progress.eventId !== undefined || progress.alertId || progress.caseId ? "partial" : "unknown",
      ...progress,
      ...remoteFailureDetails(error),
      message: `${service} write outcome is unconfirmed. Reconcile remote state before retrying. Do not repeat the create operation automatically.`,
    }) }],
    isError: true,
  };
}

// Reject excessive structure before callers map service objects. Model output
// has a separate aggregate encoded-byte budget, including caller-supplied data.
function checkDataBudget(value: unknown, status: number): void {
  let nodes = 0;
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 2000 || depth > 12) throw new RemoteRequestFailure("data-limit", status);
    if (!item || typeof item !== "object") return;
    if (Array.isArray(item)) {
      if (item.length > 100) throw new RemoteRequestFailure("data-limit", status);
      for (const child of item) visit(child, depth + 1);
    } else {
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        if (key.length > 256) throw new RemoteRequestFailure("data-limit", status);
        visit((item as Record<string, unknown>)[key], depth + 1);
      }
    }
  };
  visit(value, 0);
}

// The deadline includes fetch and every body read. Race it explicitly so a
// stalled stream cannot depend on a transport's abort implementation to settle.
export async function requestRemoteJson(
  url: string,
  options: RequestInit,
  timeoutMs = 30000,
  project?: (data: unknown, status: number) => unknown,
): Promise<{ status: number; data: unknown }> {
  const controller = new AbortController();
  let status = 0;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let response: Response | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const cancel = () => {
    controller.abort();
    // Cancellation itself must not extend the request deadline.
    if (reader) void reader.cancel().catch(() => {});
    else if (response?.body) void response.body.cancel().catch(() => {});
  };
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new RemoteRequestFailure("deadline", status));
      cancel();
    }, timeoutMs);
  });
  try {
    return await Promise.race([deadline, (async () => {
      response = await fetch(url, { ...options, signal: controller.signal });
      status = response.status;
      if (!response.ok) throw new RemoteRequestFailure("http", status);
      const length = response.headers.get("content-length");
      if (length && Number(length) > 1048576) throw new RemoteRequestFailure("body-too-large", status);
      // A fetch that resolves after abort must not resume reading its body.
      if (controller.signal.aborted) {
        cancel();
        throw new RemoteRequestFailure("deadline", status);
      }
      reader = response.body?.getReader();
      // A fixed buffer bounds retained memory independently of fragmentation.
      const body = Buffer.allocUnsafe(1048576);
      let bytes = 0;
      let chunks = 0;
      while (reader) {
        const chunk = await reader.read();
        if (controller.signal.aborted) throw new RemoteRequestFailure("deadline", status);
        if (chunk.done) break;
        if (++chunks > 65536 || bytes + chunk.value.byteLength > body.length) {
          throw new RemoteRequestFailure("body-too-large", status);
        }
        body.set(chunk.value, bytes);
        bytes += chunk.value.byteLength;
      }
      if (bytes === 0 && status === 204) return { status, data: null };
      let data: unknown;
      try {
        data = JSON.parse(body.subarray(0, bytes).toString("utf8"));
      } catch {
        throw new RemoteRequestFailure("invalid-json", status);
      }
      // Endpoint projections read a fixed set of identity fields after the
      // byte-bounded parse. Unused create-response arrays are never traversed.
      if (project) data = project(data, status);
      checkDataBudget(data, status);
      return { status, data };
    })()]);
  } catch (error) {
    cancel();
    throw error instanceof RemoteRequestFailure ? error : new RemoteRequestFailure("network", status);
  } finally {
    clearTimeout(timer);
  }
}

// Serialize only through the shared, bounded model-data boundary.
export const remoteOutput = serializeTelemetryData;
