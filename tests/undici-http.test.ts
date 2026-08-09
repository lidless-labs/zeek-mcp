import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Agent } from "undici";

// HTTP request-path tests for the undici-backed fetch helpers in thehive.ts and
// misp.ts. We mock global fetch, capture argv, and invoke tool handlers through
// a minimal McpServer stub (same pattern as pcap-injection.test.ts).

type ToolHandler = (params: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

type FetchCall = {
  url: string;
  options: RequestInit & { dispatcher?: Agent };
};

const fetchCalls: FetchCall[] = [];

function makeServerStub() {
  const handlers: Record<string, ToolHandler> = {};
  const server = {
    tool: (name: string, _desc: string, _schema: unknown, handler: ToolHandler) => {
      handlers[name] = handler;
    },
  };
  return { server, handlers };
}

function jsonResponse(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function createMockFetch(
  impl?: (url: string, options: RequestInit & { dispatcher?: Agent }) => Promise<Response>,
) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const options = (init ?? {}) as RequestInit & { dispatcher?: Agent };
    fetchCalls.push({ url, options });
    if (impl) {
      return impl(url, options);
    }
    return jsonResponse(200, {});
  });
}

function hangingFetchOnAbort(): ReturnType<typeof createMockFetch> {
  return createMockFetch((_url, options) => {
    return new Promise((_resolve, reject) => {
      const signal = options.signal;
      if (!signal) {
        return;
      }
      if (signal.aborted) {
        reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
        return;
      }
      signal.addEventListener("abort", () => {
        reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
      });
    });
  });
}

beforeEach(() => {
  fetchCalls.length = 0;
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  delete process.env.THEHIVE_URL;
  delete process.env.THEHIVE_API_KEY;
  delete process.env.THEHIVE_VERIFY_SSL;
  delete process.env.MISP_URL;
  delete process.env.MISP_API_KEY;
  delete process.env.MISP_VERIFY_SSL;
});

async function registerTheHiveHandlers(verifySsl = true) {
  process.env.THEHIVE_URL = "http://192.0.2.94:9000";
  process.env.THEHIVE_API_KEY = "test-key-123";
  process.env.THEHIVE_VERIFY_SSL = verifySsl ? "true" : "false";
  vi.resetModules();
  const { registerTheHiveTools } = await import("../src/tools/thehive.js");
  const { server, handlers } = makeServerStub();
  registerTheHiveTools(server as never);
  return handlers;
}

async function registerMispHandlers(verifySsl = true) {
  process.env.MISP_URL = "https://192.0.2.97";
  process.env.MISP_API_KEY = "test-misp-key";
  process.env.MISP_VERIFY_SSL = verifySsl ? "true" : "false";
  vi.resetModules();
  const { registerMispTools } = await import("../src/tools/misp.js");
  const { server, handlers } = makeServerStub();
  registerMispTools(server as never);
  return handlers;
}

describe("TheHive HTTP client (undici/fetch)", () => {
  describe("timeout and abort", () => {
    it("passes an AbortSignal to fetch and aborts after the default timeout", async () => {
      vi.useFakeTimers();
      vi.stubGlobal("fetch", hangingFetchOnAbort());
      const handlers = await registerTheHiveHandlers();

      const resultPromise = handlers.thehive_create_alert({
        title: "Test alert",
        description: "Timeout probe",
      });

      await vi.advanceTimersByTimeAsync(30000);
      const result = await resultPromise;

      expect(fetchCalls.length).toBe(1);
      expect(fetchCalls[0].options.signal).toBeInstanceOf(AbortSignal);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error creating TheHive alert:");
      expect(result.content[0].text.toLowerCase()).toMatch(/abort/);
    });

    it("clears the timeout timer when fetch resolves before the deadline", async () => {
      vi.useFakeTimers();
      const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-1" })),
      );
      const handlers = await registerTheHiveHandlers();

      await handlers.thehive_create_alert({
        title: "Fast alert",
        description: "Should finish before timeout",
      });

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
      await vi.advanceTimersByTimeAsync(30000);
      // Only the initial alert POST; no retry after the (cleared) timer fires.
      expect(fetchCalls.length).toBe(1);
    });
  });

  describe("error-to-response mapping", () => {
    it("returns isError without calling fetch when the API key is missing", async () => {
      vi.stubGlobal("fetch", createMockFetch());
      process.env.THEHIVE_URL = "http://192.0.2.94:9000";
      delete process.env.THEHIVE_API_KEY;
      vi.resetModules();
      const { registerTheHiveTools } = await import("../src/tools/thehive.js");
      const { server, handlers } = makeServerStub();
      registerTheHiveTools(server as never);

      const result = await handlers.thehive_create_alert({
        title: "No key",
        description: "Should fail fast",
      });

      expect(fetchCalls.length).toBe(0);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("THEHIVE_API_KEY");
    });

    it("maps non-201 HTTP responses to isError with status and body", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(400, { message: "bad request" })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        title: "Bad payload",
        description: "Server rejects",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("TheHive error (400)");
      expect(result.content[0].text).toContain("bad request");
    });

    it("maps network failures to isError with the thrown message", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => {
          throw new Error("ECONNREFUSED");
        }),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_case({
        title: "Unreachable",
        description: "Network down",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toBe("Error creating TheHive case: ECONNREFUSED");
    });

    it("treats invalid JSON bodies as null data while still checking status", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => new Response("not-json", { status: 502 })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        title: "Broken body",
        description: "Non-JSON response",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toBe("TheHive error (502): null");
    });

    it("returns success JSON when the server responds 201", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-42", number: 7 })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        title: "Good alert",
        description: "Created",
      });

      expect(result.isError).toBeUndefined();
      const payload = JSON.parse(result.content[0].text);
      expect(payload.success).toBe(true);
      expect(payload.alertId).toBe("alert-42");
    });
  });

  describe("undici dispatcher and request shape", () => {
    it("attaches a scoped undici Agent dispatcher when verifySsl is false", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-ssl" })),
      );
      const handlers = await registerTheHiveHandlers(false);

      await handlers.thehive_create_alert({
        title: "Insecure TLS",
        description: "Scoped agent",
      });

      expect(fetchCalls[0].options.dispatcher).toBeInstanceOf(Agent);
    });

    it("omits the dispatcher when verifySsl is true", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-secure" })),
      );
      const handlers = await registerTheHiveHandlers(true);

      await handlers.thehive_create_alert({
        title: "Secure TLS",
        description: "Default verify",
      });

      expect(fetchCalls[0].options.dispatcher).toBeUndefined();
    });

    it("reuses the same insecure Agent across requests", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-reuse" })),
      );
      const handlers = await registerTheHiveHandlers(false);

      await handlers.thehive_create_alert({
        title: "First",
        description: "Creates alert",
        observables: [{ dataType: "ip", data: "192.0.2.1" }],
      });

      const firstAgent = fetchCalls[0].options.dispatcher;
      const secondAgent = fetchCalls[1]?.options.dispatcher;
      expect(fetchCalls.length).toBeGreaterThan(1);
      expect(firstAgent).toBe(secondAgent);
    });

    it("sends Authorization, Content-Type, method, and URL as expected", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-shape" })),
      );
      const handlers = await registerTheHiveHandlers();

      await handlers.thehive_create_alert({
        title: "Shape check",
        description: "Headers and URL",
      });

      expect(fetchCalls[0].url).toBe("http://192.0.2.94:9000/api/v1/alert");
      expect(fetchCalls[0].options.method).toBe("POST");
      const headers = fetchCalls[0].options.headers as Record<string, string>;
      expect(headers.Authorization).toBe("Bearer test-key-123");
      expect(headers["Content-Type"]).toBe("application/json");
    });
  });
});

describe("MISP HTTP client (undici/fetch)", () => {
  describe("error-to-response mapping", () => {
    it("returns isError without calling fetch when the API key is missing", async () => {
      vi.stubGlobal("fetch", createMockFetch());
      process.env.MISP_URL = "https://192.0.2.97";
      delete process.env.MISP_API_KEY;
      vi.resetModules();
      const { registerMispTools } = await import("../src/tools/misp.js");
      const { server, handlers } = makeServerStub();
      registerMispTools(server as never);

      const result = await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(fetchCalls.length).toBe(0);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("MISP_API_KEY");
    });

    it("maps non-200 HTTP responses to isError with status and body", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(403, { errors: "Forbidden" })),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("MISP error (403)");
      expect(result.content[0].text).toContain("Forbidden");
    });

    it("maps network failures to isError with the thrown message", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => {
          throw new Error("getaddrinfo ENOTFOUND");
        }),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_add_event({ info: "Unreachable host" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toBe("Error creating MISP event: getaddrinfo ENOTFOUND");
    });

    it("returns success JSON when the server responds 200", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () =>
          jsonResponse(200, { Event: { id: "99", uuid: "uuid-99" } }),
        ),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_add_event({ info: "Created event" });

      expect(result.isError).toBeUndefined();
      const payload = JSON.parse(result.content[0].text);
      expect(payload.success).toBe(true);
      expect(payload.eventId).toBe("99");
    });

    it("swallows per-indicator network errors in bulk lookup without failing the tool", async () => {
      let call = 0;
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => {
          call += 1;
          if (call === 1) {
            throw new Error("transient failure");
          }
          return jsonResponse(200, { response: { Attribute: [{ category: "Network activity" }] } });
        }),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_bulk_lookup({
        indicators: [
          { value: "192.0.2.10", type: "ip-src" },
          { value: "192.0.2.11", type: "ip-src" },
        ],
      });

      expect(result.isError).toBeUndefined();
      const payload = JSON.parse(result.content[0].text);
      expect(payload.totalChecked).toBe(2);
      expect(payload.totalHits).toBe(1);
      expect(payload.clean).toEqual(
        expect.arrayContaining([expect.objectContaining({ value: "192.0.2.10" })]),
      );
    });
  });

  describe("undici dispatcher and request shape", () => {
    it("attaches a scoped undici Agent dispatcher when verifySsl is false", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(200, { response: { Attribute: [] } })),
      );
      const handlers = await registerMispHandlers(false);

      await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(fetchCalls[0].options.dispatcher).toBeInstanceOf(Agent);
    });

    it("omits the dispatcher when verifySsl is true", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(200, { response: { Attribute: [] } })),
      );
      const handlers = await registerMispHandlers(true);

      await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(fetchCalls[0].options.dispatcher).toBeUndefined();
    });

    it("sends Authorization, Accept, Content-Type, method, and URL as expected", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(200, { response: { Attribute: [] } })),
      );
      const handlers = await registerMispHandlers();

      await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(fetchCalls[0].url).toBe("https://192.0.2.97/attributes/restSearch");
      expect(fetchCalls[0].options.method).toBe("POST");
      const headers = fetchCalls[0].options.headers as Record<string, string>;
      expect(headers.Authorization).toBe("test-misp-key");
      expect(headers.Accept).toBe("application/json");
      expect(headers["Content-Type"]).toBe("application/json");
    });
  });
});
