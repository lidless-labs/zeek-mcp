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
    tool: (name: string, _desc: string, _schema: unknown, ...args: unknown[]) => {
      handlers[name] = args.at(-1) as ToolHandler;
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
  vi.stubEnv("ZEEK_ALLOW_MUTATION", "1");
  fetchCalls.length = 0;
});

afterEach(() => {
  vi.unstubAllEnvs();
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
        confirm: true,
        title: "Test alert",
        description: "Timeout probe",
      });

      await vi.advanceTimersByTimeAsync(30000);
      const result = await resultPromise;

      expect(fetchCalls.length).toBe(1);
      expect(fetchCalls[0].options.signal).toBeInstanceOf(AbortSignal);
      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "deadline", status: 0 });
      expect(result.content[0].text).toMatch(/reconcile/i);
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
        confirm: true,
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
        confirm: true,
        title: "No key",
        description: "Should fail fast",
      });

      expect(fetchCalls.length).toBe(0);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("THEHIVE_API_KEY");
    });

    it("maps non-201 HTTP responses to a local failure class and numeric status", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(400, { message: "bad request" })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        confirm: true,
        title: "Bad payload",
        description: "Server rejects",
      });

      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "http", status: 400 });
      expect(result.content[0].text).toMatch(/reconcile/i);
    });

    it("maps network failures to a local network failure", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => {
          throw new Error("ECONNREFUSED");
        }),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_case({
        confirm: true,
        title: "Unreachable",
        description: "Network down",
      });

      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "network", status: 0 });
      expect(result.content[0].text).toMatch(/reconcile/i);
    });

    it("reports a non-success acknowledgement as unknown without disclosing its invalid body", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => new Response("not-json", { status: 502 })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        confirm: true,
        title: "Broken body",
        description: "Non-JSON response",
      });

      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "http", status: 502 });
      expect(result.content[0].text).toMatch(/reconcile/i);
    });

    it("returns success JSON when the server responds 201", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(201, { _id: "alert-42", number: 7 })),
      );
      const handlers = await registerTheHiveHandlers();

      const result = await handlers.thehive_create_alert({
        confirm: true,
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
        confirm: true,
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
        confirm: true,
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
        confirm: true,
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
        confirm: true,
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

    it("maps non-200 HTTP responses to a local failure class and numeric status", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => jsonResponse(403, { errors: "Forbidden" })),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_search_iocs({ value: "192.0.2.50" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toBe("MISP request failed: http (status 403).");
    });

    it("maps network failures to a local network failure", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () => {
          throw new Error("getaddrinfo ENOTFOUND");
        }),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_add_event({ confirm: true, info: "Unreachable host" });

      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "network", status: 0 });
      expect(result.content[0].text).toMatch(/reconcile/i);
    });

    it("returns success JSON when the server responds 200", async () => {
      vi.stubGlobal(
        "fetch",
        createMockFetch(async () =>
          jsonResponse(200, { Event: { id: "99", uuid: "uuid-99" } }),
        ),
      );
      const handlers = await registerMispHandlers();

      const result = await handlers.misp_add_event({ confirm: true, info: "Created event" });

      expect(result.isError).toBeUndefined();
      const payload = JSON.parse(result.content[0].text);
      expect(payload.success).toBe(true);
      expect(payload.eventId).toBe("99");
    });

    it("reports per-indicator failures separately from clean IOC results", async () => {
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

      expect(result.isError).toBe(true);
      const payload = JSON.parse(result.content[0].text);
      expect(payload.totalChecked).toBe(2);
      expect(payload.totalHits).toBe(1);
      expect(payload.clean).toEqual([]);
      expect(payload.failures).toEqual([{ index: 0, failure: "network", status: 0 }]);
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

describe.each(["MISP", "TheHive"])("%s bounded remote responses", (service) => {
  async function handler() {
    const handlers = service === "MISP" ? await registerMispHandlers() : await registerTheHiveHandlers();
    return () => service === "MISP"
      ? handlers.misp_search_iocs({ value: "192.0.2.50" })
      : handlers.thehive_search_cases({ entityType: "case", limit: 20 });
  }

  it("cancels a non-success body without reading or disclosing secret-bearing data", async () => {
    let cancelled = false;
    let reads = 0;
    vi.stubGlobal("fetch", createMockFetch(async () => new Response(new ReadableStream({
      pull(controller) { reads++; controller.enqueue(new TextEncoder().encode('secret=credential https://example.com/private')); controller.close(); },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { status: 503 })));
    const call = await handler();
    const result = await call();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(`${service} request failed: http (status 503).`);
    expect(cancelled).toBe(true);
    expect(reads).toBe(0);
  });

  it("rejects an oversized Content-Length before consuming the body", async () => {
    let cancelled = false;
    let reads = 0;
    vi.stubGlobal("fetch", createMockFetch(async () => new Response(new ReadableStream({
      pull(controller) { reads++; controller.enqueue(new TextEncoder().encode("{}")); controller.close(); },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { status: 200, headers: { "Content-Length": "1048577" } })));
    const call = await handler();
    const result = await call();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(`${service} request failed: body-too-large (status 200).`);
    expect(reads).toBe(0);
    expect(cancelled).toBe(true);
  });

  it.each([undefined, "2"])("enforces the byte ceiling for chunked/lying length %s and cancels", async (length) => {
    let cancelled = false;
    let reads = 0;
    vi.stubGlobal("fetch", createMockFetch(async () => new Response(new ReadableStream({
      pull(controller) { reads++; controller.enqueue(new TextEncoder().encode('"' + "x".repeat(262144))); if (reads === 5) controller.close(); },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { status: 200, headers: length ? { "Content-Length": length } : {} })));
    const call = await handler();
    const result = await call();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(`${service} request failed: body-too-large (status 200).`);
    expect(reads).toBeLessThanOrEqual(5);
    expect(cancelled).toBe(true);
  });

  it("bounds repeated empty chunks without retaining them indefinitely", async () => {
    let reads = 0;
    let cancelled = false;
    vi.stubGlobal("fetch", createMockFetch(async () => new Response(new ReadableStream({
      pull(controller) {
        reads++;
        if (reads <= 65537) controller.enqueue(new Uint8Array(0));
        else { controller.enqueue(new TextEncoder().encode("[]")); controller.close(); }
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { status: 200 })));
    const call = await handler();
    const result = await call();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(`${service} request failed: body-too-large (status 200).`);
    expect(reads).toBeLessThanOrEqual(65537);
    expect(cancelled).toBe(true);
  });

  it("keeps the deadline active while a response body stalls", async () => {
    vi.useFakeTimers();
    let cancelled = false;
    vi.stubGlobal("fetch", createMockFetch(async () => new Response(new ReadableStream({
      pull() { return new Promise(() => {}); },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 }), { status: 200 })));
    const call = await handler();
    const pending = call();
    await vi.advanceTimersByTimeAsync(30000);
    const result = await pending;
    expect(result.content[0].text).toBe(`${service} request failed: deadline (status 200).`);
    expect(result.isError).toBe(true);
    expect(cancelled).toBe(true);
  });

  it("removes request URLs and credentials from thrown transport errors", async () => {
    vi.stubGlobal("fetch", createMockFetch(async (url, options) => {
      throw new Error(url + " " + JSON.stringify(options.headers));
    }));
    const call = await handler();
    const result = await call();
    expect(result.content[0].text).toBe(`${service} request failed: network (status 0).`);
    expect(result.isError).toBe(true);
  });

  it.each(["array", "key", "depth", "nodes"])("rejects excessive %s structure before mapping model output", async (kind) => {
    const data = kind === "array" ? Array(101).fill({})
      : kind === "key" ? { ["k".repeat(257)]: "secret" }
      : kind === "nodes" ? Object.fromEntries(Array.from({ length: 2100 }, (_, i) => [String(i), i]))
      : JSON.parse('{"nested":'.repeat(20) + '1' + '}'.repeat(20));
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(200, data)));
    const call = await handler();
    const result = await call();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(`${service} request failed: data-limit (status 200).`);
  });

  it("bounds the aggregate serialized success before returning model content", async () => {
    const items = Array.from({ length: 80 }, (_, i) => ({ id: String(i), value: "x".repeat(10000), comment: "y".repeat(1000), title: "z".repeat(10000) }));
    const data = service === "MISP" ? { response: { Attribute: items.map(({ id, value }) => ({ id, value })) } } : items.map(({ id, title }) => ({ _id: id, title }));
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(200, data)));
    const call = await handler();
    const result = await call();
    expect(result.isError).not.toBe(true);
    expect(Buffer.byteLength(result.content[0].text)).toBeLessThanOrEqual(65536);
    expect(() => JSON.parse(result.content[0].text)).not.toThrow();
  });
});

describe("bounded mutation acknowledgements", () => {
  it.each(["misp_add_event", "thehive_create_alert", "thehive_create_case"])("retains a validated %s identity on an unexpected successful status", async (name) => {
    const misp = name === "misp_add_event";
    const kind = name === "thehive_create_alert" ? "alert" : "case";
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(misp ? 201 : 200,
      misp ? { Event: { id: "42" } } : { _id: `${kind}-42` })));
    const handlers = misp ? await registerMispHandlers() : await registerTheHiveHandlers();
    const result = await handlers[name]({ confirm: true, info: "Detection", title: "Detection", tasks: [{ title: "Investigate" }] });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      outcome: "partial", [misp ? "eventId" : `${kind}Id`]: misp ? "42" : `${kind}-42`,
      failure: "http", status: misp ? 201 : 200,
    });
    expect(fetchCalls).toHaveLength(1);
  });

  it("retains MISP identity from a 101-attribute acknowledgement without repeating the POST", async () => {
    const attributes = Array.from({ length: 101 }, (_, i) => ({ type: "domain", value: `ioc-${i}.example` }));
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(200, {
      Event: { id: "42", uuid: "12345678-1234-4234-8234-123456789abc", Attribute: attributes },
    })));
    const handlers = await registerMispHandlers();
    const result = await handlers.misp_add_event({ confirm: true, info: "Detection", attributes });
    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({ success: true, eventId: "42", uuid: "12345678-1234-4234-8234-123456789abc", attributeCount: 101 });
    expect(Buffer.byteLength(result.content[0].text)).toBeLessThanOrEqual(65536);
    expect(fetchCalls).toHaveLength(1);
    expect(JSON.parse(fetchCalls[0].options.body as string).Event.Attribute).toHaveLength(101);
  });

  it.each(["alert", "case"])("keeps TheHive %s identity and child acknowledgements with unused large arrays", async (kind) => {
    vi.stubGlobal("fetch", createMockFetch(async (url) => jsonResponse(201, {
      _id: url.endsWith(`/${kind}`) ? `${kind}-42` : "child-1",
      number: 7,
      unused: Array(101).fill({ data: "remote evidence" }),
    })));
    const handlers = await registerTheHiveHandlers();
    const result = await handlers[`thehive_create_${kind}`]({
      confirm: true, title: "Detection", description: "Evidence",
      tasks: kind === "case" ? [{ title: "Investigate" }] : undefined,
      observables: [{ dataType: "domain", data: "ioc.example" }],
    });
    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({ success: true, [`${kind}Id`]: `${kind}-42`, observableCount: 1 });
    expect(fetchCalls.map((call) => new URL(call.url).pathname)).toEqual(kind === "case"
      ? ["/api/v1/case", "/api/v1/case/case-42/task", "/api/v1/case/case-42/observable"]
      : ["/api/v1/alert", "/api/v1/alert/alert-42/observable"]);
  });

  it.each([undefined, {}, ["42"], "x".repeat(129), "../other", 9007199254740992])("treats invalid MISP identity %j as unknown and never retries", async (id) => {
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(200, { Event: { id } })));
    const handlers = await registerMispHandlers();
    const result = await handlers.misp_add_event({ confirm: true, info: "Detection" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({ success: false, outcome: "unknown", status: 200, failure: "data-limit" });
    expect(result.content[0].text).toMatch(/reconcile/i);
    expect(fetchCalls).toHaveLength(1);
  });

  it.each([undefined, {}, ["case-42"], "x".repeat(129), "../other", 42])("stops before child writes when TheHive parent identity %j is invalid", async (_id) => {
    vi.stubGlobal("fetch", createMockFetch(async () => jsonResponse(201, { _id })));
    const handlers = await registerTheHiveHandlers();
    const result = await handlers.thehive_create_case({ confirm: true, title: "Detection", tasks: [{ title: "Investigate" }] });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", status: 201, failure: "data-limit" });
    expect(fetchCalls).toHaveLength(1);
  });

  it.each(["misp_add_event", "thehive_create_alert", "thehive_create_case"])("reports an unreadable successful %s acknowledgement as unknown without repeating writes", async (name) => {
    const misp = name === "misp_add_event";
    vi.stubGlobal("fetch", createMockFetch(async () => new Response("secret invalid JSON", { status: misp ? 200 : 201 })));
    const handlers = misp ? await registerMispHandlers() : await registerTheHiveHandlers();
    const result = await handlers[name]({ confirm: true, info: "Detection", title: "Detection" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({ outcome: "unknown", failure: "invalid-json", status: misp ? 200 : 201 });
    expect(result.content[0].text).toMatch(/reconcile/i);
    expect(result.content[0].text).not.toContain("secret");
    expect(fetchCalls).toHaveLength(1);
  });

  it.each(["alert", "case"])("retains confirmed %s parent and child progress when a later child response exceeds the byte cap", async (kind) => {
    vi.stubGlobal("fetch", createMockFetch(async (url) => {
      if (url.endsWith(`/${kind}`)) return jsonResponse(201, { _id: `${kind}-42` });
      if (fetchCalls.length === 2) return jsonResponse(201, {});
      return new Response("secret", { status: 201, headers: { "Content-Length": "1048577" } });
    }));
    const handlers = await registerTheHiveHandlers();
    const result = await handlers[`thehive_create_${kind}`]({
      confirm: true, title: "Detection",
      tasks: kind === "case" ? [{ title: "Investigate" }] : undefined,
      observables: [{ dataType: "domain", data: "first.example" }, { dataType: "domain", data: "second.example" }, { dataType: "domain", data: "third.example" }],
    });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      outcome: "partial", [`${kind}Id`]: `${kind}-42`,
      confirmedTaskCount: kind === "case" ? 1 : 0,
      confirmedObservableCount: kind === "case" ? 0 : 1,
      unconfirmedOperation: { kind: "observable", index: kind === "case" ? 0 : 1 },
      failure: "body-too-large", status: 201,
    });
    expect(result.content[0].text).toMatch(/reconcile/i);
    expect(result.content[0].text).not.toContain("secret");
    expect(fetchCalls).toHaveLength(3);
  });
});
