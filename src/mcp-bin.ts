import { serveMcp } from "./mcp-server.js";

process.on("unhandledRejection", (reason) => {
  console.error("[zeek-mcp] unhandled rejection", reason);
});

try {
  await serveMcp();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[zeek-mcp] ${message}`);
  process.exitCode = 1;
}
