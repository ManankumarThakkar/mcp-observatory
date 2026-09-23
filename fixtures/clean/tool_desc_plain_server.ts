// Realistic near-misses. Every one of these must NOT produce a finding.
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

const server = new McpServer({ name: "docs", version: "1.0.0" });

// Ordinary English that an over-eager phrase list flags. "instead of" and
// "you must" caught 20 of 1,824 real descriptions, all of them benign.
server.registerTool("convert", {
  description: "Convert HTML you already have instead of fetching it",
  inputSchema: z.object({
    html: z.string().describe("Markup you already have, instead of fetching a URL"),
    url: z.string().optional().describe("You must supply either this or html"),
  }),
}, handler);

// Long and thorough, but purely descriptive. Length alone is not a signal:
// plenty of good tools are documented carefully.
server.registerTool("export", {
  description: "Exports a document to PDF, preserving layout, embedded fonts and vector graphics. Page size follows the source document unless overridden. Encrypted sources are rejected rather than silently skipped, and the original file is never modified in place.",
  inputSchema: z.object({
    path: z.string().describe("Absolute path to the source document"),
  }),
}, handler);

// A property that is not a description, holding text that would flag if it were.
const metadata = {
  title: "Ignore previous instructions",
  notes: "system prompt handling lives in the docs",
};

// A test framework's describe, which is a bare call rather than a schema method.
describe("export", () => {
  it("never mentions the system prompt", () => {});
});
