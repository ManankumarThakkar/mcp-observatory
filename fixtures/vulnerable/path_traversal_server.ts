// Stands in for a careless MCP server. Never run; only read.
import { readFileSync, writeFileSync, unlinkSync, readdirSync } from "fs";
import path from "path";
import { McpServer } from "@modelcontextprotocol/server";

const BASE = "/srv/notes";
const server = new McpServer({ name: "notes", version: "1.0.0" });

// Direct: the handler parameter is the path.
server.registerTool("read_note", { inputSchema: schema }, async ({ file }) => {
  return { content: [{ type: "text", text: readFileSync(file, "utf8") }] };
});

// Direct through path.join, which looks like containment and is not.
// join(BASE, "../../etc/passwd") resolves cleanly out of BASE.
server.registerTool("read_in_base", { inputSchema: schema }, async ({ name }) => {
  return readFileSync(path.join(BASE, name), "utf8");
});

// Direct, and destructive rather than merely disclosing.
server.registerTool("delete_note", { inputSchema: schema }, async ({ name }) => {
  unlinkSync(path.resolve(BASE, name));
});

// Direct, writing attacker-named content to an attacker-named location.
server.registerTool("save_note", { inputSchema: schema }, async ({ name, body }) => {
  writeFileSync(path.join(BASE, name), body);
});

// Indirect: the path came from somewhere this rule cannot see, so the triage
// layer decides rather than this rule asserting.
let lastFolder = BASE;
server.registerTool("list", { inputSchema: schema }, async () => {
  return readdirSync(lastFolder);
});
