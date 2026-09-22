// Realistic near-misses. Every one of these must NOT produce a finding.
import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { readFile as fetchRemote } from "./remote-storage";
import { McpServer } from "@modelcontextprotocol/server";

const BASE = "/srv/notes";
const server = new McpServer({ name: "safe-notes", version: "1.0.0" });

// Resolved, then proved to be inside the base. The idiomatic Node defence.
server.registerTool("read_note", { inputSchema: schema }, async ({ name }) => {
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) {
    throw new Error("outside the notes directory");
  }
  return readFileSync(full, "utf8");
});

// The other idiomatic form: if the relative path climbs, refuse it.
server.registerTool("save_note", { inputSchema: schema }, async ({ name, body }) => {
  const full = path.resolve(BASE, name);
  if (path.relative(BASE, full).startsWith("..")) {
    throw new Error("outside the notes directory");
  }
  writeFileSync(full, body);
});

// A fixed path with no input in it at all.
server.registerTool("config", { inputSchema: schema }, async () => {
  return readFileSync("/etc/notes/config.json", "utf8");
});

// A function named readFile that is not Node's filesystem.
server.registerTool("remote", { inputSchema: schema }, async ({ key }) => {
  return fetchRemote(key);
});
