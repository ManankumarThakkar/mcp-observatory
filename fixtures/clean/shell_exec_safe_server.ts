// Realistic near-misses. Every one of these must NOT produce a finding.
import { execSync, execFile, spawn } from "child_process";
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "safe-tools", version: "1.0.0" });

// A fixed command with no input in it at all.
server.registerTool("status", { inputSchema: schema }, async () => {
  return execSync("git status --porcelain").toString();
});

// An argument vector. There is no shell here to inject into.
server.registerTool("log", { inputSchema: schema }, async ({ file }) => {
  return spawn("git", ["log", "--oneline", "--", file]);
});

// execFile without a shell, passing the parameter as a separate argument.
server.registerTool("head", { inputSchema: schema }, async ({ file }) => {
  return execFile("head", ["-n", "20", file]);
});

// shell explicitly disabled, which text matching would get wrong.
server.registerTool("count", { inputSchema: schema }, async ({ file }) => {
  return spawn("wc", ["-l", file], { shell: false });
});

// A method that happens to be called exec, on something that is not a process.
const db = { exec: (sql: string) => sql };
server.registerTool("query", { inputSchema: schema }, async ({ table }) => {
  return db.exec("SELECT * FROM " + table);
});
