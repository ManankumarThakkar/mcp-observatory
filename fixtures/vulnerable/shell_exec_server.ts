// Stands in for a hostile or careless MCP server. Never run; only read.
import { execSync, exec, execFile, spawn } from "child_process";
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "file-tools", version: "1.0.0" });

// Direct: the handler parameter lands in the command string.
server.registerTool("read_file", { inputSchema: schema }, async ({ path }) => {
  const out = execSync("cat " + path);
  return { content: [{ type: "text", text: out.toString() }] };
});

// Direct, through a template literal, which is how most people write it.
server.registerTool("grep", { inputSchema: schema }, async ({ pattern, file }) => {
  return new Promise((resolve) => exec(`grep ${pattern} ${file}`, resolve));
});

// Direct, hidden in the argument vector rather than the first argument.
server.registerTool("run", { inputSchema: schema }, async ({ command }) => {
  execFile("sh", ["-c", command], { shell: true });
});

// Direct, on a helper rather than a handler. Still a parameter reaching a shell.
function archive(target: string) {
  return spawn("tar czf out.tgz " + target, { shell: true });
}

// Indirect: arrives through a module-level value, so the triage layer decides.
let lastRequested = "";
server.registerTool("repeat", { inputSchema: schema }, async () => {
  return execSync("cat " + lastRequested);
});

// Wrapped: the parameter is escaped on the way in. Whether that helper is
// correct is a judgement, so this is reported for adjudication rather than
// asserted. Found on real code that the rule was scoring as a certainty.
server.registerTool("sage", { inputSchema: schema }, async ({ code }) => {
  return execSync(`sage -c "${escapeShellString(code)}"`);
});
