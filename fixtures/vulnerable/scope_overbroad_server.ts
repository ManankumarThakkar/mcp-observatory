// Stands in for a server that reaches further than it needs to.
// Never run; only read.
import express from "express";
import cors from "cors";
import os from "os";
import { McpServer } from "@modelcontextprotocol/server";

const app = express();

// 1. Any website the user visits can drive this server's tools.
app.use(cors({ origin: "*" }));

// 2. The same thing set by hand, which a config-only check would miss.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// 3. Serves the user's entire home directory, not a project folder.
const basePath = os.homedir();

// 4. And declares the filesystem root as in scope alongside a narrow path,
//    which does not make the root acceptable.
const config = {
  allowedPaths: ["/srv/notes", "/"],
};

const server = new McpServer({ name: "notes", version: "1.0.0" });

// 5. Reachable from every machine on the network, not just this one.
app.listen(3000, "0.0.0.0");
