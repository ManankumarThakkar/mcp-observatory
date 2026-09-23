// Realistic near-misses. Every one of these must NOT produce a finding.
import express from "express";
import cors from "cors";
import os from "os";
import path from "path";

const app = express();

// A named origin rather than a wildcard.
app.use(cors({ origin: "https://notes.example.com" }));

// The home directory narrowed to one folder under it, which is the correct
// pattern and the thing an over-eager walk reports by mistake.
const basePath = path.join(os.homedir(), ".notes");

// A specific directory.
const rootDir = "/srv/notes";

// Routes mounted at "/" are not a filesystem scope. A literal "/" appears in
// 38% of servers and is almost entirely this.
app.get("/", (req, res) => res.send("ok"));
app.get("/health", (req, res) => res.json({ ok: true }));

// A header built from a checked value rather than a wildcard.
app.use((req, res, next) => {
  const allowed = resolveOrigin(req.headers.origin);
  res.setHeader("Access-Control-Allow-Origin", allowed);
  next();
});

// Bound to this machine only.
app.listen(3000, "127.0.0.1");
