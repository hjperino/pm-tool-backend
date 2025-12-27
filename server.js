import express from "express";
import helmet from "helmet";
import bcrypt from "bcryptjs";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

// ---- Konfiguration aus ENV (Render -> Environment)
const JSONBIN_BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY;
const EDIT_PASSWORD_HASH = process.env.EDIT_PASSWORD_HASH; // bcrypt-hash
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// ---- sehr simples CORS (nur deine erlaubten Origins)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,PUT,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-Editor-Token");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function jsonbinUrl() {
  if (!JSONBIN_BIN_ID) throw new Error("Missing JSONBIN_BIN_ID");
  return `https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`;
}

// ---- Token-Mechanik (minimalistisch, aber besser als Passwort im Frontend)
// Wir geben bei erfolgreicher Passwortprüfung ein kurzlebiges Token zurück.
function makeToken() {
  // simpel: random string; in produktiv evtl. JWT. Für deinen Zweck reicht das oft.
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}
const tokenStore = new Map(); // token -> expiresAt (ms)

function requireEditor(req, res, next) {
  const token = req.headers["x-editor-token"];
  if (!token || !tokenStore.has(token)) return res.status(401).json({ error: "Not authorized" });
  const expiresAt = tokenStore.get(token);
  if (Date.now() > expiresAt) {
    tokenStore.delete(token);
    return res.status(401).json({ error: "Token expired" });
  }
  next();
}

// ---- Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---- Load: holt tasks+log aus jsonbin
app.get("/api/data", async (_req, res) => {
  try {
    const r = await fetch(jsonbinUrl(), {
      headers: { "X-Master-Key": JSONBIN_API_KEY }
    });
    if (!r.ok) return res.status(502).json({ error: "jsonbin load failed" });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

// ---- Auth: prüft Passwort und gibt Token
app.post("/api/auth", async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ ok: false });

    const ok = await bcrypt.compare(password, EDIT_PASSWORD_HASH || "");
    if (!ok) return res.status(401).json({ ok: false });

    const token = makeToken();
    tokenStore.set(token, Date.now() + 1000 * 60 * 60); // 1h gültig
    res.json({ ok: true, token });
  } catch {
    res.status(500).json({ ok: false });
  }
});

// ---- Save: schreibt tasks+log zu jsonbin (nur mit gültigem Token)
app.put("/api/data", requireEditor, async (req, res) => {
  try {
    const body = req.body || {};
    const r = await fetch(jsonbinUrl(), {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Master-Key": JSONBIN_API_KEY
      },
      body: JSON.stringify(body)
    });
    if (!r.ok) return res.status(502).json({ error: "jsonbin save failed" });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));