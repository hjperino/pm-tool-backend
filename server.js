import express from "express";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

// ---- Konfiguration aus ENV (Render -> Environment)
const JSONBIN_BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY;
const EDIT_PASSWORD_HASH = process.env.EDIT_PASSWORD_HASH; // bcrypt-hash

// CORS
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim().replace(/\/$/, ""))
  .filter(Boolean);

// Mail
const MAIL_DEBOUNCE_MINUTES = Number(process.env.MAIL_DEBOUNCE_MINUTES || "5");
const MAIL_FROM = process.env.MAIL_FROM || "PM Tool <teamki4@dlh.zh.ch>";
const MAIL_SUBJECT_PREFIX = process.env.MAIL_SUBJECT_PREFIX || "[PM-Tool]";

// TEAM_EMAILS_JSON: {"Hansjuerg Perino":"hansjuerg.perino@dlh.zh.ch","Name2":"name2@..."}
let TEAM_EMAILS = {};
try {
  TEAM_EMAILS = JSON.parse(process.env.TEAM_EMAILS_JSON || "{}");
} catch {
  TEAM_EMAILS = {};
}

// ---- SMTP Transport (only if configured)
const smtpConfigured =
  !!process.env.SMTP_HOST &&
  !!process.env.SMTP_PORT &&
  !!process.env.SMTP_USER &&
  !!process.env.SMTP_PASS;

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    })
  : null;

// ---- sehr simples CORS (nur erlaubte Origins)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const normalizedOrigin = origin ? origin.replace(/\/$/, "") : "";

  if (normalizedOrigin && ALLOWED_ORIGINS.includes(normalizedOrigin)) {
    res.setHeader("Access-Control-Allow-Origin", normalizedOrigin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,PUT,POST,OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type,X-Editor-Token,X-Editor-Name,X-Editor-Email"
    );
  }

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function jsonbinUrl() {
  if (!JSONBIN_BIN_ID) throw new Error("Missing JSONBIN_BIN_ID");
  return `https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`;
}

// ---- Token-Mechanik (minimalistisch)
function makeToken() {
  return (
    Math.random().toString(36).slice(2) +
    Math.random().toString(36).slice(2) +
    Date.now().toString(36)
  );
}

const tokenStore = new Map(); // token -> expiresAt

function requireEditor(req, res, next) {
  const token = req.headers["x-editor-token"];
  if (!token || typeof token !== "string") return res.status(401).json({ ok: false });

  const exp = tokenStore.get(token);
  if (!exp || exp < Date.now()) return res.status(401).json({ ok: false });

  // optional identity
  req.editorName = (req.headers["x-editor-name"] || "").toString();
  req.editorEmail = (req.headers["x-editor-email"] || "").toString();

  next();
}

// ---- Health
app.get("/health", (req, res) => res.json({ ok: true }));

// ---- Auth: Passwort -> token
app.post("/api/auth", async (req, res) => {
  try {
    const password = (req.body?.password ?? "").toString().trim();
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

// ---- Load: tasks+log aus jsonbin
app.get("/api/data", async (req, res) => {
  try {
    const r = await fetch(jsonbinUrl(), {
      headers: {
        "X-Master-Key": JSONBIN_API_KEY,
      },
    });
    if (!r.ok) return res.status(502).json({ error: "jsonbin load failed" });
    const data = await r.json();
    res.json(data);
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

// -------------------- MAIL: Change detection + debounce --------------------

const WATCH_FIELDS = ["status", "title", "description", "deadline", "links", "assignedTo"];

function normalizeTask(t) {
  const o = {};
  for (const f of WATCH_FIELDS) o[f] = t?.[f];
  // normalize arrays for stable compare
  if (Array.isArray(o.links)) o.links = [...o.links];
  if (Array.isArray(o.assignedTo)) o.assignedTo = [...o.assignedTo];
  return o;
}

function jsonStable(v) {
  // stable-ish stringify for objects containing arrays/primitives
  return JSON.stringify(v, (key, value) => {
    if (Array.isArray(value)) return [...value].sort();
    return value;
  });
}

function diffTasks(oldTasks, newTasks) {
  const oldMap = new Map((oldTasks || []).map((t) => [t.id, t]));
  const newMap = new Map((newTasks || []).map((t) => [t.id, t]));

  const changes = []; // {type, id, before, after, recipients:Set<string>}
  const allIds = new Set([...oldMap.keys(), ...newMap.keys()]);

  for (const id of allIds) {
    const before = oldMap.get(id);
    const after = newMap.get(id);

    const beforeAssigned = new Set((before?.assignedTo || []).map(String));
    const afterAssigned = new Set((after?.assignedTo || []).map(String));
    const recipients = new Set([...beforeAssigned, ...afterAssigned]);

    if (!before && after) {
      changes.push({ type: "created", id, before: null, after, recipients });
      continue;
    }
    if (before && !after) {
      changes.push({ type: "deleted", id, before, after: null, recipients });
      continue;
    }

    const b = normalizeTask(before);
    const a = normalizeTask(after);

    if (jsonStable(b) !== jsonStable(a)) {
      changes.push({ type: "updated", id, before, after, recipients });
    }
  }

  return changes;
}

function resolveEmailForName(name) {
  if (!name) return null;
  const direct = TEAM_EMAILS[name];
  if (direct) return direct;
  // fallback: try case-insensitive match
  const key = Object.keys(TEAM_EMAILS).find((k) => k.toLowerCase() === String(name).toLowerCase());
  return key ? TEAM_EMAILS[key] : null;
}

function buildMailTextForRecipient(recipientName, recipientEmail, changes, editorName, editorEmail) {
  const editorLine =
    editorName || editorEmail
      ? `Editor: ${editorName || "-"}${editorEmail ? ` <${editorEmail}>` : ""}`
      : "Editor: (unknown)";

  const lines = [];
  lines.push(`${MAIL_SUBJECT_PREFIX} Task-Update`);
  lines.push("");
  lines.push(editorLine);
  lines.push(`Time: ${new Date().toISOString()}`);
  lines.push("");

  for (const c of changes) {
    if (c.type === "created") {
      lines.push(`NEW: ${c.after?.title || "(no title)"} (id=${c.id})`);
      lines.push(`  Status: ${c.after?.status || "-"}`);
      lines.push(`  Deadline: ${c.after?.deadline || "-"}`);
      lines.push("");
    } else if (c.type === "deleted") {
      lines.push(`DELETED: ${c.before?.title || "(no title)"} (id=${c.id})`);
      lines.push("");
    } else {
      // updated: show changed fields
      lines.push(`UPDATED: ${c.after?.title || c.before?.title || "(no title)"} (id=${c.id})`);
      for (const f of WATCH_FIELDS) {
        const bv = normalizeTask(c.before)[f];
        const av = normalizeTask(c.after)[f];
        if (jsonStable(bv) !== jsonStable(av)) {
          lines.push(`  - ${f}: ${JSON.stringify(bv)}  ->  ${JSON.stringify(av)}`);
        }
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

// Debounce store: email -> {recipientName, changes:[], timer, editorName, editorEmail}
const pendingByEmail = new Map();

async function sendDebouncedMail(email) {
  const entry = pendingByEmail.get(email);
  if (!entry) return;

  pendingByEmail.delete(email);

  if (!smtpConfigured || !transporter) {
    console.log("MAIL: SMTP not configured, skipping send to", email);
    return;
  }

  const subject = `${MAIL_SUBJECT_PREFIX} Task-Update (${entry.changes.length})`;
  const text = buildMailTextForRecipient(
    entry.recipientName,
    email,
    entry.changes,
    entry.editorName,
    entry.editorEmail
  );

  console.log("MAIL: sending to", email, "changes:", entry.changes.length);

  try {
    await transporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject,
      text,
    });
    console.log("MAIL: sent OK to", email);
  } catch (e) {
    console.log("MAIL: send FAIL to", email, e?.message || e);
  }
}

function queueMail(recipientName, recipientEmail, changes, editorName, editorEmail) {
  if (!recipientEmail) return;

  const existing = pendingByEmail.get(recipientEmail);
  if (!existing) {
    const timer = setTimeout(() => {
      sendDebouncedMail(recipientEmail);
    }, MAIL_DEBOUNCE_MINUTES * 60 * 1000);

    pendingByEmail.set(recipientEmail, {
      recipientName,
      changes: [...changes],
      timer,
      editorName,
      editorEmail,
    });

    console.log(
      "MAIL: queued",
      recipientEmail,
      "changes:",
      changes.length,
      "debounce(min):",
      MAIL_DEBOUNCE_MINUTES
    );
  } else {
    // extend existing
    existing.changes.push(...changes);
    existing.editorName = editorName || existing.editorName;
    existing.editorEmail = editorEmail || existing.editorEmail;

    clearTimeout(existing.timer);
    existing.timer = setTimeout(() => {
      sendDebouncedMail(recipientEmail);
    }, MAIL_DEBOUNCE_MINUTES * 60 * 1000);

    console.log("MAIL: updated queue", recipientEmail, "total changes:", existing.changes.length);
  }
}

// ---- Save: schreibt tasks+log zu jsonbin (nur mit gültigem Token) + mail queue
app.put("/api/data", requireEditor, async (req, res) => {
  try {
    const body = req.body || {};

    // Load old data first for diff
    let oldTasks = [];
    try {
      const rOld = await fetch(jsonbinUrl(), {
        headers: { "X-Master-Key": JSONBIN_API_KEY },
      });
      if (rOld.ok) {
        const oldData = await rOld.json();
        oldTasks = oldData?.record?.tasks || [];
      }
    } catch {
      // If load fails, we still save, but mail diff might be empty
      oldTasks = [];
    }

    // Save new data
    const r = await fetch(jsonbinUrl(), {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Master-Key": JSONBIN_API_KEY,
      },
      body: JSON.stringify(body),
    });

    if (!r.ok) return res.status(502).json({ error: "jsonbin save failed" });

    // Diff + queue mails AFTER successful save
    const newTasks = body?.tasks || [];
    const changes = diffTasks(oldTasks, newTasks);

    if (changes.length === 0) {
      console.log("MAIL: no relevant task changes detected");
    } else {
      // group by recipient name -> email
      const perRecipient = new Map(); // email -> {name, changes:[]}

      for (const c of changes) {
        for (const name of c.recipients) {
          const email = resolveEmailForName(name);
          if (!email) continue;

          if (!perRecipient.has(email)) perRecipient.set(email, { name, changes: [] });
          perRecipient.get(email).changes.push(c);
        }
      }

      const editorName = req.editorName || "";
      const editorEmail = req.editorEmail || "";

      for (const [email, payload] of perRecipient.entries()) {
        queueMail(payload.name, email, payload.changes, editorName, editorEmail);
      }

      if (perRecipient.size === 0) {
        console.log("MAIL: changes detected but no recipients matched TEAM_EMAILS_JSON");
      }
    }

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
