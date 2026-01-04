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
// ---- Mail / Team mapping
const TEAM_EMAILS = (() => {
  try {
    return JSON.parse(process.env.TEAM_EMAILS_JSON || "{}");
  } catch {
    return {};
  }
})();

const MAIL_FROM = process.env.MAIL_FROM || "PM-Tool <no-reply@example.com>";
const MAIL_SUBJECT_PREFIX = process.env.MAIL_SUBJECT_PREFIX || "[PM-Tool]";
const MAIL_DEBOUNCE_MINUTES = Number(process.env.MAIL_DEBOUNCE_MINUTES || "5");

// ---- SMTP (Brevo)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_SECURE === "true", // 587 => false (STARTTLS)
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// optional: verify once on start (logs help a lot)
transporter.verify()
  .then(() => console.log("SMTP ready"))
  .catch(err => console.error("SMTP error:", err.message));

// ---- Debounce queue: one digest per recipient
// Map<email, { timer: Timeout|null, items: Array<ChangeEvent>, lastEditor: {name,email}? }>
const mailQueue = new Map();

function resolveRecipientEmails(assignedTo) {
  const names = Array.isArray(assignedTo) ? assignedTo : [];
  const emails = [];
  for (const n of names) {
    const e = TEAM_EMAILS[n];
    if (e) emails.push(e);
  }
  // unique + stable
  return [...new Set(emails)];
}

function safeStr(v) {
  return (v === null || v === undefined) ? "" : String(v);
}

function normalizeLinks(task) {
  // your tasks may store links differently; support common patterns
  const links = task?.links ?? task?.link ?? task?.url ?? null;
  if (!links) return [];
  if (Array.isArray(links)) return links.map(safeStr).map(s => s.trim()).filter(Boolean);
  return safeStr(links).split(/\s+/).map(s => s.trim()).filter(Boolean);
}

function pickComparable(t) {
  return {
    status: safeStr(t?.status).trim(),
    title: safeStr(t?.title).trim(),
    description: safeStr(t?.description ?? t?.comment).trim(),
    deadline: safeStr(t?.deadline).trim(),
    links: normalizeLinks(t).sort(),
    assignedTo: Array.isArray(t?.assignedTo) ? [...t.assignedTo].sort() : []
  };
}

function diffOne(oldT, newT) {
  const a = pickComparable(oldT);
  const b = pickComparable(newT);

  const changes = [];
  const fields = ["status","title","description","deadline"] as const;

  for (const f of fields) {
    if (a[f] !== b[f]) changes.push({ field: f, from: a[f], to: b[f] });
  }

  // links
  if (JSON.stringify(a.links) !== JSON.stringify(b.links)) {
    changes.push({ field: "links", from: a.links.join(" "), to: b.links.join(" ") });
  }

  // assignedTo
  if (JSON.stringify(a.assignedTo) !== JSON.stringify(b.assignedTo)) {
    changes.push({ field: "assignedTo", from: a.assignedTo.join(", "), to: b.assignedTo.join(", ") });
  }

  return changes;
}

function diffTasks(oldTasks, newTasks) {
  const oldMap = new Map((oldTasks || []).map(t => [t.id, t]));
  const newMap = new Map((newTasks || []).map(t => [t.id, t]));

  const created = [];
  const deleted = [];
  const updated = [];

  for (const [id, nt] of newMap.entries()) {
    const ot = oldMap.get(id);
    if (!ot) {
      created.push(nt);
    } else {
      const changes = diffOne(ot, nt);
      if (changes.length) updated.push({ oldTask: ot, newTask: nt, changes });
    }
  }

  for (const [id, ot] of oldMap.entries()) {
    if (!newMap.has(id)) deleted.push(ot);
  }

  return { created, deleted, updated };
}

function formatDigestText(changeEvents, editor) {
  const who = editor?.name
    ? `${editor.name}${editor.email ? ` <${editor.email}>` : ""}`
    : (editor?.email || "unbekannt");

  const lines = [];
  lines.push(`${MAIL_SUBJECT_PREFIX} Task-Änderungen`);
  lines.push(`Geändert von: ${who}`);
  lines.push(`Zeit: ${new Date().toLocaleString("de-CH")}`);
  lines.push("");
  for (const ev of changeEvents) {
    if (ev.type === "created") {
      lines.push(`NEU: ${safeStr(ev.task?.title)} (ID ${ev.task?.id})`);
      lines.push(`Status: ${safeStr(ev.task?.status)} | Deadline: ${safeStr(ev.task?.deadline)}`);
      lines.push("");
    } else if (ev.type === "deleted") {
      lines.push(`GELÖSCHT: ${safeStr(ev.task?.title)} (ID ${ev.task?.id})`);
      lines.push("");
    } else if (ev.type === "updated") {
      lines.push(`GEÄNDERT: ${safeStr(ev.task?.title)} (ID ${ev.task?.id})`);
      for (const c of ev.changes) {
        lines.push(`- ${c.field}: "${safeStr(c.from)}" → "${safeStr(c.to)}"`);
      }
      lines.push("");
    }
  }
  return lines.join("\n");
}

async function sendDigestEmail(toEmail, changeEvents, editor) {
  const subject = `${MAIL_SUBJECT_PREFIX} Änderungen an deinen Tasks (${changeEvents.length})`;
  const text = formatDigestText(changeEvents, editor);

  await transporter.sendMail({
    from: MAIL_FROM,
    to: toEmail,
    subject,
    text
  });
}

function enqueueChanges(recipientEmail, changeEvents, editor) {
  const existing = mailQueue.get(recipientEmail) || { timer: null, items: [], lastEditor: null };
  existing.items.push(...changeEvents);
  existing.lastEditor = editor || existing.lastEditor;

  if (!existing.timer) {
    existing.timer = setTimeout(async () => {
      const data = mailQueue.get(recipientEmail);
      if (!data) return;

      // Snapshot then clear before sending (avoid duplicates on error loops)
      const items = data.items.slice();
      const ed = data.lastEditor;
      mailQueue.delete(recipientEmail);

      try {
        await sendDigestEmail(recipientEmail, items, ed);
        console.log("Digest sent to", recipientEmail, "items:", items.length);
      } catch (err) {
        console.error("Digest send failed to", recipientEmail, err?.message || err);
        // If you want retry, re-enqueue once:
        // enqueueChanges(recipientEmail, items, ed);
      }
    }, MAIL_DEBOUNCE_MINUTES * 60 * 1000);
  }

  mailQueue.set(recipientEmail, existing);
}
app.listen(port, () => console.log("Listening on", port));
