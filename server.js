import express from "express";
import dotenv from "dotenv";
import { createClient } from "@libsql/client";
import crypto from "crypto";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Turso (libSQL) — se TURSO_DATABASE_URL não estiver definido, cai num arquivo local
// (útil só pra testar no seu próprio computador; em produção sempre use Turso).
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "file:codelar.db",
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
  intMode: "number",
});

async function setup() {
  await db.batch(
    [
      `CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'employee',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        notes TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        direction TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(client_id) REFERENCES clients(id)
      )`,
    ],
    "write"
  );

  // Migração segura: adiciona colunas novas em bancos que já existiam antes dessas features.
  const info = await db.execute("PRAGMA table_info(clients)");
  const existing = info.rows.map((r) => r.name);
  async function addColIfMissing(col, defSql) {
    if (!existing.includes(col)) {
      await db.execute(`ALTER TABLE clients ADD COLUMN ${defSql}`);
      existing.push(col);
    }
  }
  await addColIfMissing("client_date", "client_date TEXT");
  await addColIfMissing("site_type", "site_type TEXT");
  await addColIfMissing("site_specs", "site_specs TEXT");
  await addColIfMissing("amount_paid_cents", "amount_paid_cents INTEGER NOT NULL DEFAULT 0");
  await addColIfMissing("finished", "finished INTEGER NOT NULL DEFAULT 0");
  await addColIfMissing("finished_at", "finished_at TEXT");
}

const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");

// Acesso por PIN único (uso pessoal, uma pessoa só).
// O PIN fica no .env do servidor — nunca no frontend, nunca no código versionado.
if (!process.env.DASHBOARD_PIN) {
  console.warn("Aviso: DASHBOARD_PIN não definido no .env — ninguém vai conseguir desbloquear o painel.");
}
const validTokens = new Set(); // tokens de sessão em memória (somem ao reiniciar o servidor)

app.use(express.json());
app.use(express.static("public"));

function auth(req, res, next) {
  const token = req.headers["x-codelar-token"];
  if (!token || !validTokens.has(token)) return res.status(401).json({ error: "Não autenticado" });
  next();
}

app.post("/api/unlock", (req, res) => {
  const { pin } = req.body || {};
  if (!process.env.DASHBOARD_PIN || pin !== process.env.DASHBOARD_PIN) {
    return res.status(401).json({ error: "PIN incorreto" });
  }
  const token = crypto.randomBytes(24).toString("hex");
  validTokens.add(token);
  res.json({ token });
});

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const finishedR = await db.execute("SELECT COUNT(*) c FROM clients WHERE finished=1");
    const totalR = await db.execute("SELECT COALESCE(SUM(amount_paid_cents),0) n FROM clients");
    const now = new Date();
    const monthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-01`;
    const monthR = await db.execute({
      sql: "SELECT COALESCE(SUM(amount_paid_cents),0) n FROM clients WHERE COALESCE(client_date,created_at)>=?",
      args: [monthStart],
    });
    const salesR = await db.execute({
      sql: "SELECT COUNT(*) c FROM clients WHERE COALESCE(client_date,created_at)>=? AND amount_paid_cents>0",
      args: [monthStart],
    });
    res.json({
      finished: finishedR.rows[0].c,
      totalReceived: totalR.rows[0].n,
      monthReceived: monthR.rows[0].n,
      salesMonth: salesR.rows[0].c,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao consultar dashboard" });
  }
});

app.get("/api/clients", auth, async (req, res) => {
  const r = await db.execute("SELECT * FROM clients WHERE finished=0 ORDER BY id DESC");
  res.json(r.rows);
});
app.get("/api/clients/history", auth, async (req, res) => {
  const r = await db.execute("SELECT * FROM clients WHERE finished=1 ORDER BY finished_at DESC");
  res.json(r.rows);
});
app.post("/api/clients", auth, async (req, res) => {
  const { name, email = "", phone = "", client_date = null, site_type = "", site_specs = "", amount_paid_cents = 0 } = req.body || {};
  if (!name) return res.status(400).json({ error: "Nome é obrigatório" });
  const r = await db.execute({
    sql: `INSERT INTO clients(name,email,phone,client_date,site_type,site_specs,amount_paid_cents) VALUES(?,?,?,?,?,?,?)`,
    args: [name, email, phone, client_date, site_type, site_specs, Number(amount_paid_cents) || 0],
  });
  res.json({ id: Number(r.lastInsertRowid) });
});
app.put("/api/clients/:id/finish", auth, async (req, res) => {
  const { finished = 1 } = req.body || {};
  const finished_at = Number(finished) === 1 ? new Date().toISOString() : null;
  await db.execute({
    sql: "UPDATE clients SET finished=?, finished_at=? WHERE id=?",
    args: [Number(finished), finished_at, req.params.id],
  });
  res.json({ ok: true });
});
app.delete("/api/clients/:id", auth, async (req, res) => {
  await db.execute({ sql: "DELETE FROM clients WHERE id=?", args: [req.params.id] });
  res.json({ ok: true });
});

app.get("/api/messages", auth, async (req, res) => {
  const r = await db.execute(
    `SELECT m.*, c.name client_name FROM messages m LEFT JOIN clients c ON c.id=m.client_id ORDER BY m.created_at DESC LIMIT 200`
  );
  res.json(r.rows);
});
app.post("/api/messages", auth, async (req, res) => {
  const { client_id, body } = req.body || {};
  if (!body) return res.status(400).json({ error: "Mensagem vazia" });
  const r = await db.execute({
    sql: "INSERT INTO messages(client_id,direction,body) VALUES(?,?,?)",
    args: [client_id || null, "outbound", body],
  });
  res.json({ id: Number(r.lastInsertRowid) });
});

app.get("/*splat", (req, res) => res.sendFile(process.cwd() + "/public/index.html"));

setup()
  .then(() => {
    app.listen(port, () => console.log(`Codelar OS em http://localhost:${port}`));
  })
  .catch((e) => {
    console.error("Erro ao inicializar o banco de dados:", e);
    process.exit(1);
  });
