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
  await addColIfMissing("site_category", "site_category TEXT");
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
  const { name, email = "", phone = "", client_date = null, site_type = "", site_category = "", site_specs = "", amount_paid_cents = 0 } = req.body || {};
  if (!name) return res.status(400).json({ error: "Nome é obrigatório" });
  const r = await db.execute({
    sql: `INSERT INTO clients(name,email,phone,client_date,site_type,site_category,site_specs,amount_paid_cents) VALUES(?,?,?,?,?,?,?,?)`,
    args: [name, email, phone, client_date, site_type, site_category, site_specs, Number(amount_paid_cents) || 0],
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

function normalizeText(s) {
  return (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();
}
// Termos comuns em português -> categoria do OpenStreetMap (pra busca por região, mais resultados que texto livre).
const TAG_MAP = {
  padaria: "bakery", panificadora: "bakery",
  restaurante: "restaurant", pizzaria: "pizza", lanchonete: "fast_food",
  academia: "gym", farmacia: "pharmacy",
  salao: "hairdresser", "salao de beleza": "hairdresser", barbearia: "hairdresser",
  clinica: "clinic", dentista: "dentist", "clinica odontologica": "dentist",
  advocacia: "lawyer", advogado: "lawyer",
  contabilidade: "accounting", contador: "accounting",
  petshop: "pet", "pet shop": "pet",
  oficina: "car_repair", mecanica: "car_repair", "oficina mecanica": "car_repair",
  mercado: "supermarket", supermercado: "supermarket", mercearia: "convenience",
  hotel: "hotel", pousada: "guest_house",
  livraria: "bookshop", papelaria: "stationery",
  floricultura: "florist", joalheria: "jewelry",
  otica: "optician", imobiliaria: "real_estate_agency",
  "loja de roupas": "clothes", boutique: "clothes",
  cafe: "cafe", cafeteria: "cafe",
};
function phoneToWhatsapp(raw) {
  if (!raw) return null;
  const digits = String(raw).replace(/\D/g, "");
  if (!digits) return null;
  if (digits.startsWith("55") && digits.length >= 12) return digits;
  if (digits.length === 10 || digits.length === 11) return "55" + digits;
  if (digits.length >= 12) return digits;
  return null;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Prospecção: busca empresas via LocationIQ (compatível com Nominatim/OpenStreetMap).
// Precisa de uma chave gratuita em locationiq.com (5.000 buscas/dia grátis, sem cartão).
// Só retorna quem tem telefone encontrado (pra permitir o botão de WhatsApp) — é um indício
// de oportunidade baseado em dado público, não garantia de que a empresa não tem site.
app.get("/api/prospect", auth, async (req, res) => {
  const query = (req.query.query || "").trim();
  const state = (req.query.state || "").trim();
  const city = (req.query.city || "").trim();
  if (!query) return res.status(400).json({ error: "Informe o tipo de negócio que você quer buscar" });
  const key = process.env.LOCATIONIQ_API_KEY;
  if (!key) {
    return res.status(503).json({ error: "Busca de empresas ainda não configurada — falta a chave LOCATIONIQ_API_KEY no servidor." });
  }

  const locationParts = [city, state, "Brasil"].filter(Boolean).join(", ");
  const tag = TAG_MAP[normalizeText(query)];

  try {
    let rawResults = [];

    if (tag) {
      // 1) acha um ponto central pra região pedida
      const geoUrl = new URL("https://us1.locationiq.com/v1/search");
      geoUrl.searchParams.set("key", key);
      geoUrl.searchParams.set("q", locationParts || "Brasil");
      geoUrl.searchParams.set("format", "json");
      geoUrl.searchParams.set("limit", "1");
      const geoR = await fetch(geoUrl, { headers: { Accept: "application/json" } });
      const geoText = await geoR.text();
      if (!geoR.ok) return res.status(502).json({ error: `Não encontrei essa localização (status ${geoR.status}).` });
      const geoData = JSON.parse(geoText);
      if (!geoData.length) return res.json({ results: [] });
      const { lat, lon } = geoData[0];

      // 2) busca por categoria perto desse ponto (mais resultados que texto livre)
      const radius = city ? 10000 : state ? 45000 : 20000;
      const nearUrl = new URL("https://us1.locationiq.com/v1/nearby");
      nearUrl.searchParams.set("key", key);
      nearUrl.searchParams.set("lat", lat);
      nearUrl.searchParams.set("lon", lon);
      nearUrl.searchParams.set("tag", tag);
      nearUrl.searchParams.set("radius", String(radius));
      nearUrl.searchParams.set("format", "json");
      const nearR = await fetch(nearUrl, { headers: { Accept: "application/json" } });
      const nearText = await nearR.text();
      if (!nearR.ok) {
        console.error("LocationIQ nearby respondeu", nearR.status, nearText.slice(0, 300));
        return res.status(502).json({ error: `Busca falhou (status ${nearR.status}). ${nearText.slice(0, 150)}` });
      }
      rawResults = JSON.parse(nearText);
    } else {
      // categoria não reconhecida no dicionário: busca por texto livre
      const q = locationParts ? `${query} em ${locationParts}` : `${query}, Brasil`;
      const url = new URL("https://us1.locationiq.com/v1/search");
      url.searchParams.set("key", key);
      url.searchParams.set("q", q);
      url.searchParams.set("format", "json");
      url.searchParams.set("addressdetails", "1");
      url.searchParams.set("extratags", "1");
      url.searchParams.set("limit", "20");
      const r = await fetch(url, { headers: { Accept: "application/json" } });
      const bodyText = await r.text();
      if (!r.ok) {
        if (r.status === 404) return res.json({ results: [] });
        console.error("LocationIQ search respondeu", r.status, bodyText.slice(0, 300));
        return res.status(502).json({ error: `Busca falhou (status ${r.status}). ${bodyText.slice(0, 150)}` });
      }
      rawResults = JSON.parse(bodyText);
    }

    // A Nearby API não devolve telefone/site direto — busca esse detalhe por item (respeitando 2 req/s do plano grátis).
    const enriched = [];
    for (const item of rawResults.slice(0, 18)) {
      let phone = item.extratags?.phone || item.extratags?.["contact:phone"] || null;
      let website = item.extratags?.website || item.extratags?.["contact:website"] || null;
      if (!phone && !website && item.lat && item.lon) {
        try {
          const revUrl = new URL("https://us1.locationiq.com/v1/reverse");
          revUrl.searchParams.set("key", key);
          revUrl.searchParams.set("lat", item.lat);
          revUrl.searchParams.set("lon", item.lon);
          revUrl.searchParams.set("format", "json");
          revUrl.searchParams.set("extratags", "1");
          const revR = await fetch(revUrl, { headers: { Accept: "application/json" } });
          if (revR.ok) {
            const revData = await revR.json();
            phone = revData.extratags?.phone || revData.extratags?.["contact:phone"] || null;
            website = revData.extratags?.website || revData.extratags?.["contact:website"] || null;
          }
        } catch (e) {
          /* segue sem contato pra esse item */
        }
        await sleep(550);
      }
      enriched.push({
        name: item.name || item.display_name.split(",")[0],
        address: item.display_name,
        phone,
        website,
        whatsapp: phoneToWhatsapp(phone),
      });
    }

    const withPhone = enriched.filter((r) => r.whatsapp).slice(0, 10);
    res.json({ results: withPhone });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: `Não foi possível buscar agora: ${e.message}` });
  }
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
