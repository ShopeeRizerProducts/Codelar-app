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
      `CREATE TABLE IF NOT EXISTS contacted_companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT,
        phone TEXT UNIQUE NOT NULL,
        website TEXT,
        contacted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

// Prospecção: usa Overpass (OpenStreetMap) pra achar TODAS as empresas de uma categoria numa
// região de uma vez só, já com telefone/site nas próprias tags — muito mais rápido e confiável
// que buscar item por item. Complementa com busca por texto livre (LocationIQ) quando a
// categoria não é reconhecida, ou pra somar mais resultados.
const OSM_TAG_MAP = {
  padaria: ["shop", "bakery"], panificadora: ["shop", "bakery"],
  restaurante: ["amenity", "restaurant"], pizzaria: ["amenity", "restaurant"],
  lanchonete: ["amenity", "fast_food"],
  academia: ["leisure", "fitness_centre"],
  farmacia: ["amenity", "pharmacy"],
  salao: ["shop", "hairdresser"], "salao de beleza": ["shop", "hairdresser"], barbearia: ["shop", "hairdresser"],
  clinica: ["amenity", "clinic"], dentista: ["amenity", "dentist"], "clinica odontologica": ["amenity", "dentist"],
  advocacia: ["office", "lawyer"], advogado: ["office", "lawyer"],
  contabilidade: ["office", "accountant"], contador: ["office", "accountant"],
  petshop: ["shop", "pet"], "pet shop": ["shop", "pet"],
  oficina: ["shop", "car_repair"], mecanica: ["shop", "car_repair"], "oficina mecanica": ["shop", "car_repair"],
  mercado: ["shop", "supermarket"], supermercado: ["shop", "supermarket"], mercearia: ["shop", "convenience"],
  hotel: ["tourism", "hotel"], pousada: ["tourism", "guest_house"],
  livraria: ["shop", "books"], papelaria: ["shop", "stationery"],
  floricultura: ["shop", "florist"], joalheria: ["shop", "jewelry"],
  otica: ["shop", "optician"], imobiliaria: ["office", "estate_agent"],
  "loja de roupas": ["shop", "clothes"], boutique: ["shop", "clothes"],
  cafe: ["amenity", "cafe"], cafeteria: ["amenity", "cafe"],
};

async function geocodeArea(key, q) {
  const geoUrl = new URL("https://us1.locationiq.com/v1/search");
  geoUrl.searchParams.set("key", key);
  geoUrl.searchParams.set("q", q);
  geoUrl.searchParams.set("format", "json");
  geoUrl.searchParams.set("limit", "1");
  const geoR = await fetch(geoUrl, { headers: { Accept: "application/json" } });
  if (!geoR.ok) return null;
  const geoData = await geoR.json();
  if (!geoData.length) return null;
  return { lat: geoData[0].lat, lon: geoData[0].lon };
}

function addressFromTags(tags) {
  const parts = [tags["addr:street"], tags["addr:housenumber"], tags["addr:suburb"], tags["addr:city"]].filter(Boolean);
  return parts.length ? parts.join(", ") : null;
}

async function queryOverpass(lat, lon, osmKey, osmValue, radius) {
  const query = `[out:json][timeout:25];(node["${osmKey}"="${osmValue}"](around:${radius},${lat},${lon});way["${osmKey}"="${osmValue}"](around:${radius},${lat},${lon}););out center tags qt;`;
  try {
    const r = await fetch("https://overpass-api.de/api/interpreter", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "data=" + encodeURIComponent(query),
    });
    if (!r.ok) return [];
    const data = await r.json();
    return (data.elements || []).map((el) => {
      const tags = el.tags || {};
      return {
        name: tags.name || null,
        address: addressFromTags(tags),
        phone: tags.phone || tags["contact:phone"] || null,
        website: tags.website || tags["contact:website"] || null,
        whatsappTag: tags.whatsapp || tags["contact:whatsapp"] || null,
      };
    }).filter((it) => it.name);
  } catch (e) {
    return [];
  }
}

app.get("/api/prospect", auth, async (req, res) => {
  const query = (req.query.query || "").trim();
  const state = (req.query.state || "").trim();
  const city = (req.query.city || "").trim();
  const siteFilter = (req.query.siteFilter || "any").trim(); // any | with | without
  const waFilter = (req.query.waFilter || "any").trim(); // any | confirmed | phoneOnly
  const excludeContacted = req.query.excludeContacted === "1";
  if (!query) return res.status(400).json({ error: "Informe o tipo de negócio que você quer buscar" });
  const key = process.env.LOCATIONIQ_API_KEY;
  if (!key) {
    return res.status(503).json({ error: "Busca de empresas ainda não configurada — falta a chave LOCATIONIQ_API_KEY no servidor." });
  }

  const locationParts = [city, state, "Brasil"].filter(Boolean).join(", ");
  const osmTag = OSM_TAG_MAP[normalizeText(query)];

  try {
    let combined = [];

    if (osmTag) {
      let geo = await geocodeArea(key, locationParts || "Brasil");
      if (!geo && state) geo = await geocodeArea(key, `${state}, Brasil`);
      if (!geo) geo = await geocodeArea(key, "Brasil");

      if (geo) {
        let radius = city ? 25000 : state ? 90000 : 40000;
        let overpassResults = await queryOverpass(geo.lat, geo.lon, osmTag[0], osmTag[1], radius);
        if (overpassResults.length < 12) {
          radius = Math.min(radius * 3, 200000);
          overpassResults = await queryOverpass(geo.lat, geo.lon, osmTag[0], osmTag[1], radius);
        }
        combined.push(
          ...overpassResults.map((it) => ({
            name: it.name,
            address: it.address || locationParts,
            phone: it.phone,
            website: it.website,
            whatsapp: phoneToWhatsapp(it.phone || it.whatsappTag),
            whatsappConfirmed: Boolean(it.whatsappTag),
          }))
        );
      }
    }

    // Sempre soma busca por texto livre (LocationIQ já devolve telefone/site direto, sem chamada extra).
    const q = locationParts ? `${query} em ${locationParts}` : `${query}, Brasil`;
    const url = new URL("https://us1.locationiq.com/v1/search");
    url.searchParams.set("key", key);
    url.searchParams.set("q", q);
    url.searchParams.set("format", "json");
    url.searchParams.set("addressdetails", "1");
    url.searchParams.set("extratags", "1");
    url.searchParams.set("limit", "20");
    try {
      const r = await fetch(url, { headers: { Accept: "application/json" } });
      if (r.ok) {
        const data = await r.json();
        combined.push(
          ...data.map((item) => {
            const phone = item.extratags?.phone || item.extratags?.["contact:phone"] || null;
            const waTag = item.extratags?.whatsapp || item.extratags?.["contact:whatsapp"] || null;
            return {
              name: item.name || item.display_name.split(",")[0],
              address: item.display_name,
              phone,
              website: item.extratags?.website || item.extratags?.["contact:website"] || null,
              whatsapp: phoneToWhatsapp(phone || waTag),
              whatsappConfirmed: Boolean(waTag),
            };
          })
        );
      }
    } catch (e) {
      /* segue só com o que já tiver */
    }

    // Remove duplicados (mesmo telefone, ou mesmo nome quando não tem telefone).
    const seen = new Set();
    let enriched = combined.filter((r) => {
      const k = r.whatsapp || `${normalizeText(r.name)}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

    let filtered = enriched.filter((r) => r.whatsapp);
    if (siteFilter === "with") filtered = filtered.filter((r) => r.website);
    if (siteFilter === "without") filtered = filtered.filter((r) => !r.website);
    if (waFilter === "confirmed") filtered = filtered.filter((r) => r.whatsappConfirmed);
    if (waFilter === "phoneOnly") filtered = filtered.filter((r) => !r.whatsappConfirmed);

    const contactedR = await db.execute("SELECT phone FROM contacted_companies");
    const contactedPhones = new Set(contactedR.rows.map((r) => r.phone));
    filtered = filtered.map((r) => ({ ...r, alreadyContacted: contactedPhones.has(r.whatsapp) }));
    if (excludeContacted) filtered = filtered.filter((r) => !r.alreadyContacted);

    res.json({ results: filtered.slice(0, 10) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: `Não foi possível buscar agora: ${e.message}` });
  }
});

app.get("/api/prospect/contacted", auth, async (req, res) => {
  const r = await db.execute("SELECT * FROM contacted_companies ORDER BY contacted_at DESC");
  res.json(r.rows);
});
app.post("/api/prospect/contact", auth, async (req, res) => {
  const { name, address = "", phone, website = "" } = req.body || {};
  if (!name || !phone) return res.status(400).json({ error: "Nome e telefone são obrigatórios" });
  await db.execute({
    sql: `INSERT INTO contacted_companies(name,address,phone,website,contacted_at) VALUES(?,?,?,?,?)
          ON CONFLICT(phone) DO UPDATE SET contacted_at=excluded.contacted_at`,
    args: [name, address, phone, website, new Date().toISOString()],
  });
  res.json({ ok: true });
});
app.delete("/api/prospect/contacted/:id", auth, async (req, res) => {
  await db.execute({ sql: "DELETE FROM contacted_companies WHERE id=?", args: [req.params.id] });
  res.json({ ok: true });
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
