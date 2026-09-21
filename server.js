import express from "express";
import dotenv from "dotenv";
import { createClient } from "@libsql/client";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import makeWASocket, { Browsers, DisconnectReason, useMultiFileAuthState } from "@whiskeysockets/baileys";
import pino from "pino";

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

// WhatsApp Web via pairing code (sem QR).
// O código é solicitado ao próprio WhatsApp; nunca é gerado aleatoriamente pelo frontend.
// A sessão fica em disco para reconectar depois que o processo reiniciar.
const WA_AUTH_DIR = process.env.WA_AUTH_DIR || path.resolve("./whatsapp_auth");
let waSock = null;
let waState = { status: "disconnected", phone: null, pairingCode: null, lastError: null };
let waStarting = null;
let waReadyPromise = null;
let waReadyResolve = null;
let waReadyReject = null;

function waDigits(value) { return String(value || "").replace(/\D/g, ""); }

function createWaReadyWaiter() {
  waReadyPromise = new Promise((resolve, reject) => {
    waReadyResolve = resolve;
    waReadyReject = reject;
  });
  return waReadyPromise;
}

async function startWhatsApp() {
  if (waStarting) return waStarting;
  if (waSock && waState.status !== "disconnected" && waState.status !== "logged_out") return waSock;

  waStarting = (async () => {
    fs.mkdirSync(WA_AUTH_DIR, { recursive: true });
    const { state, saveCreds } = await useMultiFileAuthState(WA_AUTH_DIR);
    waState.status = state.creds.registered ? "connecting" : "connecting";
    waState.lastError = null;
    createWaReadyWaiter();

    // Ubuntu/Chrome é uma identificação canônica para o fluxo de pairing code.
    // Não usamos um browser personalizado, pois isso pode fazer o WhatsApp rejeitar
    // o companion_hello antes de o código ser utilizável.
    const sock = makeWASocket({
      auth: state,
      browser: Browsers.ubuntu("Chrome"),
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      syncFullHistory: false,
      shouldSyncHistoryMessage: () => false,
      logger: pino({ level: "silent" }),
    });

    waSock = sock;
    sock.ev.on("creds.update", saveCreds);
    sock.ev.on("connection.update", ({ connection, qr, lastDisconnect }) => {
      if (qr && waReadyResolve) {
        // Neste ponto o socket já recebeu a referência de autenticação do WhatsApp.
        waReadyResolve();
        waReadyResolve = null;
        waReadyReject = null;
      }
      if (connection === "open") {
        waState.status = "connected";
        waState.lastError = null;
        waState.pairingCode = null;
        waState.phone = sock.user?.id?.split(":")[0] || waState.phone;
        if (waReadyResolve) {
          waReadyResolve();
          waReadyResolve = null;
          waReadyReject = null;
        }
      } else if (connection === "connecting") {
        waState.status = "connecting";
      } else if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        const msg = lastDisconnect?.error?.message || String(lastDisconnect?.error || "Conexão encerrada");
        waState.lastError = `WhatsApp encerrou a conexão (${code || "sem código"}): ${msg}`;
        if (waReadyReject) {
          waReadyReject(new Error(waState.lastError));
          waReadyResolve = null;
          waReadyReject = null;
        }
        waState.status = code === DisconnectReason.loggedOut ? "logged_out" : "disconnected";
        waSock = null;
        if (code !== DisconnectReason.loggedOut) {
          setTimeout(() => { startWhatsApp().catch(err => { waState.lastError = String(err?.message || err); }); }, 2000);
        }
      }
    });
    return sock;
  })().finally(() => { waStarting = null; });
  return waStarting;
}

app.get("/api/whatsapp/status", auth, async (req, res) => {
  try {
    await startWhatsApp();
    res.json({ ...waState, connected: waState.status === "connected" });
  } catch (e) {
    waState.lastError = String(e?.message || e);
    res.status(500).json({ ...waState, error: waState.lastError });
  }
});

app.post("/api/whatsapp/pairing-code", auth, async (req, res) => {
  try {
    const phone = waDigits(req.body?.phone);
    if (!/^55\d{10,11}$/.test(phone)) {
      return res.status(400).json({ error: "Informe o número completo com DDI 55, somente números. Ex.: 5534999999999" });
    }

    // Cada tentativa começa com uma sessão não autenticada. Isso evita reutilizar
    // um estado parcialmente pareado de uma tentativa anterior.
    if (waSock && (waState.status === "pairing" || waState.status === "connecting")) {
      return res.status(409).json({ error: "Já existe uma tentativa de vinculação em andamento. Aguarde alguns segundos ou desconecte e tente novamente." });
    }

    const sock = await startWhatsApp();
    if (waState.status === "connected") {
      return res.status(409).json({ error: "O WhatsApp já está conectado.", ...waState });
    }

    // IMPORTANTE: requestPairingCode precisa ser chamado quando o socket já estiver
    // pronto para autenticação. Em versões afetadas, chamar imediatamente após
    // makeWASocket pode produzir 428/Precondition Required/Connection Closed.
    await Promise.race([
      waReadyPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error("O WhatsApp não ficou pronto para solicitar o código. Se o painel estiver hospedado no Render/cloud, veja o aviso de rede no README.")), 20000))
    ]);

    const code = await sock.requestPairingCode(phone);
    waState.phone = phone;
    waState.pairingCode = code;
    waState.status = "pairing";
    res.json({ code, phone, status: waState.status });
  } catch (e) {
    console.error("WhatsApp pairing error:", e);
    waState.lastError = String(e?.message || e);
    res.status(500).json({
      error: "Não foi possível gerar o código de vinculação.",
      detail: waState.lastError,
      status: waState.status,
    });
  }
});

app.post("/api/whatsapp/disconnect", auth, async (req, res) => {
  try {
    if (waSock) { try { await waSock.logout(); } catch {} }
    waSock = null;
    waState = { status: "disconnected", phone: null, pairingCode: null, lastError: null };
    fs.rmSync(WA_AUTH_DIR, { recursive: true, force: true });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: "Não foi possível desconectar." }); }
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

// Prospecção: busca empresas via LocationIQ (compatível com Nominatim/OpenStreetMap).
// Precisa de uma chave gratuita em locationiq.com (5.000 buscas/dia grátis, sem cartão).
// Só retorna quem tem telefone encontrado (pra permitir o botão de WhatsApp) — é um indício
// de oportunidade baseado em dado público, não garantia de que a empresa não tem site.
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

app.get("/api/prospect", auth, async (req, res) => {
  const query = (req.query.query || "").trim();
  const state = (req.query.state || "").trim();
  const city = (req.query.city || "").trim();
  const siteFilter = (req.query.siteFilter || "any").trim(); // any | with | without
  const waFilter = (req.query.waFilter || "any").trim(); // any | confirmed | phoneOnly
  if (!query) return res.status(400).json({ error: "Informe o tipo de negócio que você quer buscar" });
  const key = process.env.LOCATIONIQ_API_KEY;
  if (!key) {
    return res.status(503).json({ error: "Busca de empresas ainda não configurada — falta a chave LOCATIONIQ_API_KEY no servidor." });
  }

  const locationParts = [city, state, "Brasil"].filter(Boolean).join(", ");
  const tag = TAG_MAP[normalizeText(query)];

  try {
    let rawResults = [];
    const seen = new Set();
    function addRaw(list) {
      for (const item of list) {
        const k = `${item.lat},${item.lon}`;
        if (!seen.has(k)) {
          seen.add(k);
          rawResults.push(item);
        }
      }
    }

    if (tag && (city || state)) {
      // Tenta geocodificar: cidade+estado primeiro, depois só estado, depois só "Brasil".
      // Cidades pequenas às vezes não são encontradas — nunca trava nisso, só degrada.
      let geo = await geocodeArea(key, locationParts);
      if (!geo && state) geo = await geocodeArea(key, `${state}, Brasil`);
      if (!geo) geo = await geocodeArea(key, "Brasil");

      if (geo) {
        const radius = city ? 20000 : state ? 80000 : 35000;
        const nearUrl = new URL("https://us1.locationiq.com/v1/nearby");
        nearUrl.searchParams.set("key", key);
        nearUrl.searchParams.set("lat", geo.lat);
        nearUrl.searchParams.set("lon", geo.lon);
        nearUrl.searchParams.set("tag", tag);
        nearUrl.searchParams.set("radius", String(radius));
        nearUrl.searchParams.set("format", "json");
        try {
          const nearR = await fetch(nearUrl, { headers: { Accept: "application/json" } });
          if (nearR.ok) addRaw(await nearR.json());
        } catch (e) {
          /* segue só com a busca por texto abaixo */
        }
      }
    }

    // Sempre soma a busca por texto livre também — combinar as duas dá mais resultados
    // do que qualquer uma sozinha (e é o único caminho quando a categoria não é reconhecida).
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
      if (r.ok) addRaw(await r.json());
    } catch (e) {
      /* segue só com o que já tiver */
    }

    // A Nearby API não devolve telefone/site direto — busca esse detalhe por item (respeitando 2 req/s do plano grátis).
    const enriched = [];
    for (const item of rawResults.slice(0, 25)) {
      let phone = item.extratags?.phone || item.extratags?.["contact:phone"] || null;
      let website = item.extratags?.website || item.extratags?.["contact:website"] || null;
      let waTag = item.extratags?.whatsapp || item.extratags?.["contact:whatsapp"] || null;
      if (!phone && !website && !waTag && item.lat && item.lon) {
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
            waTag = revData.extratags?.whatsapp || revData.extratags?.["contact:whatsapp"] || null;
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
        whatsapp: phoneToWhatsapp(phone || waTag),
        whatsappConfirmed: Boolean(waTag),
      });
    }

    let filtered = enriched.filter((r) => r.whatsapp);
    if (siteFilter === "with") filtered = filtered.filter((r) => r.website);
    if (siteFilter === "without") filtered = filtered.filter((r) => !r.website);
    if (waFilter === "confirmed") filtered = filtered.filter((r) => r.whatsappConfirmed);
    if (waFilter === "phoneOnly") filtered = filtered.filter((r) => !r.whatsappConfirmed);

    // Marca quem já foi contatado antes, pra não repetir sem querer.
    const contactedR = await db.execute("SELECT phone FROM contacted_companies");
    const contactedPhones = new Set(contactedR.rows.map((r) => r.phone));
    filtered = filtered.map((r) => ({ ...r, alreadyContacted: contactedPhones.has(r.whatsapp) }));

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
