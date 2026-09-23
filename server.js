import express from "express";
import dotenv from "dotenv";
import { createClient } from "@libsql/client";
import crypto from "crypto";
import makeWASocket, { Browsers, DisconnectReason, useMultiFileAuthState } from "@whiskeysockets/baileys";
import pino from "pino";
import fs from "fs/promises";
import path from "path";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const WA_AUTH_DIR = process.env.WA_AUTH_DIR || path.join(process.cwd(), "wa_auth");
const WA_DAILY_LIMIT = 25;
const WA_MIN_INTERVAL_MS = 60_000;
let waSock = null;
let waStatus = { state: "disconnected", phone: null, message: "WhatsApp não conectado." };
let waReadyPromise = null;
let waLastSentAt = 0;

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
      `CREATE TABLE IF NOT EXISTS wa_contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE NOT NULL,
        name TEXT,
        opted_in INTEGER NOT NULL DEFAULT 0,
        blocked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS wa_send_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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


function cleanWaNumber(raw) {
  const digits = String(raw || "").replace(/\D/g, "");
  if (!digits) return null;
  if (digits.startsWith("55") && digits.length >= 12) return digits;
  if (digits.length === 10 || digits.length === 11) return "55" + digits;
  return digits.length >= 12 ? digits : null;
}
function waJid(phone) { return `${phone}@s.whatsapp.net`; }
function todayStartIso() {
  const d = new Date();
  d.setHours(0,0,0,0);
  return d.toISOString();
}
async function waDailyCount() {
  const r = await db.execute({sql:"SELECT COUNT(*) c FROM wa_send_log WHERE status='sent' AND sent_at>=?",args:[todayStartIso()]});
  return Number(r.rows[0]?.c || 0);
}
async function setWaStatus(state, message, phone=null) {
  waStatus = { state, phone: phone || waStatus.phone || null, message };
}
async function connectWhatsApp() {
  await fs.mkdir(WA_AUTH_DIR, { recursive: true });
  const { state, saveCreds } = await useMultiFileAuthState(WA_AUTH_DIR);
  waReadyPromise = null;
  const logger = pino({ level: "silent" });
  const sock = makeWASocket({
    auth: state,
    logger,
    browser: Browsers.ubuntu("Chrome"),
    syncFullHistory: false,
    shouldSyncHistoryMessage: () => false,
    markOnlineOnConnect: false,
  });
  waSock = sock;
  sock.ev.on("creds.update", saveCreds);
  waReadyPromise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      sock.ev.off("connection.update", handler);
      reject(new Error("O WhatsApp não iniciou a conexão a tempo."));
    }, 15_000);
    const handler = ({ connection, qr }) => {
      // Para código de pareamento, o socket precisa ter começado a conectar.
      // Esperar por esse evento evita chamar requestPairingCode cedo demais.
      if (connection === "connecting" || qr) {
        clearTimeout(timer);
        setWaStatus("pairing_ready", "WhatsApp pronto para solicitar o código de pareamento.").catch(()=>{});
        sock.ev.off("connection.update", handler);
        resolve(true);
      } else if (connection === "open") {
        clearTimeout(timer);
        setWaStatus("connected", "WhatsApp conectado.", sock.user?.id?.split(":")[0]).catch(()=>{});
        sock.ev.off("connection.update", handler);
        resolve(true);
      }
    };
    sock.ev.on("connection.update", handler);
  });
  sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
    if (connection === "open") {
      await setWaStatus("connected", "WhatsApp conectado.", sock.user?.id?.split(":")[0]);
    } else if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      waSock = null;
      if (code === DisconnectReason.loggedOut) {
        await fs.rm(WA_AUTH_DIR, { recursive: true, force: true }).catch(()=>{});
        await setWaStatus("logged_out", "WhatsApp desconectado. Faça o pareamento novamente.", null);
      } else {
        await setWaStatus("disconnected", `Conexão encerrada${code ? ` (${code})` : ""}.`, null);
      }
    }
  });
  return sock;
}

app.get("/api/wa/status", auth, async (req, res) => {
  res.json({ ...waStatus, dailySent: await waDailyCount(), dailyLimit: WA_DAILY_LIMIT, nextSendInMs: Math.max(0, WA_MIN_INTERVAL_MS - (Date.now()-waLastSentAt)) });
});
app.post("/api/wa/pairing-code", auth, async (req, res) => {
  const phone = cleanWaNumber(req.body?.phone);
  if (!phone) return res.status(400).json({error:"Informe o número com DDD e código do país. Ex.: 5534999999999"});
  try {
    if (waSock?.user) return res.status(409).json({error:"Já existe um WhatsApp conectado. Desconecte antes de parear outro número."});
    const sock = waSock || await connectWhatsApp();
    await waReadyPromise;
    if (sock.authState?.creds?.registered) return res.status(409).json({error:"Esta sessão já está autenticada. Desconecte antes de parear outro número."});
    const code = await Promise.race([
      sock.requestPairingCode(phone),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Tempo esgotado ao solicitar o código ao WhatsApp.")), 15_000))
    ]);
    await setWaStatus("pairing_code", "Código gerado. Digite no WhatsApp em Aparelhos conectados.", phone);
    res.json({ ok:true, code, phone });
  } catch (e) {
    await setWaStatus("error", e?.message || "Não foi possível gerar o código.");
    res.status(500).json({error:"Não foi possível gerar o código de pareamento. Verifique o número e tente novamente.", detail:e?.message || ""});
  }
});
app.post("/api/wa/disconnect", auth, async (req, res) => {
  try { if (waSock) await waSock.logout(); } catch {}
  waSock = null;
  await fs.rm(WA_AUTH_DIR, { recursive:true, force:true }).catch(()=>{});
  await setWaStatus("disconnected", "WhatsApp desconectado.", null);
  res.json({ok:true});
});
app.get("/api/wa/contacts", auth, async (req,res) => {
  const r = await db.execute("SELECT * FROM wa_contacts ORDER BY id DESC");
  res.json(r.rows);
});
app.post("/api/wa/contacts", auth, async (req,res) => {
  const phone=cleanWaNumber(req.body?.phone); const name=String(req.body?.name||"").trim();
  if(!phone) return res.status(400).json({error:"Número inválido"});
  await db.execute({sql:"INSERT INTO wa_contacts(phone,name,opted_in,blocked) VALUES(?,?,?,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name,opted_in=excluded.opted_in,blocked=excluded.blocked",args:[phone,name,req.body?.opted_in?1:0,req.body?.blocked?1:0]});
  res.json({ok:true,phone});
});
app.post("/api/wa/send", auth, async (req,res) => {
  const phone=cleanWaNumber(req.body?.phone); const message=String(req.body?.message||"").trim();
  if(!phone || !message) return res.status(400).json({error:"Número e mensagem são obrigatórios."});
  const c=await db.execute({sql:"SELECT * FROM wa_contacts WHERE phone=?",args:[phone]});
  const contact=c.rows[0];
  if(!contact) return res.status(400).json({error:"Adicione o número à lista e confirme que ele tem autorização para receber mensagens antes de enviar."});
  if(Number(contact.blocked)===1) return res.status(400).json({error:"Este número está bloqueado e não pode receber mensagens."});
  if(Number(contact.opted_in)!==1) return res.status(400).json({error:"Este contato não está marcado como autorizado para receber mensagens."});
  const count=await waDailyCount();
  if(count>=WA_DAILY_LIMIT) return res.status(429).json({error:"Limite diário de 25 mensagens atingido."});
  const wait=WA_MIN_INTERVAL_MS-(Date.now()-waLastSentAt);
  if(wait>0) return res.status(429).json({error:`Aguarde ${Math.ceil(wait/1000)}s antes do próximo envio.`});
  if(!waSock?.user) return res.status(409).json({error:"WhatsApp não está conectado."});
  try {
    const check=await waSock.onWhatsApp(phone);
    if(!check?.[0]?.exists) return res.status(400).json({error:"Esse número não foi confirmado como uma conta do WhatsApp."});
    await waSock.sendMessage(waJid(phone), {text:message});
    waLastSentAt=Date.now();
    await db.execute({sql:"INSERT INTO wa_send_log(phone,message,status) VALUES(?,?,?)",args:[phone,message,"sent"]});
    res.json({ok:true,real:true,phone});
  } catch(e) {
    await db.execute({sql:"INSERT INTO wa_send_log(phone,message,status,error) VALUES(?,?,?,?)",args:[phone,message,"error",e?.message||"Erro"]}).catch(()=>{});
    res.status(500).json({error:"Falha no envio real do WhatsApp. Nenhum retry automático foi feito.",detail:e?.message||""});
  }
});

app.post("/api/wa/batch", auth, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  const rawNumbers = Array.isArray(req.body?.phones) ? req.body.phones : [];
  const intervalSec = Math.max(60, Math.min(3600, Number(req.body?.intervalSec || 60)));
  if (!message) return res.status(400).json({error:"Digite a mensagem."});
  const phones = [...new Set(rawNumbers.map(cleanWaNumber).filter(Boolean))];
  if (!phones.length) return res.status(400).json({error:"Adicione pelo menos um número."});
  if (phones.length > WA_DAILY_LIMIT) return res.status(400).json({error:`A fila não pode ter mais de ${WA_DAILY_LIMIT} números.`});
  if (!waSock?.user) return res.status(409).json({error:"WhatsApp não está conectado."});

  const authorized = await db.execute({
    sql:`SELECT phone, blocked, opted_in FROM wa_contacts WHERE phone IN (${phones.map(()=>'?').join(',')})`,
    args:phones
  });
  const map = new Map(authorized.rows.map(r => [r.phone, r]));
  const invalid = phones.filter(p => !map.has(p) || Number(map.get(p).blocked) === 1 || Number(map.get(p).opted_in) !== 1);
  if (invalid.length) return res.status(400).json({error:"Todos os números precisam estar cadastrados e autorizados para receber mensagens.", invalid});

  let sent = 0;
  const results = [];
  for (const phone of phones) {
    const count = await waDailyCount();
    if (count >= WA_DAILY_LIMIT) { results.push({phone, status:"skipped", error:"Limite diário atingido"}); break; }
    const wait = WA_MIN_INTERVAL_MS - (Date.now() - waLastSentAt);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    try {
      const check = await waSock.onWhatsApp(phone);
      if (!check?.[0]?.exists) { results.push({phone, status:"error", error:"Número não confirmado como conta do WhatsApp"}); continue; }
      await waSock.sendMessage(waJid(phone), {text:message});
      waLastSentAt = Date.now();
      await db.execute({sql:"INSERT INTO wa_send_log(phone,message,status) VALUES(?,?,?)",args:[phone,message,"sent"]});
      sent++; results.push({phone, status:"sent"});
    } catch (e) {
      await db.execute({sql:"INSERT INTO wa_send_log(phone,message,status,error) VALUES(?,?,?,?)",args:[phone,message,"error",e?.message||"Erro"]}).catch(()=>{});
      results.push({phone, status:"error", error:e?.message||"Erro no envio"});
    }
    // Intervalo escolhido pelo usuário, com mínimo obrigatório de 60 segundos.
    if (sent < phones.length) await new Promise(r => setTimeout(r, intervalSec * 1000));
  }
  res.json({ok:true, sent, results, intervalSec});
});

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
  try {
    const geoR = await fetch(geoUrl, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(8000) });
    if (!geoR.ok) return null;
    const geoData = await geoR.json();
    if (!geoData.length) return null;
    const it = geoData[0];
    // boundingbox do Nominatim/LocationIQ vem como [south, north, west, east] (strings).
    const bbox = Array.isArray(it.boundingbox) && it.boundingbox.length === 4
      ? it.boundingbox.map(Number)
      : null;
    return { lat: it.lat, lon: it.lon, bbox };
  } catch (e) {
    console.error("geocodeArea falhou:", e.message);
    return null;
  }
}

function addressFromTags(tags) {
  const parts = [tags["addr:street"], tags["addr:housenumber"], tags["addr:suburb"], tags["addr:city"]].filter(Boolean);
  return parts.length ? parts.join(", ") : null;
}

// Busca dentro da área real (o retângulo que cobre a cidade/estado/país inteiro), não só
// num raio ao redor de um ponto — assim cobre o lugar todo de verdade.
async function queryOverpass(bbox, osmKey, osmValue) {
  const [south, north, west, east] = bbox;
  const box = `${south},${west},${north},${east}`;
  const query = `[out:json][timeout:25];(node["${osmKey}"="${osmValue}"](${box});way["${osmKey}"="${osmValue}"](${box}););out center tags qt;`;
  try {
    const r = await fetch("https://overpass-api.de/api/interpreter", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "data=" + encodeURIComponent(query),
      signal: AbortSignal.timeout(22000),
    });
    if (!r.ok) {
      console.error("Overpass respondeu status", r.status, (await r.text()).slice(0, 200));
      return [];
    }
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
    console.error("queryOverpass falhou:", e.message);
    return [];
  }
}

async function textSearchLocationIQ(key, q) {
  const url = new URL("https://us1.locationiq.com/v1/search");
  url.searchParams.set("key", key);
  url.searchParams.set("q", q);
  url.searchParams.set("format", "json");
  url.searchParams.set("addressdetails", "1");
  url.searchParams.set("extratags", "1");
  url.searchParams.set("limit", "20");
  try {
    const r = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) {
      console.error("LocationIQ search respondeu status", r.status);
      return [];
    }
    const data = await r.json();
    return data.map((item) => {
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
    });
  } catch (e) {
    console.error("textSearchLocationIQ falhou:", e.message);
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
  const q = locationParts ? `${query} em ${locationParts}` : `${query}, Brasil`;

  try {
    const [overpassResults, textResults] = await Promise.all([
      (async () => {
        if (!osmTag) return [];
        let geo = await geocodeArea(key, locationParts || "Brasil");
        if (!geo && state) geo = await geocodeArea(key, `${state}, Brasil`);
        if (!geo) geo = await geocodeArea(key, "Brasil");
        if (!geo) return [];
        let bbox = geo.bbox;
        if (!bbox) {
          // Caso raro sem contorno disponível: aproxima com ~50km ao redor do ponto.
          const d = 0.45;
          bbox = [Number(geo.lat) - d, Number(geo.lat) + d, Number(geo.lon) - d, Number(geo.lon) + d];
        }
        // Alarga um pouco a borda, pra pegar empresas bem na divisa que o contorno exato deixaria de fora.
        const [south, north, west, east] = bbox;
        const latPad = (north - south) * 0.15;
        const lonPad = (east - west) * 0.15;
        const paddedBbox = [south - latPad, north + latPad, west - lonPad, east + lonPad];
        const results = await queryOverpass(paddedBbox, osmTag[0], osmTag[1]);
        return results.map((it) => ({
          name: it.name,
          address: it.address || locationParts,
          phone: it.phone,
          website: it.website,
          whatsapp: phoneToWhatsapp(it.phone || it.whatsappTag),
          whatsappConfirmed: Boolean(it.whatsappTag),
        }));
      })(),
      textSearchLocationIQ(key, q),
    ]);

    const combined = [...overpassResults, ...textResults];

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
