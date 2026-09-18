import express from "express";
import dotenv from "dotenv";
import Database from "better-sqlite3";
import crypto from "crypto";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const db = new Database("codelar.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'employee',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER,
  direction TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
`);

// Migração segura: adiciona colunas novas em bancos que já existiam antes dessas features.
const clientCols = db.prepare("PRAGMA table_info(clients)").all().map(c=>c.name);
function addColIfMissing(col,defSql){ if(!clientCols.includes(col)){ db.exec(`ALTER TABLE clients ADD COLUMN ${defSql}`); clientCols.push(col); } }
addColIfMissing("client_date","client_date TEXT");
addColIfMissing("site_type","site_type TEXT");
addColIfMissing("site_specs","site_specs TEXT");
addColIfMissing("amount_paid_cents","amount_paid_cents INTEGER NOT NULL DEFAULT 0");
addColIfMissing("finished","finished INTEGER NOT NULL DEFAULT 0");
addColIfMissing("finished_at","finished_at TEXT");

const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");

// Acesso por PIN único (uso pessoal, uma pessoa só).
// O PIN fica no .env do servidor — nunca no frontend, nunca no código versionado.
if (!process.env.DASHBOARD_PIN) {
  console.warn("Aviso: DASHBOARD_PIN não definido no .env — ninguém vai conseguir desbloquear o painel.");
}
const validTokens = new Set(); // tokens de sessão em memória (somem ao reiniciar o servidor)

app.use(express.json());
app.use(express.static("public"));

function auth(req,res,next){
  const token = req.headers["x-codelar-token"];
  if(!token || !validTokens.has(token)) return res.status(401).json({error:"Não autenticado"});
  next();
}

app.post("/api/unlock",(req,res)=>{
  const {pin}=req.body||{};
  if(!process.env.DASHBOARD_PIN || pin !== process.env.DASHBOARD_PIN){
    return res.status(401).json({error:"PIN incorreto"});
  }
  const token = crypto.randomBytes(24).toString("hex");
  validTokens.add(token);
  res.json({token});
});

app.get("/api/dashboard",auth,(req,res)=>{
  const finished=db.prepare("SELECT COUNT(*) c FROM clients WHERE finished=1").get().c;
  const totalReceived=db.prepare("SELECT COALESCE(SUM(amount_paid_cents),0) n FROM clients").get().n;
  const now=new Date();
  const monthStart=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-01`;
  const monthReceived=db.prepare("SELECT COALESCE(SUM(amount_paid_cents),0) n FROM clients WHERE COALESCE(client_date,created_at)>=?").get(monthStart).n;
  const salesMonth=db.prepare("SELECT COUNT(*) c FROM clients WHERE COALESCE(client_date,created_at)>=? AND amount_paid_cents>0").get(monthStart).c;
  res.json({finished,totalReceived,monthReceived,salesMonth});
});

app.get("/api/clients",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM clients WHERE finished=0 ORDER BY id DESC").all());
});
app.get("/api/clients/history",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM clients WHERE finished=1 ORDER BY finished_at DESC").all());
});
app.post("/api/clients",auth,(req,res)=>{
  const {name,email="",phone="",client_date=null,site_type="",site_specs="",amount_paid_cents=0}=req.body||{};
  if(!name) return res.status(400).json({error:"Nome é obrigatório"});
  const r=db.prepare(`INSERT INTO clients(name,email,phone,client_date,site_type,site_specs,amount_paid_cents) VALUES(?,?,?,?,?,?,?)`)
    .run(name,email,phone,client_date,site_type,site_specs,Number(amount_paid_cents)||0);
  res.json({id:r.lastInsertRowid});
});
app.put("/api/clients/:id/finish",auth,(req,res)=>{
  const {finished=1}=req.body||{};
  const finished_at = Number(finished)===1 ? new Date().toISOString() : null;
  db.prepare("UPDATE clients SET finished=?, finished_at=? WHERE id=?").run(Number(finished),finished_at,req.params.id);
  res.json({ok:true});
});
app.delete("/api/clients/:id",auth,(req,res)=>{
  db.prepare("DELETE FROM clients WHERE id=?").run(req.params.id);
  res.json({ok:true});
});

app.get("/api/messages",auth,(req,res)=>{
  res.json(db.prepare(`SELECT m.*, c.name client_name FROM messages m LEFT JOIN clients c ON c.id=m.client_id ORDER BY m.created_at DESC LIMIT 200`).all());
});

app.post("/api/messages",auth,(req,res)=>{
  const {client_id,body}=req.body||{};
  if(!body) return res.status(400).json({error:"Mensagem vazia"});
  const r=db.prepare("INSERT INTO messages(client_id,direction,body) VALUES(?,?,?)").run(client_id||null,"outbound",body);
  res.json({id:r.lastInsertRowid});
});

app.get("/*splat",(req,res)=>res.sendFile(process.cwd()+"/public/index.html"));
app.listen(port,()=>console.log(`Codelar OS em http://localhost:${port}`));
