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
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  progress INTEGER NOT NULL DEFAULT 0,
  price_cents INTEGER NOT NULL DEFAULT 0,
  due_date TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER,
  project_id INTEGER,
  mp_payment_id TEXT UNIQUE,
  amount_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  description TEXT,
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(client_id) REFERENCES clients(id),
  FOREIGN KEY(project_id) REFERENCES projects(id)
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
  const clients=db.prepare("SELECT COUNT(*) c FROM clients WHERE finished=0").get().c;
  const projects=db.prepare("SELECT COUNT(*) c FROM projects").get().c;
  const active=db.prepare("SELECT COUNT(*) c FROM projects WHERE status NOT IN ('completed','cancelled')").get().c;
  const received=db.prepare("SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE status='approved'").get().n;
  const pending=db.prepare("SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE status IN ('pending','in_process')").get().n;
  res.json({clients,projects,active,received,pending});
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

app.get("/api/projects",auth,(req,res)=>{
  res.json(db.prepare(`SELECT p.*, c.name client_name FROM projects p LEFT JOIN clients c ON c.id=p.client_id ORDER BY p.id DESC`).all());
});
app.post("/api/projects",auth,(req,res)=>{
  const {client_id,name,description="",status="pending",progress=0,price_cents=0,due_date=null}=req.body||{};
  if(!name) return res.status(400).json({error:"Nome do projeto é obrigatório"});
  const r=db.prepare(`INSERT INTO projects(client_id,name,description,status,progress,price_cents,due_date) VALUES(?,?,?,?,?,?,?)`)
    .run(client_id||null,name,description,status,Math.max(0,Math.min(100,Number(progress)||0)),Number(price_cents)||0,due_date);
  res.json({id:r.lastInsertRowid});
});

app.get("/api/payments",auth,(req,res)=>{
  res.json(db.prepare(`SELECT p.*, c.name client_name, pr.name project_name FROM payments p LEFT JOIN clients c ON c.id=p.client_id LEFT JOIN projects pr ON pr.id=p.project_id ORDER BY p.created_at DESC`).all());
});
app.post("/api/payments",auth,(req,res)=>{
  const {client_id,project_id=null,amount_cents,status="pending",description="",paid_at=null}=req.body||{};
  if(!client_id) return res.status(400).json({error:"Cliente é obrigatório"});
  if(!amount_cents || Number(amount_cents)<=0) return res.status(400).json({error:"Valor é obrigatório"});
  const r=db.prepare(`INSERT INTO payments(client_id,project_id,amount_cents,status,description,paid_at) VALUES(?,?,?,?,?,?)`)
    .run(Number(client_id),project_id?Number(project_id):null,Number(amount_cents),status,description,paid_at);
  res.json({id:r.lastInsertRowid});
});
app.put("/api/payments/:id",auth,(req,res)=>{
  const {status}=req.body||{};
  if(!status) return res.status(400).json({error:"Status é obrigatório"});
  const paid_at = status==="approved" ? new Date().toISOString() : null;
  db.prepare(`UPDATE payments SET status=?, paid_at=COALESCE(?,paid_at) WHERE id=?`).run(status,paid_at,req.params.id);
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
