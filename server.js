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
  const clients=db.prepare("SELECT COUNT(*) c FROM clients").get().c;
  const projects=db.prepare("SELECT COUNT(*) c FROM projects").get().c;
  const active=db.prepare("SELECT COUNT(*) c FROM projects WHERE status NOT IN ('completed','cancelled')").get().c;
  const received=db.prepare("SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE status='approved'").get().n;
  const pending=db.prepare("SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE status IN ('pending','in_process')").get().n;
  res.json({clients,projects,active,received,pending});
});

app.get("/api/clients",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM clients ORDER BY id DESC").all());
});
app.post("/api/clients",auth,(req,res)=>{
  const {name,email="",phone="",notes=""}=req.body||{};
  if(!name) return res.status(400).json({error:"Nome é obrigatório"});
  const r=db.prepare("INSERT INTO clients(name,email,phone,notes) VALUES(?,?,?,?)").run(name,email,phone,notes);
  res.json({id:r.lastInsertRowid});
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
  res.json(db.prepare(`SELECT p.*, c.name client_name FROM payments p LEFT JOIN clients c ON c.id=p.client_id ORDER BY p.created_at DESC`).all());
});

app.post("/api/messages",auth,(req,res)=>{
  const {client_id,body}=req.body||{};
  if(!body) return res.status(400).json({error:"Mensagem vazia"});
  const r=db.prepare("INSERT INTO messages(client_id,direction,body) VALUES(?,?,?)").run(client_id||null,"outbound",body);
  res.json({id:r.lastInsertRowid});
});

// Mercado Pago: leitura dos pagamentos da conta ligada ao token do servidor.
// O Access Token nunca é enviado ao navegador.
app.get("/api/mercadopago/status",auth,(req,res)=>{
  res.json({connected:Boolean(process.env.MP_ACCESS_TOKEN)});
});

app.get("/api/mercadopago/payments",auth,async(req,res)=>{
  if(!process.env.MP_ACCESS_TOKEN) return res.status(503).json({error:"Mercado Pago ainda não conectado. Configure MP_ACCESS_TOKEN no servidor."});
  try{
    const url = new URL("https://api.mercadopago.com/v1/payments/search");
    url.searchParams.set("sort","date_created");
    url.searchParams.set("criteria","desc");
    url.searchParams.set("limit","50");
    const r=await fetch(url,{headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,Accept:"application/json"}});
    const data=await r.json();
    if(!r.ok) return res.status(r.status).json({error:data});
    const items=(data.results||[]).map(p=>({
      id:String(p.id), amount_cents:Math.round((p.transaction_amount||0)*100),
      status:p.status, description:p.description||"",
      paid_at:p.date_approved||null, created_at:p.date_created||null
    }));
    res.json({results:items,paging:data.paging||{}});
  }catch(e){res.status(500).json({error:"Falha ao consultar Mercado Pago"});}
});

// Webhook: atualiza/insere pagamento quando o Mercado Pago notificar um payment.
// A validação completa da assinatura deve ser configurada com o segredo da aplicação.
app.post("/api/webhooks/mercadopago",async(req,res)=>{
  const type=req.query.type || req.body?.type;
  const id=req.query["data.id"] || req.body?.data?.id;
  if(type !== "payment" || !id) return res.sendStatus(200);
  if(!process.env.MP_ACCESS_TOKEN) return res.sendStatus(200);
  try{
    const r=await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(id)}`,{
      headers:{Authorization:`Bearer ${process.env.MP_ACCESS_TOKEN}`,Accept:"application/json"}
    });
    if(!r.ok) return res.sendStatus(200);
    const p=await r.json();
    const cents=Math.round((p.transaction_amount||0)*100);
    db.prepare(`
      INSERT INTO payments(mp_payment_id,amount_cents,status,description,paid_at)
      VALUES(?,?,?,?,?)
      ON CONFLICT(mp_payment_id) DO UPDATE SET
        amount_cents=excluded.amount_cents,status=excluded.status,
        description=excluded.description,paid_at=excluded.paid_at
    `).run(String(p.id),cents,p.status,p.description||"",p.date_approved||null);
    res.sendStatus(200);
  }catch(e){res.sendStatus(200);}
});

app.get("/*splat",(req,res)=>res.sendFile(process.cwd()+"/public/index.html"));
app.listen(port,()=>console.log(`Codelar OS em http://localhost:${port}`));
