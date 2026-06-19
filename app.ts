/**
 * Modern OWASP Top-50 Vulnerable Full-Stack Lab - Single File
 * Deliberately vulnerable local training app. Do not deploy.
 * Stack: Node.js + TypeScript + Express + SQLite + Supabase-style auth/RLS/storage mistakes.
 * Run: npm install && npm start
 */

import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import sqlite3 from "sqlite3";
import axios from "axios";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import child_process from "child_process";

const app = express();
const port = 3000;
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

const JWT_SECRET = "dev-secret"; // V01 hardcoded weak secret
const SUPABASE_URL = "https://example-project.supabase.co";
const SUPABASE_ANON_KEY = "public-anon-key-placeholder";
const SUPABASE_SERVICE_ROLE_KEY = "service-role-key-placeholder-never-ship"; // V18 exposed service role
const ADMIN_API_KEY = "admin-api-key-123";

type Role = "admin" | "user" | "auditor";
const users = [
  { id: 1, username: "admin", password: "admin123", role: "admin" as Role, email: "admin@lab.local", apiKey: "adm-secret-001", tenantId: "tenant-a" },
  { id: 2, username: "alice", password: "password", role: "user" as Role, email: "alice@lab.local", apiKey: "alice-secret-002", tenantId: "tenant-a" },
  { id: 3, username: "bob", password: "password", role: "user" as Role, email: "bob@lab.local", apiKey: "bob-secret-003", tenantId: "tenant-b" },
];
const comments: string[] = [];
const auditLog: string[] = [];
const resetTokens: Record<string, string> = {};
const upload = multer({ dest: "uploads/" });
fs.mkdirSync("uploads", { recursive: true });

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER, tenant_id TEXT)");
  db.run("INSERT INTO products (name, price, tenant_id) VALUES ('Laptop', 1000, 'tenant-a')");
  db.run("INSERT INTO products (name, price, tenant_id) VALUES ('Phone', 700, 'tenant-a')");
  db.run("INSERT INTO products (name, price, tenant_id) VALUES ('Server', 5000, 'tenant-b')");
  db.run("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT)");
  db.run("INSERT INTO notes (owner_id, body) VALUES (1, 'Admin private note')");
  db.run("INSERT INTO notes (owner_id, body) VALUES (2, 'Alice private note')");
  db.run("INSERT INTO notes (owner_id, body) VALUES (3, 'Bob private note')");
});

function html(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1>${body}<hr><a href="/">Home</a></body></html>`;
}
function currentUser(req: Request) {
  const found = users.find(u => u.username === req.cookies.username);
  if (!found) return null;
  return { ...found, role: (req.cookies.role || found.role) as Role }; // V15 trusts role cookie
}
function needLogin(req: Request, res: Response) {
  const u = currentUser(req); if (!u) { res.status(401).send("Login required"); return null; } return u;
}
function md5(x: string) { return crypto.createHash("md5").update(x).digest("hex"); }

app.get("/", (req, res) => {
  const u = currentUser(req);
  res.send(html("Modern OWASP Top-50 Vulnerable Lab", `
    <p><b>Deliberately vulnerable.</b> Local lab only.</p>
    <p>User: ${u ? `${u.username} / ${u.role} / ${u.tenantId}` : "not logged in"}</p>
    <p><a href="/v07-login?username=alice&password=password">Login alice</a> | <a href="/v07-login?username=admin&password=admin123">Login admin</a> | <a href="/logout">Logout</a></p>
    <ol>${Array.from({length:50},(_,i)=>`<li><a href="/v${String(i+1).padStart(2,"0")}">V${String(i+1).padStart(2,"0")}</a></li>`).join("")}</ol>
    <h3>Examples</h3>
    <ul><li><a href="/v08-reflected-xss?q=%3Cscript%3Ealert(1)%3C/script%3E">XSS</a></li><li><a href="/v10-sqli?q=%27%20OR%20%271%27%3D%271">SQLi</a></li><li><a href="/v14-profile?id=1">IDOR</a></li><li><a href="/v15-admin">RBAC bypass</a></li><li><a href="/v23-fetch?url=http://127.0.0.1:3000/v25-debug">SSRF demo</a></li></ul>`));
});

app.get("/v01",(_,res)=>res.redirect("/v01-hardcoded-secrets"));
app.get("/v01-hardcoded-secrets",(_,res)=>res.send(html("V01 Hardcoded Secrets",`<pre>JWT_SECRET=${JWT_SECRET}\nADMIN_API_KEY=${ADMIN_API_KEY}\nSUPABASE_SERVICE_ROLE_KEY=${SUPABASE_SERVICE_ROLE_KEY}</pre>`)));
app.get("/v02",(_,res)=>res.redirect("/v02-env-leak"));
app.get("/v02-env-leak",(_,res)=>res.json({env:process.env,supabaseUrl:SUPABASE_URL,anonKey:SUPABASE_ANON_KEY}));
app.get("/v03",(req,res)=>res.redirect(`/v03-weak-hash?value=${encodeURIComponent(String(req.query.value||"password"))}`));
app.get("/v03-weak-hash",(req,res)=>{const v=String(req.query.value||"password");res.send(html("V03 Weak Hashing",`<p>MD5(${v})=${md5(v)}</p>`));});
app.get("/v04",(_,res)=>res.redirect("/v04-cors"));
app.get("/v04-cors",(_,res)=>{res.setHeader("Access-Control-Allow-Origin","*");res.setHeader("Access-Control-Allow-Credentials","true");res.json({message:"Permissive CORS"});});
app.get("/v05",(_,res)=>res.redirect("/v05-clickjacking"));
app.get("/v05-clickjacking",(_,res)=>res.send(html("V05 Clickjacking",`<button>Transfer Funds</button><p>No frame protection.</p>`)));
app.get("/v06",(_,res)=>res.redirect("/v06-open-redirect?next=https://example.com"));
app.get("/v06-open-redirect",(req,res)=>res.redirect(String(req.query.next||"/")));

app.get("/v07",(_,res)=>res.redirect("/v07-login?username=alice&password=password"));
app.get("/v07-login",(req,res)=>{const u=users.find(x=>x.username===req.query.username&&x.password===req.query.password);if(!u)return res.status(401).send("Login failed");res.cookie("username",u.username,{httpOnly:false});res.cookie("role",u.role,{httpOnly:false});res.redirect("/");});
app.get("/logout",(_,res)=>{res.clearCookie("username");res.clearCookie("role");res.redirect("/");});
app.get("/v08",(_,res)=>res.redirect("/v08-reflected-xss?q=%3Cscript%3Ealert(1)%3C/script%3E"));
app.get("/v08-reflected-xss",(req,res)=>res.send(html("V08 Reflected XSS",`<p>Search: ${String(req.query.q||"")}</p>`)));
app.get("/v09",(_,res)=>res.redirect("/v09-stored-xss"));
app.all("/v09-stored-xss",(req,res)=>{if(req.method==="POST")comments.push(String(req.body.comment||""));res.send(html("V09 Stored XSS",`<form method="POST"><input name="comment" placeholder="<script>alert(1)</script>"><button>Post</button></form><ul>${comments.map(c=>`<li>${c}</li>`).join("")}</ul>`));});
app.get("/v10",(_,res)=>res.redirect("/v10-sqli?q=Laptop"));
app.get("/v10-sqli",(req,res)=>{const q=String(req.query.q||"");const sql=`SELECT id,name,price,tenant_id FROM products WHERE name LIKE '%${q}%'`;db.all(sql,(err,rows)=>res.send(html("V10 SQL Injection",`<p><code>${sql}</code></p><pre>${err?err.message:JSON.stringify(rows,null,2)}</pre>`)));});
app.get("/v11",(_,res)=>res.redirect("/v11-nosql-injection?role=admin"));
app.get("/v11-nosql-injection",(req,res)=>res.json({query:req.query,matched:users.filter(u=>!req.query.role||u.role===req.query.role)}));
app.get("/v12",(_,res)=>res.redirect("/v12-template-injection?name={{7*7}}"));
app.get("/v12-template-injection",(req,res)=>{let tpl=`<h2>Hello ${String(req.query.name||"guest")}</h2>`;tpl=tpl.replace(/\{\{7\*7\}\}/g,"49");res.send(html("V12 Template Injection",tpl));});

app.get("/v13",(_,res)=>res.redirect("/v13-jwt-weak"));
app.get("/v13-jwt-weak",(_,res)=>res.json({token:jwt.sign({sub:"2",role:"admin"},JWT_SECRET,{expiresIn:"7d"}),note:"Weak shared secret"}));
app.get("/v14",(_,res)=>res.redirect("/v14-profile?id=1"));
app.get("/v14-profile",(req,res)=>{const u=users.find(x=>x.id===Number(req.query.id||1));if(!u)return res.status(404).send("not found");res.json(u);});
app.get("/v15",(_,res)=>res.redirect("/v15-admin"));
app.get("/v15-admin",(req,res)=>{const u=needLogin(req,res);if(!u)return;if(u.role!=="admin")return res.status(403).send("Forbidden. Hint: role cookie is trusted.");res.send(html("V15 RBAC Bypass",`<p>Admin panel reached as ${u.username}</p>`));});
app.get("/v16",(_,res)=>res.redirect("/v16-tenant-data?tenantId=tenant-b"));
app.get("/v16-tenant-data",(req,res)=>db.all(`SELECT * FROM products WHERE tenant_id='${String(req.query.tenantId||"tenant-a")}'`,(err,rows)=>res.json({err,rows})));
app.get("/v17",(_,res)=>res.redirect("/v17-supabase-rls-bypass?user_id=1"));
app.get("/v17-supabase-rls-bypass",(req,res)=>db.all(`SELECT * FROM notes WHERE owner_id=${Number(req.query.user_id||1)}`,(err,rows)=>res.json({note:"Simulates missing Supabase RLS / trusted client user_id",err,rows})));
app.get("/v18",(_,res)=>res.redirect("/v18-supabase-service-role-leak"));
app.get("/v18-supabase-service-role-leak",(_,res)=>res.json({SUPABASE_URL,SUPABASE_ANON_KEY,SUPABASE_SERVICE_ROLE_KEY}));
app.get("/v19",(_,res)=>res.redirect("/v19-mass-assignment"));
app.post("/v19-mass-assignment",(req,res)=>{const nu:any={id:users.length+1,username:"new",password:"new",role:"user",email:"",apiKey:"new",tenantId:"tenant-a",...req.body};users.push(nu);res.json(nu);});
app.get("/v19-mass-assignment",(_,res)=>res.send(html("V19 Mass Assignment",`<form method="POST"><input name="username" value="mallory"><input name="role" value="admin"><button>Create</button></form>`)));
app.get("/v20",(_,res)=>res.redirect("/v20-graphql-overfetch"));
app.get("/v20-graphql-overfetch",(_,res)=>res.json({data:users}));

app.get("/v21",(_,res)=>res.redirect("/v21-upload"));
app.post("/v21-upload",upload.single("file"),(req,res)=>res.json({uploaded:req.file}));
app.get("/v21-upload",(_,res)=>res.send(html("V21 Insecure Upload",`<form method="POST" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form>`)));
app.get("/v22",(_,res)=>res.redirect("/v22-path-traversal?file=app.ts"));
app.get("/v22-path-traversal",(req,res)=>{const file=String(req.query.file||"app.ts");fs.readFile(path.join(process.cwd(),file),"utf8",(err,data)=>err?res.status(404).send(err.message):res.type("text/plain").send(data.slice(0,5000)));});
app.get("/v23",(_,res)=>res.redirect("/v23-fetch?url=http://127.0.0.1:3000/v25-debug"));
app.get("/v23-fetch",async(req,res)=>{try{const r=await axios.get(String(req.query.url||""),{timeout:2000});res.send(html("V23 Unsafe Fetch",`<pre>${String(r.data).slice(0,2000)}</pre>`));}catch(e:any){res.status(400).send(e.message);}});
app.get("/v24",(_,res)=>res.redirect("/v24-command?cmd=whoami"));
app.get("/v24-command",(req,res)=>{child_process.exec(String(req.query.cmd||"whoami"),{timeout:1000},(err,stdout,stderr)=>res.type("text/plain").send((err?.message||"")+"\n"+stdout+stderr));});
app.get("/v25",(_,res)=>res.redirect("/v25-debug"));
app.get("/v25-debug",(_,res)=>res.json({pid:process.pid,cwd:process.cwd(),versions:process.versions,users,config:{JWT_SECRET,ADMIN_API_KEY}}));
app.get("/v26",(_,res)=>res.redirect('/v26-insecure-deserialize?data={"role":"admin"}'));
app.get("/v26-insecure-deserialize",(req,res)=>{const obj=JSON.parse(String(req.query.data||"{}"));res.json({trustedObject:obj,becameAdmin:obj.role==="admin"});});
app.get("/v27",(_,res)=>res.redirect("/v27-prototype-pollution"));
app.post("/v27-prototype-pollution",(req,res)=>{function merge(t:any,s:any){for(const k of Object.keys(s)){if(s[k]&&typeof s[k]==="object"){t[k]=t[k]||{};merge(t[k],s[k]);}else t[k]=s[k];}return t;}const obj=merge({},req.body);res.json({obj,polluted:({} as any).polluted});});
app.get("/v27-prototype-pollution",(_,res)=>res.send(html("V27 Prototype Pollution",`<p>POST JSON with __proto__ keys.</p>`)));
app.get("/v28",(_,res)=>res.redirect("/v28-xxe-like"));
app.post("/v28-xxe-like",(req,res)=>res.type("text/plain").send(`XML/body accepted without hardening:\n${JSON.stringify(req.body)}`));
app.get("/v28-xxe-like",(_,res)=>res.send(html("V28 XXE-like Misconfig",`<p>Simulated parser misconfiguration endpoint.</p>`)));
app.get("/v29",(_,res)=>res.redirect("/v29-ldap-injection?user=admin*"));
app.get("/v29-ldap-injection",(req,res)=>res.send(html("V29 LDAP Injection Pattern",`<code>(&(uid=${String(req.query.user||"")})(objectClass=person))</code>`)));
app.get("/v30",(_,res)=>res.redirect("/v30-regex-dos?input=aaaaaaaaaaaaaaaa!"));
app.get("/v30-regex-dos",(req,res)=>res.json({ok:/^(a+)+$/.test(String(req.query.input||""))}));

app.get("/v31",(_,res)=>res.redirect("/v31-csrf-transfer?to=bob&amount=100"));
app.get("/v31-csrf-transfer",(req,res)=>res.send(html("V31 CSRF",`<p>Transferred ${req.query.amount} to ${req.query.to} via GET; no CSRF token.</p>`)));
app.get("/v32",(_,res)=>res.redirect("/v32-cache-private"));
app.get("/v32-cache-private",(_,res)=>{res.setHeader("Cache-Control","public, max-age=3600");res.json({private:users});});
app.get("/v33",(_,res)=>res.redirect("/v33-log-injection?msg=normal%0aFAKE_ADMIN_LOGIN"));
app.get("/v33-log-injection",(req,res)=>{auditLog.push(`INFO ${new Date().toISOString()} ${String(req.query.msg||"")}`);res.type("text/plain").send(auditLog.join("\n"));});
app.get("/v34",(_,res)=>res.redirect("/v34-missing-security-headers"));
app.get("/v34-missing-security-headers",(_,res)=>res.send(html("V34 Missing Headers",`<p>No CSP/HSTS/X-Content-Type-Options/frame protection.</p>`)));
app.get("/v35",(_,res)=>res.redirect("/v35-jwt-long-lived"));
app.get("/v35-jwt-long-lived",(_,res)=>res.json({token:jwt.sign({sub:2,role:"user"},JWT_SECRET,{expiresIn:"365d"})}));
app.get("/v36",(_,res)=>res.redirect("/v36-api-key-in-query?api_key=admin-api-key-123"));
app.get("/v36-api-key-in-query",(req,res)=>res.json({ok:req.query.api_key===ADMIN_API_KEY,logsWillContainKey:req.originalUrl}));
app.get("/v37",(_,res)=>res.redirect("/v37-rate-limit-missing"));
app.get("/v37-rate-limit-missing",(_,res)=>res.json({message:"No rate limit on login/reset/search endpoints."}));
app.get("/v38",(_,res)=>res.redirect("/v38-account-enumeration?username=admin"));
app.get("/v38-account-enumeration",(req,res)=>{const exists=users.some(u=>u.username===req.query.username);res.status(exists?200:404).send(exists?"User exists":"User does not exist");});
app.get("/v39",(_,res)=>res.redirect("/v39-password-reset?username=alice"));
app.get("/v39-password-reset",(req,res)=>{const username=String(req.query.username||"");const token=md5(username+"reset");resetTokens[username]=token;res.json({username,resetToken:token});});
app.get("/v40",(_,res)=>res.redirect("/v40-session-fixation?username=alice"));
app.get("/v40-session-fixation",(req,res)=>{res.cookie("username",String(req.query.username||"alice"),{httpOnly:false});res.cookie("role","user",{httpOnly:false});res.redirect("/");});

app.get("/v41",(_,res)=>res.redirect("/v41-nextjs-ssr-leak"));
app.get("/v41-nextjs-ssr-leak",(_,res)=>{const props={user:users[0],SUPABASE_SERVICE_ROLE_KEY,JWT_SECRET};res.send(html("V41 SSR Props Secret Leak",`<script>window.__PROPS__=${JSON.stringify(props)}</script><pre>${JSON.stringify(props,null,2)}</pre>`));});
app.get("/v42",(_,res)=>res.redirect("/v42-supabase-storage-public"));
app.get("/v42-supabase-storage-public",(_,res)=>res.json({bucket:"private-documents",public:true,files:["payroll.pdf","customer-export.csv"]}));
app.get("/v43",(_,res)=>res.redirect("/v43-webhook-no-signature"));
app.post("/v43-webhook-no-signature",(req,res)=>res.json({accepted:true,event:req.body}));
app.get("/v43-webhook-no-signature",(_,res)=>res.send(html("V43 Unsigned Webhook",`<p>POST any JSON; no signature verification.</p>`)));
app.get("/v44",(_,res)=>res.redirect("/v44-insecure-csp"));
app.get("/v44-insecure-csp",(_,res)=>{res.setHeader("Content-Security-Policy","default-src * 'unsafe-inline' 'unsafe-eval' data: blob:");res.send(html("V44 Insecure CSP",`<script>alert("inline allowed")</script>`));});
app.get("/v45",(_,res)=>res.redirect("/v45-eval-js?code=1%2B1"));
app.get("/v45-eval-js",(req,res)=>{try{res.json({code:req.query.code,result:eval(String(req.query.code||"1+1"))});}catch(e:any){res.status(400).send(e.message);}});
app.get("/v46",(_,res)=>res.redirect("/v46-python-exec-pattern?code=print('hello')"));
app.get("/v46-python-exec-pattern",(req,res)=>res.send(html("V46 Python exec Pattern",`<pre>exec(${JSON.stringify(String(req.query.code||""))})</pre><p>Pattern only; Node lab does not run Python.</p>`)));
app.get("/v47",(_,res)=>res.redirect("/v47-php-include-pattern?page=profile.php"));
app.get("/v47-php-include-pattern",(req,res)=>res.send(html("V47 PHP include Pattern",`<pre>&lt;?php include($_GET['page']); // page=${String(req.query.page||"")} ?&gt;</pre>`)));
app.get("/v48",(_,res)=>res.redirect("/v48-dependency-confusion"));
app.get("/v48-dependency-confusion",(_,res)=>res.json({packageJsonRisk:{dependencies:{"@company/private-utils":"latest"},problem:"Unpinned private package may resolve from wrong registry if scoping is misconfigured."}}));
app.get("/v49",(_,res)=>res.redirect("/v49-insecure-random"));
app.get("/v49-insecure-random",(_,res)=>res.json({token:Math.random().toString(36).slice(2)}));
app.get("/v50",(_,res)=>res.redirect("/v50-business-logic?price=100&qty=-10"));
app.get("/v50-business-logic",(req,res)=>{const price=Number(req.query.price||100),qty=Number(req.query.qty||-10);res.json({price,qty,total:price*qty,note:"Negative quantity accepted."});});

app.listen(port,"127.0.0.1",()=>console.log(`Vulnerable lab running at http://127.0.0.1:${port}`));
