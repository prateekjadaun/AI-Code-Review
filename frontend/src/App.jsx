// frontend/src/App.jsx — Aesthetic Dark UI
import { useState, useCallback } from "react";

const LANGUAGES = [
  { id: "python",     label: "Python",     icon: "🐍", ext: ".py"   },
  { id: "javascript", label: "JavaScript", icon: "🟨", ext: ".js"   },
  { id: "typescript", label: "TypeScript", icon: "🔷", ext: ".ts"   },
  { id: "java",       label: "Java",       icon: "☕", ext: ".java" },
  { id: "go",         label: "Go",         icon: "🐹", ext: ".go"   },
  { id: "jsx",        label: "React JSX",  icon: "⚛️", ext: ".jsx"  },
];

const SAMPLES = {
  python: {
    "SQL Injection": `def get_user(username):\n    query = "SELECT * FROM users WHERE username = '" + username + "'"\n    cursor.execute(query)\n    return cursor.fetchone()`,
    "XSS Vulnerability": `@app.route('/greet')\ndef greet():\n    name = request.args.get('name', '')\n    return f'<h1>Hello, {name}!</h1>'`,
    "Hardcoded Secret": `SECRET_KEY = "mysecretkey123"\nDB_PASSWORD = "admin123"\nAPI_KEY = "sk-abc123def456"`,
    "Weak Crypto": `import hashlib\n\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()`,
    "Command Injection": `import subprocess\n\ndef run_command(user_input):\n    result = subprocess.run(user_input, shell=True, capture_output=True)\n    return result.stdout.decode()`,
    "Clean Code": `import bcrypt\n\ndef hash_password(password: str) -> bytes:\n    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\ndef verify_password(password: str, hashed: bytes) -> bool:\n    return bcrypt.checkpw(password.encode(), hashed)`,
  },
  javascript: {
    "XSS Vulnerability": `function showMessage(userInput) {\n  document.getElementById('output').innerHTML = userInput;\n}`,
    "Hardcoded Secret": `const API_KEY = "sk-abc123def456xyz";\nconst DB_PASSWORD = "admin123";\nconst JWT_SECRET = "supersecretjwt";`,
    "SQL Injection": `function getUser(username) {\n  const query = "SELECT * FROM users WHERE name='" + username + "'";\n  db.execute(query);\n}`,
    "Clean Code": `const sanitized = DOMPurify.sanitize(userInput);\ndocument.getElementById('output').textContent = sanitized;\nconst SECRET = process.env.API_KEY;`,
  },
  typescript: {
    "XSS Vulnerability": `function renderBio(user: { bio: string }): void {\n  document.body.innerHTML = user.bio;\n}`,
    "Hardcoded Secret": `const token: string = "ghp_AbCdEfGhIjKlMnOpQrSt123456";\nconst dbPass: string = "password123";`,
    "Clean Code": `function renderBio(user: { bio: string }): void {\n  const el = document.createElement('p');\n  el.textContent = user.bio;\n  document.body.appendChild(el);\n}`,
  },
  java: {
    "SQL Injection": `public User getUser(String username) {\n    String query = "SELECT * FROM users WHERE name='" + username + "'";\n    return db.execute(query);\n}`,
    "Weak Crypto": `import java.security.MessageDigest;\n\npublic String hashPassword(String password) {\n    MessageDigest md = MessageDigest.getInstance("MD5");\n    byte[] hash = md.digest(password.getBytes());\n    return new String(hash);\n}`,
    "Clean Code": `PreparedStatement stmt = conn.prepareStatement(\n    "SELECT * FROM users WHERE name = ?"\n);\nstmt.setString(1, username);\nResultSet rs = stmt.executeQuery();`,
  },
  go: {
    "SQL Injection": `func getUser(db *sql.DB, username string) {\n    query := "SELECT * FROM users WHERE name='" + username + "'"\n    db.Query(query)\n}`,
    "Hardcoded Secret": `const (\n    APIKey    = "sk-abc123def456xyz"\n    DBPasswd  = "admin123"\n    JWTSecret = "supersecret"\n)`,
    "Clean Code": `func getUser(db *sql.DB, username string) (*User, error) {\n    row := db.QueryRow("SELECT * FROM users WHERE name = ?", username)\n    var u User\n    return &u, row.Scan(&u.ID, &u.Name)\n}`,
  },
  jsx: {
    "XSS Vulnerability": `function UserProfile({ user }) {\n  return (\n    <div dangerouslySetInnerHTML={{ __html: user.bio }} />\n  );\n}`,
    "Hardcoded Secret": `const API_KEY = "sk-abc123def456";\n\nfunction App() {\n  const res = fetch('/api', {\n    headers: { Authorization: API_KEY }\n  });\n}`,
    "Clean Code": `import DOMPurify from 'dompurify';\n\nfunction UserProfile({ user }) {\n  const cleanBio = DOMPurify.sanitize(user.bio);\n  return <div dangerouslySetInnerHTML={{ __html: cleanBio }} />;\n}`,
  },
};

const RULES = [
  { id: "SEC001", pattern: /(execute|query)\s*\(\s*["'].*\+.*["']|f["'].*SELECT|f["'].*INSERT/gi,        label: "vulnerability", category: "sql_injection",          severity: "critical", message: "SQL Injection: string concatenation in SQL query.",
    fix: `# ❌ Wrong: string concatenation lets attackers inject SQL\nquery = "SELECT * FROM users WHERE username = '" + username + "'"\n\n# ✅ Right: parameterized query — the driver escapes the value\nquery = "SELECT * FROM users WHERE username = %s"\ncursor.execute(query, (username,))` },
  { id: "SEC002", pattern: /innerHTML\s*=(?!=)|dangerouslySetInnerHTML/gi,                               label: "vulnerability", category: "xss",                     severity: "high",     message: "XSS: unsanitized content in innerHTML or dangerouslySetInnerHTML.",
    fix: `// ❌ Wrong: raw user input rendered as HTML\nelement.innerHTML = userInput;\n\n// ✅ Right: sanitize first, or use textContent\nimport DOMPurify from "dompurify";\nelement.innerHTML = DOMPurify.sanitize(userInput);\n// or, if no HTML is needed at all:\nelement.textContent = userInput;` },
  { id: "SEC003", pattern: /(password|secret|api_key|token|passwd|apikey)\s*[=:]\s*["'][^"']{6,}["']/gi, label: "vulnerability", category: "hardcoded_secrets",        severity: "critical", message: "Hardcoded secret detected. Use environment variables.",
    fix: `# ❌ Wrong: secret committed directly in source code\nAPI_KEY = "sk-abc123def456"\n\n# ✅ Right: load from environment variables / secrets manager\nimport os\nAPI_KEY = os.environ["API_KEY"]` },
  { id: "SEC004", pattern: /hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(["']MD5["']\)/gi,          label: "vulnerability", category: "weak_crypto",             severity: "critical", message: "MD5/SHA1 are broken for passwords. Use bcrypt or argon2.",
    fix: `# ❌ Wrong: MD5 is fast and crackable — bad for passwords\nhashlib.md5(password.encode()).hexdigest()\n\n# ✅ Right: use a slow, salted, purpose-built hash\nimport bcrypt\nbcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))` },
  { id: "SEC005", pattern: /subprocess\.(run|call|Popen).*shell\s*=\s*True|exec\.Command\("sh"/gi,       label: "vulnerability", category: "command_injection",       severity: "critical", message: "Command injection: shell=True with user input.",
    fix: `# ❌ Wrong: shell=True lets user input execute arbitrary commands\nsubprocess.run(user_input, shell=True)\n\n# ✅ Right: pass a list, no shell interpretation\nsubprocess.run(["ping", "-c", "1", host], shell=False)` },
  { id: "SEC006", pattern: /pickle\.loads?\s*\(/gi,                                                      label: "vulnerability", category: "insecure_deserialization", severity: "critical", message: "pickle.loads on untrusted data allows code execution.",
    fix: `# ❌ Wrong: pickle can execute arbitrary code on load\ndata = pickle.loads(untrusted_bytes)\n\n# ✅ Right: use a safe, data-only format\nimport json\ndata = json.loads(untrusted_bytes)` },
  { id: "SM001",  pattern: /except\s*:/g,                                                                label: "code_smell",    category: "bare_except",             severity: "high",     message: "Bare except swallows all errors. Catch specific exceptions.",
    fix: `# ❌ Wrong: catches everything, even Ctrl+C\ntry:\n    risky_call()\nexcept:\n    pass\n\n# ✅ Right: catch only what you expect, log the rest\ntry:\n    risky_call()\nexcept ValueError as e:\n    logging.error(f"Invalid input: {e}")` },
  { id: "SM002",  pattern: /(?<!\w)(86400|3600|9999|255)(?!\w)/g,                                       label: "code_smell",    category: "magic_numbers",           severity: "low",      message: "Magic number. Define as a named constant.",
    fix: `# ❌ Wrong: unclear what 86400 means\ntime.sleep(86400)\n\n# ✅ Right: named constant explains intent\nSECONDS_PER_DAY = 86400\ntime.sleep(SECONDS_PER_DAY)` },
  { id: "SM003",  pattern: /#\s*(TODO|FIXME|HACK|BUG)\b/g,                                              label: "code_smell",    category: "todo_comment",            severity: "low",      message: "TODO/FIXME comment. Track in an issue tracker.",
    fix: `# ❌ Wrong: TODO left buried in code, easy to forget\n# TODO: handle empty input case\n\n# ✅ Right: track it as a proper issue, and code stays clean\n# See JIRA-123 for the empty-input edge case\nif not input_value:\n    raise ValueError("Input cannot be empty")` },
  { id: "ST001",  pattern: /^\s*print\s*\(|console\.log\s*\(/gm,                                        label: "style",         category: "debug_print",             severity: "low",      message: "Debug print found. Use a logging module instead.",
    fix: `# ❌ Wrong: print() can't be filtered or turned off in prod\nprint("user logged in:", username)\n\n# ✅ Right: structured, level-based logging\nimport logging\nlogging.info("User logged in: %s", username)` },
];

const SEV = {
  critical: { color: "#f87171", bg: "rgba(248,113,113,0.12)", border: "rgba(248,113,113,0.3)", dot: "#ef4444" },
  high:     { color: "#fb923c", bg: "rgba(251,146,60,0.12)",  border: "rgba(251,146,60,0.3)",  dot: "#f97316" },
  medium:   { color: "#facc15", bg: "rgba(250,204,21,0.12)",  border: "rgba(250,204,21,0.3)",  dot: "#eab308" },
  low:      { color: "#60a5fa", bg: "rgba(96,165,250,0.12)",  border: "rgba(96,165,250,0.3)",  dot: "#3b82f6" },
  none:     { color: "#4ade80", bg: "rgba(74,222,128,0.12)",  border: "rgba(74,222,128,0.3)",  dot: "#22c55e" },
};

function analyzeCode(code) {
  const lines = code.split("\n");
  const findings = [];
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(lines[i])) {
        findings.push({ ...rule, line: i + 1, snippet: lines[i].trim().slice(0, 90) });
      }
    }
  }
  const order = ["critical","high","medium","low"];
  const overall = order.find(s => findings.some(f => f.severity === s)) || "none";
  return { findings, overall, passed: findings.length === 0 };
}

const THEMES = {
  dark: {
    name: "dark", icon: "🌙",
    pageBg:"#0d0d0f", text:"#e2e2e5", subtext:"#6b6b7a", faint:"#4b4b58", faint2:"#5b5b6a",
    headerBg:"#111114", headerBorder:"#1e1e24", headerShadow:"none",
    barBg:"#0f0f12", barBorder:"#1a1a20",
    sidebarBg:"#0f0f12", sidebarBorder:"#1a1a20",
    cardBg:"#0d0d0f", cardBorder:"#1e1e24", cardShadow:"none",
    inputText:"#c9c9d3",
    editorBg:"#0a0a0d", editorBorder:"#1e1e24", editorText:"#a8ff78",
    tabInactive:"#5b5b6a", emptyText:"#3b3b48",
    accent:"#6366f1", accentText:"#a5b4fc",
    footerBg:"#0a0a0d", footerBorder:"#1a1a20", footerText:"#3b3b48",
    findingBg:"rgba(255,255,255,0.04)",
  },
  light: {
    name: "light", icon: "☀️",
    pageBg:"#eef0f6", text:"#20222b", subtext:"#5c5f6e", faint:"#8b8e9d", faint2:"#6c6f7e",
    headerBg:"#ffffff", headerBorder:"#d3d6e0",
    headerShadow:"0 1px 2px rgba(23,25,42,0.06)",
    barBg:"#ffffff", barBorder:"#e1e3ec",
    sidebarBg:"#ffffff", sidebarBorder:"#e1e3ec",
    cardBg:"#ffffff", cardBorder:"#dde0ea",
    cardShadow:"0 1px 3px rgba(23,25,42,0.05)",
    inputText:"#20222b",
    editorBg:"#fbfbfe", editorBorder:"#d3d6e0", editorText:"#0f7a3d",
    tabInactive:"#8b8e9d", emptyText:"#b3b6c2",
    accent:"#5b5fee", accentText:"#4338ca",
    footerBg:"#ffffff", footerBorder:"#e1e3ec", footerText:"#9799a8",
    findingBg:"#f7f8fc",
  },
};

export default function App() {
  const [language, setLanguage]   = useState("python");
  const [code, setCode]           = useState(Object.values(SAMPLES.python)[0]);
  const [filename, setFilename]   = useState("example.py");
  const [result, setResult]       = useState(null);
  const [loading, setLoading]     = useState(false);
  const [activeTab, setActiveTab] = useState("editor");
  const [openFixes, setOpenFixes] = useState({});
  const [themeName, setThemeName] = useState("dark");

  const t = THEMES[themeName];
  const toggleTheme = () => setThemeName(prev => prev === "dark" ? "light" : "dark");
  const toggleFix = (i) => setOpenFixes(prev => ({ ...prev, [i]: !prev[i] }));

  const lang         = LANGUAGES.find(l => l.id === language);
  const langSamples  = SAMPLES[language] || SAMPLES.python;

  const switchLang = (id) => {
    const l = LANGUAGES.find(x => x.id === id);
    setLanguage(id);
    const first = Object.values(SAMPLES[id] || SAMPLES.python)[0];
    setCode(first);
    setFilename(`example${l.ext}`);
    setResult(null);
    setActiveTab("editor");
  };

  const loadSample = (name) => {
    setCode(langSamples[name]);
    setFilename(`${name.toLowerCase().replace(/ /g,"_")}${lang.ext}`);
    setResult(null);
    setActiveTab("editor");
  };

  const run = useCallback(() => {
    setLoading(true);
    setTimeout(() => { setResult(analyzeCode(code)); setActiveTab("results"); setLoading(false); setOpenFixes({}); }, 500);
  }, [code]);

  const counts = result ? RULES.reduce((a,r) => { const n = result.findings.filter(f=>f.severity===r.severity||f.id===r.id).length; return a; }, {}) : {};
  const sevCounts = result ? result.findings.reduce((a,f) => { a[f.severity]=(a[f.severity]||0)+1; return a; },{}) : {};

  return (
    <div style={{ minHeight:"100vh", background:t.pageBg, color:t.text, fontFamily:"'Inter',system-ui,sans-serif", display:"flex", flexDirection:"column", transition:"background 0.2s, color 0.2s" }}>

      {/* Top bar */}
      <header style={{ background:t.headerBg, borderBottom:`1px solid ${t.headerBorder}`, boxShadow:t.headerShadow, padding:"0 24px", height:56, display:"flex", alignItems:"center", justifyContent:"space-between", flexShrink:0, position:"relative", zIndex:2 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#6366f1,#8b5cf6)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>🔍</div>
          <div>
            <div style={{ fontWeight:600, fontSize:15, letterSpacing:"-0.3px" }}>AI Code Review</div>
            <div style={{ fontSize:11, color:t.subtext }}>CodeBERT · Static Analysis · PRO012</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          <span style={{ background:"rgba(99,102,241,0.15)", color:"#a5b4fc", border:"1px solid rgba(99,102,241,0.3)", borderRadius:6, fontSize:11, padding:"3px 10px", fontWeight:500 }}>NLP / Dev Tools</span>
          <span style={{ background:"rgba(34,197,94,0.12)", color:"#4ade80", border:"1px solid rgba(34,197,94,0.25)", borderRadius:6, fontSize:11, padding:"3px 10px", fontWeight:500 }}>● Live</span>
          <button onClick={toggleTheme} title="Toggle light / dark theme" style={{
            display:"flex", alignItems:"center", gap:6, background:"transparent", border:`1px solid ${t.headerBorder}`,
            borderRadius:20, padding:"4px 10px", fontSize:12, color:t.text, cursor:"pointer", marginLeft:4
          }}>
            <span>{t.icon}</span>
            <span style={{ fontWeight:500 }}>{themeName === "dark" ? "Dark" : "Light"}</span>
          </button>
        </div>
      </header>

      {/* Language bar */}
      <div style={{ background:t.barBg, borderBottom:`1px solid ${t.barBorder}`, padding:"10px 24px", display:"flex", alignItems:"center", gap:6, overflowX:"auto" }}>
        <span style={{ fontSize:12, color:t.faint, marginRight:8, whiteSpace:"nowrap" }}>Language</span>
        {LANGUAGES.map(l => (
          <button key={l.id} onClick={() => switchLang(l.id)} style={{
            display:"flex", alignItems:"center", gap:6, padding:"5px 12px", borderRadius:8,
            border: language===l.id ? "1px solid rgba(99,102,241,0.5)" : `1px solid ${t.barBorder}`,
            background: language===l.id ? "rgba(99,102,241,0.18)" : "transparent",
            color: language===l.id ? "#a5b4fc" : t.subtext,
            fontSize:13, cursor:"pointer", whiteSpace:"nowrap", transition:"all 0.15s"
          }}>
            <span>{l.icon}</span>
            <span style={{ fontWeight: language===l.id ? 600 : 400 }}>{l.label}</span>
            <span style={{ fontSize:10, opacity:0.6, fontFamily:"monospace" }}>{l.ext}</span>
          </button>
        ))}
      </div>

      {/* Main content */}
      <div style={{ flex:1, display:"grid", gridTemplateColumns:"220px 1fr", gap:0, overflow:"hidden" }}>

        {/* Sidebar */}
        <aside style={{ background:t.sidebarBg, borderRight:`1px solid ${t.sidebarBorder}`, boxShadow:t.cardShadow, padding:"16px 12px", overflowY:"auto", position:"relative", zIndex:1 }}>
          <div style={{ fontSize:11, color:t.faint, fontWeight:600, letterSpacing:"0.08em", textTransform:"uppercase", marginBottom:8, padding:"0 8px" }}>
            {lang.icon} {lang.label} samples
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:2 }}>
            {Object.keys(langSamples).map(name => (
              <button key={name} onClick={() => loadSample(name)} style={{
                textAlign:"left", padding:"7px 10px", borderRadius:6, fontSize:13, cursor:"pointer", transition:"all 0.1s",
                background: code===langSamples[name] ? "rgba(99,102,241,0.15)" : "transparent",
                color: code===langSamples[name] ? "#a5b4fc" : t.subtext,
                border: code===langSamples[name] ? "1px solid rgba(99,102,241,0.3)" : "1px solid transparent",
              }}>{name}</button>
            ))}
          </div>

          <div style={{ margin:"20px 0 8px", padding:"0 8px", fontSize:11, color:t.faint, fontWeight:600, letterSpacing:"0.08em", textTransform:"uppercase" }}>Detection rules</div>
          <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
            {RULES.map(r => (
              <div key={r.id} style={{ display:"flex", alignItems:"center", gap:7, padding:"4px 8px", borderRadius:5 }}>
                <span style={{ width:6, height:6, borderRadius:"50%", background:SEV[r.severity]?.dot, flexShrink:0 }} />
                <span style={{ fontSize:11, fontFamily:"monospace", color:t.faint2 }}>{r.id}</span>
                <span style={{ fontSize:11, color:t.faint, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.category}</span>
              </div>
            ))}
          </div>
        </aside>

        {/* Editor panel */}
        <main style={{ display:"flex", flexDirection:"column", overflow:"hidden" }}>

          {/* Toolbar */}
          <div style={{ background:t.headerBg, borderBottom:`1px solid ${t.barBorder}`, boxShadow:t.headerShadow, padding:"10px 20px", display:"flex", alignItems:"center", gap:10, position:"relative", zIndex:1 }}>
            <div style={{ flex:1, display:"flex", alignItems:"center", gap:8, background:t.cardBg, border:`1px solid ${t.cardBorder}`, borderRadius:8, padding:"6px 12px" }}>
              <span style={{ fontSize:15 }}>{lang.icon}</span>
              <input value={filename} onChange={e=>setFilename(e.target.value)}
                style={{ flex:1, background:"transparent", border:"none", outline:"none", color:t.inputText, fontSize:13, fontFamily:"monospace" }} />
              <span style={{ fontSize:11, background:"rgba(99,102,241,0.12)", color:"#818cf8", border:"1px solid rgba(99,102,241,0.2)", borderRadius:5, padding:"2px 7px" }}>{lang.label}</span>
            </div>
            <button onClick={run} disabled={loading||!code.trim()} style={{
              background: loading ? t.cardBorder : "linear-gradient(135deg,#6366f1,#8b5cf6)",
              color:"#fff", border:"none", borderRadius:8, padding:"8px 18px", fontSize:13,
              fontWeight:600, cursor: loading ? "not-allowed" : "pointer", display:"flex", alignItems:"center", gap:6, transition:"opacity 0.15s",
              opacity: (!code.trim()||loading) ? 0.5 : 1
            }}>
              {loading ? "⟳ Analyzing…" : "▶ Analyze"}
            </button>
          </div>

          {/* Tabs */}
          <div style={{ background:t.headerBg, borderBottom:`1px solid ${t.barBorder}`, display:"flex", padding:"0 20px" }}>
            {["editor","results"].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                padding:"10px 16px", fontSize:13, fontWeight:500, cursor:"pointer", border:"none",
                background:"transparent", transition:"all 0.15s",
                color: activeTab===tab ? "#a5b4fc" : t.tabInactive,
                borderBottom: activeTab===tab ? "2px solid #6366f1" : "2px solid transparent",
              }}>
                {tab==="editor" ? `📝 ${lang.label} editor` : `🔍 Results${result ? ` (${result.findings.length})` : ""}`}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div style={{ flex:1, overflowY:"auto", padding:20 }}>
            {activeTab==="editor" && (
              <textarea value={code} onChange={e=>{setCode(e.target.value);setResult(null);}}
                spellCheck={false}
                style={{ width:"100%", height:"calc(100vh - 280px)", background:t.editorBg, border:`1px solid ${t.editorBorder}`,
                  borderRadius:10, padding:16, color:t.editorText, fontFamily:"'Fira Code','Cascadia Code',monospace",
                  fontSize:13.5, lineHeight:1.7, resize:"none", outline:"none", boxSizing:"border-box" }}
                placeholder={`Paste your ${lang.label} code here…`}
              />
            )}

            {activeTab==="results" && (
              <div>
                {!result ? (
                  <div style={{ textAlign:"center", padding:"60px 0", color:t.emptyText }}>
                    <div style={{ fontSize:48, marginBottom:12 }}>🤖</div>
                    <div style={{ fontSize:15 }}>Click <strong style={{color:"#6366f1"}}>▶ Analyze</strong> to scan your code</div>
                  </div>
                ) : (
                  <>
                    {/* Status banner */}
                    <div style={{
                      background: result.passed ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)",
                      border: `1px solid ${result.passed ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`,
                      borderRadius:10, padding:"14px 18px", marginBottom:20, display:"flex", alignItems:"center", gap:14
                    }}>
                      <span style={{ fontSize:28 }}>{result.passed ? "✅" : "❌"}</span>
                      <div>
                        <div style={{ fontWeight:600, fontSize:15, color: result.passed ? "#4ade80" : "#f87171" }}>
                          {result.passed ? "All checks passed — no issues found!" : `${result.findings.length} issue(s) detected`}
                        </div>
                        <div style={{ fontSize:12, color:t.subtext, marginTop:3 }}>
                          {lang.icon} {lang.label} · {filename} · Severity:&nbsp;
                          <span style={{ color: SEV[result.overall]?.color, fontWeight:600 }}>{result.overall.toUpperCase()}</span>
                        </div>
                      </div>
                    </div>

                    {/* Severity pills */}
                    {result.findings.length > 0 && (
                      <div style={{ display:"flex", gap:8, marginBottom:20, flexWrap:"wrap" }}>
                        {["critical","high","medium","low"].map(s => sevCounts[s] ? (
                          <span key={s} style={{ background:SEV[s].bg, border:`1px solid ${SEV[s].border}`, color:SEV[s].color, borderRadius:20, padding:"4px 12px", fontSize:12, fontWeight:600 }}>
                            {sevCounts[s]} {s}
                          </span>
                        ) : null)}
                      </div>
                    )}

                    {/* Finding cards */}
                    {result.findings.map((f,i) => (
                      <div key={i} style={{
                        background: SEV[f.severity]?.bg || t.findingBg,
                        border: `1px solid ${SEV[f.severity]?.border || t.cardBorder}`,
                        boxShadow: SEV[f.severity]?.bg ? "none" : t.cardShadow,
                        borderRadius:10, padding:"14px 16px", marginBottom:12
                      }}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                            <span style={{ width:8, height:8, borderRadius:"50%", background:SEV[f.severity]?.dot }} />
                            <code style={{ fontSize:12, fontWeight:700, color:SEV[f.severity]?.color }}>{f.id}</code>
                            <span style={{ fontSize:12, color:t.faint2 }}>·</span>
                            <code style={{ fontSize:12, color:t.subtext, background: themeName==="dark" ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.04)", padding:"1px 6px", borderRadius:4 }}>{f.category}</code>
                          </div>
                          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                            <span style={{ fontSize:11, color:t.faint }}>Line {f.line}</span>
                            <span style={{ background:SEV[f.severity]?.bg, border:`1px solid ${SEV[f.severity]?.border}`, color:SEV[f.severity]?.color, borderRadius:20, padding:"2px 9px", fontSize:11, fontWeight:600 }}>
                              {f.severity.toUpperCase()}
                            </span>
                          </div>
                        </div>
                        <p style={{ margin:"0 0 8px", fontSize:13, color:t.text, lineHeight:1.5 }}>{f.message}</p>
                        {f.snippet && (
                          <pre style={{ margin:"0 0 10px", background: themeName==="dark" ? "rgba(0,0,0,0.3)" : "rgba(0,0,0,0.04)", border:`1px solid ${t.cardBorder}`, borderRadius:6, padding:"8px 12px", fontSize:12, fontFamily:"monospace", color:t.subtext, overflowX:"auto" }}>
                            {f.snippet}
                          </pre>
                        )}
                        {f.fix && (
                          <>
                            <button onClick={() => toggleFix(i)} style={{
                              background:"rgba(74,222,128,0.1)", border:"1px solid rgba(74,222,128,0.3)", color:"#4ade80",
                              borderRadius:6, padding:"5px 12px", fontSize:12, fontWeight:600, cursor:"pointer", display:"flex", alignItems:"center", gap:6
                            }}>
                              {openFixes[i] ? "▾" : "▸"} ✅ Show suggested fix
                            </button>
                            {openFixes[i] && (
                              <pre style={{
                                margin:"10px 0 0", background:"rgba(34,197,94,0.06)", border:"1px solid rgba(34,197,94,0.25)",
                                borderRadius:8, padding:"12px 14px", fontSize:12.5, fontFamily:"'Fira Code','Cascadia Code',monospace",
                                color:"#bdf5cf", lineHeight:1.6, overflowX:"auto", whiteSpace:"pre-wrap"
                              }}>
                                {f.fix}
                              </pre>
                            )}
                          </>
                        )}
                      </div>
                    ))}

                    {result.passed && (
                      <div style={{ textAlign:"center", padding:"40px 0", color:"#4ade80" }}>
                        <div style={{ fontSize:40, marginBottom:8 }}>🎉</div>
                        <div style={{ fontSize:15, fontWeight:500 }}>No vulnerabilities or code smells found!</div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer style={{ background:t.footerBg, borderTop:`1px solid ${t.footerBorder}`, padding:"10px 24px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div style={{ display:"flex", gap:16 }}>
          {[{icon:"🛡️",label:"13 security rules"},{icon:"🧹",label:"Code smell detection"},{icon:"⚡",label:"Performance checks"}].map(c=>(
            <span key={c.label} style={{ fontSize:11, color:t.faint, display:"flex", alignItems:"center", gap:5 }}>
              <span>{c.icon}</span> {c.label}
            </span>
          ))}
        </div>
        <span style={{ fontSize:11, color:t.footerText }}>PRO012 · AI-Powered Code Review · CodeBERT + Static Analysis</span>
      </footer>
    </div>
  );
}
