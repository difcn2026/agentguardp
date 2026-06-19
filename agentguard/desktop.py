"""
AgentGuard Desktop — Web GUI
Start with: agentguard serve
Opens browser at http://127.0.0.1:1099
"""
import json, sys, threading, webbrowser, time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PORT = 1099

# ── Progress state (shared between endpoints) ──
_progress = {"phase": "", "done": 0, "total": 0}

TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentGuard Pro</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --dim: #484f58;
  --accent: #58a6ff; --green: #238636; --red: #da3633;
  --orange: #f78166; --yellow: #d29922; --purple: #a371f7;
  --sidebar-w: 260px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}
/* ── Sidebar ── */
.sidebar{width:var(--sidebar-w);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;min-height:100vh;position:fixed;left:0;top:0;bottom:0;z-index:10;transition:transform .25s}
.sidebar.collapsed{transform:translateX(calc(-1 * var(--sidebar-w)))}
.sidebar-header{padding:16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.sidebar-header .logo-text{font-size:16px;font-weight:700;color:var(--accent)}
.sidebar-header .logo-text span{color:var(--orange)}
.sidebar-list{flex:1;overflow-y:auto;padding:8px}
.sidebar-item{padding:10px 12px;border-radius:6px;cursor:pointer;margin-bottom:2px;transition:background .15s;font-size:13px}
.sidebar-item:hover{background:#1c2128}
.sidebar-item.active{background:#1c2533;border-left:3px solid var(--accent)}
.sidebar-item .ts{font-size:11px;color:var(--dim);display:block;margin-top:2px}
.sidebar-item .summary{font-size:11px;color:var(--muted);margin-top:2px}
.sidebar-clear{text-align:center;padding:12px;border-top:1px solid var(--border)}
.sidebar-clear button{background:none;border:1px solid var(--border);color:var(--muted);padding:4px 16px;border-radius:4px;cursor:pointer;font-size:12px}
.sidebar-clear button:hover{color:var(--red);border-color:var(--red)}
/* ── Main ── */
.main{margin-left:var(--sidebar-w);flex:1;transition:margin .25s}
.main.expanded{margin-left:0}
/* ── Top bar ── */
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 20px;height:48px;display:flex;align-items:center;gap:12px}
.toggle-sidebar{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:4px 8px;border-radius:4px}
.toggle-sidebar:hover{color:var(--text);background:#1c2128}
.topbar .title{font-size:15px;font-weight:600}
.badge{background:var(--green);color:#fff;font-size:10px;padding:2px 8px;border-radius:10px}
.topbar .config-btn{margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px}
.topbar .config-btn:hover{color:var(--text);border-color:var(--muted)}
/* ── Content ── */
.content{padding:20px 24px;max-width:960px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
.card h3{font-size:13px;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:1px;display:flex;align-items:center;gap:8px}
.card h3 .actions{margin-left:auto;display:flex;gap:6px}
.card h3 .actions button{background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px}
.card h3 .actions button:hover{color:var(--text);border-color:var(--accent)}
.path-row{display:flex;gap:8px}
.path-row input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:10px 12px;border-radius:6px;font-size:14px;outline:none}
.path-row input:focus{border-color:var(--accent)}
.btn{padding:10px 20px;border:none;border-radius:6px;font-size:14px;cursor:pointer;font-weight:600;transition:all .2s}
.btn-primary{background:var(--green);color:#fff}.btn-primary:hover{background:#2ea043}
.btn-secondary{background:#21262d;color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{background:var(--border)}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#f85149}
.btn-accent{background:var(--accent);color:#fff}.btn-accent:hover{background:#79b8ff}
.btn:disabled{opacity:.5;cursor:not-allowed}
.modes{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.mode-tag{background:#21262d;border:1px solid var(--border);color:var(--muted);padding:6px 14px;border-radius:20px;font-size:13px;cursor:pointer}
.mode-tag.active{background:#1f6feb;border-color:var(--accent);color:#fff}
.switches{display:flex;gap:16px;margin-top:12px;align-items:center;flex-wrap:wrap}
.switch-row{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.switch-row input[type=checkbox]{accent-color:var(--green);width:16px;height:16px}
/* ── Stats ── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px 8px;text-align:center;cursor:pointer;transition:all .15s}
.stat:hover{border-color:var(--muted)}
.stat .num{font-size:28px;font-weight:700}.stat .label{font-size:10px;color:var(--muted);margin-top:2px}
.stat.crit .num{color:var(--red)}.stat.high .num{color:var(--orange)}
.stat.med .num{color:var(--yellow)}.stat.low .num{color:var(--accent)}
.stat.info .num{color:var(--purple)}
.stat.active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
/* ── Filter bar ── */
.filter-bar{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filter-chip{background:#21262d;border:1px solid var(--border);color:var(--muted);padding:3px 12px;border-radius:12px;font-size:12px;cursor:pointer}
.filter-chip.active{background:#1f3a5f;border-color:var(--accent);color:var(--accent)}
.filter-chip.all{font-weight:600}
/* ── Output ── */
.output{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:16px;max-height:520px;overflow:auto;font-family:'Cascadia Code','Fira Code','Consolas',monospace;font-size:13px;line-height:1.7;white-space:pre-wrap}
.output .dim{color:var(--dim)}
.output .crit{color:var(--red);font-weight:700}
.output .high{color:var(--orange)}
.output .ok{color:#3fb950}
.output .finding-row{display:flex;gap:8px;align-items:baseline}
.output .finding-row .loc{color:var(--dim);font-size:11px;min-width:70px}
/* ── Loading ── */
.loading{display:none;align-items:center;gap:10px;color:var(--muted);font-size:13px;margin-top:12px}
.loading.show{display:flex}
.spinner{width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}
.progress-bar{flex:1;max-width:200px;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.progress-bar .fill{height:100%;background:var(--accent);width:0%;transition:width .3s}
@keyframes spin{to{transform:rotate(360deg)}}
/* ── Config Modal ── */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;width:440px;max-width:90vw}
.modal h2{font-size:18px;margin-bottom:16px;color:var(--text)}
.modal label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px;margin-top:12px}
.modal input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;outline:none}
.modal input:focus{border-color:var(--accent)}
.modal .btn-row{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}
/* ── Welcome state ── */
.welcome{text-align:center;padding:60px 20px;color:var(--dim)}
.welcome .icon{font-size:48px;margin-bottom:16px}
.welcome h2{font-size:20px;color:var(--text);margin-bottom:8px}
.welcome p{font-size:14px;line-height:1.8}
</style>
</head>
<body>
<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-header">
    <div class="logo-text">AgentGuard <span>Pro</span></div>
  </div>
  <div class="sidebar-list" id="historyList">
    <div style="color:var(--dim);font-size:12px;text-align:center;padding:20px">No scan history yet</div>
  </div>
  <div class="sidebar-clear">
    <button onclick="clearHistory()">Clear History</button>
  </div>
</aside>

<!-- Main -->
<div class="main" id="mainArea">
  <div class="topbar">
    <button class="toggle-sidebar" onclick="toggleSidebar()" title="Toggle sidebar">&#9776;</button>
    <div class="title">AgentGuard Pro</div>
    <div class="badge">v0.3.0</div>
    <button class="config-btn" onclick="toggleConfig()">&#9881; Settings</button>
  </div>
  <div class="content">
    <!-- Scan card -->
    <div class="card">
      <h3>Scan Target</h3>
      <div class="path-row">
        <input id="path" placeholder="Choose a project folder..." />
        <button class="btn btn-secondary" onclick="browse()">Browse</button>
      </div>
      <div class="modes">
        <div class="mode-tag active" data-mode="dry-run" onclick="setMode('dry-run',this)">Dry Run</div>
        <div class="mode-tag" data-mode="safe" onclick="setMode('safe',this)">Safe</div>
        <div class="mode-tag" data-mode="fix" onclick="setMode('fix',this)">Fix All</div>
      </div>
      <div class="switches">
        <label class="switch-row"><input type="checkbox" id="bandit"> Bandit Engine (100+ rules)</label>
        <label class="switch-row"><input type="checkbox" id="ds"> DeepSeek Review</label>
        <label class="switch-row"><input type="checkbox" id="write"> Write Files</label>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px">
        <button class="btn btn-primary" id="scanBtn" onclick="doScan()">Scan</button>
        <button class="btn btn-danger" id="pipelineBtn" onclick="doPipeline()">Pipeline (Scan + Fix)</button>
      </div>
      <div class="loading" id="loading">
        <div class="spinner"></div>
        <span id="loadingText">Working...</span>
        <div class="progress-bar"><div class="fill" id="progressFill"></div></div>
      </div>
    </div>

    <!-- Results card -->
    <div class="card" id="resultsCard" style="display:none">
      <h3>
        Results
        <span class="actions">
          <button onclick="exportResults('json')" title="Export JSON">&#8595; JSON</button>
          <button onclick="exportResults('html')" title="Export HTML">&#8595; HTML</button>
          <button onclick="exportResults('md')" title="Export Markdown">&#8595; MD</button>
        </span>
      </h3>
      <div class="stats" id="stats"></div>
      <div class="filter-bar" id="filterBar" style="display:none">
        <span style="font-size:12px;color:var(--muted);margin-right:4px">Filter:</span>
        <div class="filter-chip all active" onclick="setFilter('all',this)">All</div>
        <div class="filter-chip" onclick="setFilter('CRITICAL',this)" style="color:var(--red)">Critical</div>
        <div class="filter-chip" onclick="setFilter('HIGH',this)" style="color:var(--orange)">High</div>
        <div class="filter-chip" onclick="setFilter('MEDIUM',this)" style="color:var(--yellow)">Medium</div>
        <div class="filter-chip" onclick="setFilter('LOW',this)" style="color:var(--accent)">Low</div>
        <span id="filterCount" style="font-size:11px;color:var(--dim);margin-left:8px"></span>
      </div>
      <div class="output" id="output">
        <div class="welcome">
          <div class="icon">&#128737;</div>
          <h2>AgentGuard Pro</h2>
          <p>Select a folder and click Scan<br/>or run Pipeline for scan + auto-fix</p>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Config Modal -->
<div class="modal-overlay" id="configModal">
  <div class="modal">
    <h2>&#9881; Settings</h2>
    <label>DeepSeek API URL</label>
    <input id="cfgDsUrl" placeholder="http://127.0.0.1:57321" />
    <label>License Server</label>
    <input id="cfgLicenseUrl" placeholder="http://47.236.24.76:8989" />
    <div class="btn-row">
      <button class="btn btn-secondary" onclick="toggleConfig()">Cancel</button>
      <button class="btn btn-primary" onclick="saveConfig()">Save</button>
    </div>
  </div>
</div>

<script>
// ═══ State ═══════════════════════════════
let mode='dry-run';
let currentFilter='all';
let lastResults=null;
let history=[];
let sidebarOpen=true;

// ═══ Init ═══════════════════════════════
(function(){
  try{history=JSON.parse(localStorage.getItem('ag_history')||'[]');}catch(e){history=[];}
  try{const cfg=JSON.parse(localStorage.getItem('ag_config')||'{}');
    document.getElementById('cfgDsUrl').value=cfg.dsUrl||'http://127.0.0.1:57321';
    document.getElementById('cfgLicenseUrl').value=cfg.licenseUrl||'http://47.236.24.76:8989';
  }catch(e){}
  renderHistory();
})();

// ═══ Sidebar ═══════════════════════════
function toggleSidebar(){
  sidebarOpen=!sidebarOpen;
  document.getElementById('sidebar').classList.toggle('collapsed',!sidebarOpen);
  document.getElementById('mainArea').classList.toggle('expanded',!sidebarOpen);
}
function renderHistory(){
  const el=document.getElementById('historyList');
  if(!history.length){el.innerHTML='<div style="color:var(--dim);font-size:12px;text-align:center;padding:20px">No scan history yet</div>';return;}
  el.innerHTML=history.map((h,i)=>`
    <div class="sidebar-item" onclick="loadHistory(${i})">
      <strong>${escHtml(h.path||'?')}</strong>
      <span class="ts">${h.time||''}</span>
      <span class="summary">Crit:${h.critical||0} High:${h.high||0} Med:${h.medium||0} Low:${h.low||0}</span>
    </div>
  `).join('');
}
function loadHistory(i){
  if(i<0||i>=history.length)return;
  const d=history[i];
  document.getElementById('path').value=d.path||'';
  if(d.mode) setMode(d.mode, document.querySelector(`[data-mode="${d.mode}"]`));
  if(d.bandit!==undefined) document.getElementById('bandit').checked=!!d.bandit;
  if(d.ds!==undefined) document.getElementById('ds').checked=!!d.ds;
  if(d.write!==undefined) document.getElementById('write').checked=!!d.write;
  showResults(d);
  document.getElementById('resultsCard').style.display='block';
  // highlight active
  document.querySelectorAll('.sidebar-item').forEach((el,j)=>el.classList.toggle('active',j===i));
}
function saveToHistory(d,path){
  const entry={
    path:path||document.getElementById('path').value,
    time:new Date().toLocaleString(),
    mode:mode,
    bandit:document.getElementById('bandit').checked,
    ds:document.getElementById('ds').checked,
    write:document.getElementById('write').checked,
    critical:d.critical||0, high:d.high||0, medium:d.medium||0, low:d.low||0,
    total:d.total||0,
    findings:(d.findings||[]).slice(0,200),
    fixed_count:d.fixed_count, manual_count:d.manual_count, files_changed:d.files_changed,
    diff:d.diff
  };
  history.unshift(entry);
  if(history.length>50) history=history.slice(0,50);
  try{localStorage.setItem('ag_history',JSON.stringify(history));}catch(e){}
  renderHistory();
}
function clearHistory(){
  history=[];
  try{localStorage.removeItem('ag_history');}catch(e){}
  renderHistory();
}

// ═══ Scan ═══════════════════════════════
function setMode(m,el){
  mode=m;
  document.querySelectorAll('.mode-tag').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');
}
function browse(){
  fetch('/browse').then(r=>r.json()).then(d=>{
    if(d.path) document.getElementById('path').value=d.path;
  });
}
function setLoading(show,txt){
  const l=document.getElementById('loading');
  l.className='loading'+(show?' show':'');  if(txt) document.getElementById('loadingText').textContent=txt;
  document.getElementById('progressFill').style.width='0%';
}
function doScan(){
  const path=document.getElementById('path').value;
  if(!path) return alert('Pick a folder first');
  setLoading(true,'Scanning...');
  document.getElementById('resultsCard').style.display='block';
  const params=new URLSearchParams({path,bandit:document.getElementById('bandit').checked,ds:document.getElementById('ds').checked});
  startProgressPoll();
  fetch('/scan?'+params).then(r=>r.json()).then(d=>{
    stopProgressPoll();
    setLoading(false);
    lastResults=d; showResults(d); saveToHistory(d,path);
  }).catch(e=>{
    stopProgressPoll();
    setLoading(false);
    document.getElementById('output').innerHTML='<div class="crit">Scan failed: '+escHtml(e.message)+'</div>';
  });
}
function doPipeline(){
  const path=document.getElementById('path').value;
  if(!path) return alert('Pick a folder first');
  setLoading(true,'Pipeline running...');
  document.getElementById('resultsCard').style.display='block';
  const params=new URLSearchParams({path,mode,bandit:document.getElementById('bandit').checked,ds:document.getElementById('ds').checked,write:document.getElementById('write').checked});
  startProgressPoll();
  fetch('/pipeline?'+params).then(r=>r.json()).then(d=>{
    stopProgressPoll();
    setLoading(false);
    lastResults=d; showResults(d); saveToHistory(d,path);
  }).catch(e=>{
    stopProgressPoll();
    setLoading(false);
    document.getElementById('output').innerHTML='<div class="crit">Pipeline failed: '+escHtml(e.message)+'</div>';
  });
}

// ═══ Progress polling ═══════════════════
let progressTimer=null;
function startProgressPoll(){
  progressTimer=setInterval(()=>{
    fetch('/progress').then(r=>r.json()).then(p=>{
      if(p.phase) document.getElementById('loadingText').textContent=p.phase;
      if(p.total>0){
        const pct=Math.round(p.done/p.total*100);
        document.getElementById('progressFill').style.width=pct+'%';
      }
    }).catch(()=>{});
  },500);
}
function stopProgressPoll(){
  if(progressTimer){clearInterval(progressTimer);progressTimer=null;}
}

// ═══ Results ════════════════════════════
function showResults(d){
  if(!d) return;
  document.getElementById('resultsCard').style.display='block';
  document.getElementById('stats').innerHTML=`
    <div class="stat crit" onclick="setFilter('CRITICAL')"><div class="num">${d.critical||0}</div><div class="label">Critical</div></div>
    <div class="stat high" onclick="setFilter('HIGH')"><div class="num">${d.high||0}</div><div class="label">High</div></div>
    <div class="stat med" onclick="setFilter('MEDIUM')"><div class="num">${d.medium||0}</div><div class="label">Medium</div></div>
    <div class="stat low" onclick="setFilter('LOW')"><div class="num">${d.low||0}</div><div class="label">Low</div></div>
    <div class="stat info" onclick="setFilter('all')"><div class="num">${d.total||(d.findings?d.findings.length:0)}</div><div class="label">Total</div></div>
  `;
  if(d.findings && d.findings.length>0){
    document.getElementById('filterBar').style.display='flex';
  }
  currentFilter='all';
  document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active'));
  document.querySelector('.filter-chip.all').classList.add('active');
  renderFindings(d);
}
function setFilter(sev,el){
  currentFilter=sev;
  document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active'));
  if(el) el.classList.add('active');
  else document.querySelector(`.filter-chip${sev==='all'?'.all':''}`)?.classList.add('active');
  document.querySelectorAll('.stat').forEach(s=>s.classList.remove('active'));
  renderFindings(lastResults);
}
function renderFindings(d){
  if(!d||!d.findings){document.getElementById('output').innerHTML='<div class="dim">No findings.</div>';return;}
  let findings=d.findings;
  if(currentFilter!=='all'){
    findings=findings.filter(f=>f.severity===currentFilter);
    document.querySelectorAll('.stat').forEach(s=>{
      const lbl=s.querySelector('.label')?.textContent;
      if(lbl&&lbl.toLowerCase()===currentFilter.toLowerCase()) s.classList.add('active');
    });
  }
  document.getElementById('filterCount').textContent=findings.length+' shown';
  if(!findings.length){
    document.getElementById('output').innerHTML='<div class="dim">No findings for this filter.</div>';
    return;
  }
  let html='';
  if(d.diff) html+='<div class="ok">=== Fixed Diff ===</div>'+escHtml(d.diff)+'\n\n';
  findings.slice(0,200).forEach(f=>{
    const cls=f.severity==='CRITICAL'?'crit':f.severity==='HIGH'?'high':'';
    html+=`<div class="${cls}">[${f.rule_id||'?'}] L${f.line||'?'}: ${escHtml(f.message||'')}</div>`;
    if(f.code_snippet) html+=`<div class="dim">    ${escHtml(f.code_snippet)}</div>`;
  });
  if(findings.length>200) html+=`<div class="dim">... and ${findings.length-200} more</div>`;
  if(d.fixed_count!==undefined) html+=`<div class="ok">\nFixed: ${d.fixed_count} | Manual: ${d.manual_count} | Files: ${d.files_changed}</div>`;
  document.getElementById('output').innerHTML=html||'<div class="dim">No findings.</div>';
}

// ═══ Export ═════════════════════════════
function exportResults(fmt){
  if(!lastResults){alert('No results to export');return;}
  const d=lastResults;
  let content,ext,mime;
  if(fmt==='json'){
    content=JSON.stringify(d,null,2);
    ext='json'; mime='application/json';
  }else if(fmt==='md'){
    content=buildMarkdown(d);
    ext='md'; mime='text/markdown';
  }else{
    content=buildHtml(d);
    ext='html'; mime='text/html';
  }
  const blob=new Blob([content],{type:mime});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`agentguard-scan-${Date.now()}.${ext}`;
  a.click();
  URL.revokeObjectURL(a.href);
}
function buildMarkdown(d){
  let md=`# AgentGuard Scan Report\\n\\n`;
  md+=`**Path:** ${d._path||document.getElementById('path').value}\\n`;
  md+=`**Time:** ${new Date().toLocaleString()}\\n`;
  md+=`**Mode:** ${mode}\\n\\n`;
  md+=`| Severity | Count |\\n| --- | --- |\\n`;
  md+=`| Critical | ${d.critical||0} |\\n| High | ${d.high||0} |\\n| Medium | ${d.medium||0} |\\n| Low | ${d.low||0} |\\n\\n`;
  if(d.fixed_count!==undefined) md+=`**Fixed:** ${d.fixed_count} | **Manual:** ${d.manual_count} | **Files:** ${d.files_changed}\\n\\n`;
  if(d.findings) d.findings.forEach(f=>{
    md+=`- **${f.severity||'?'}** [${f.rule_id||'?'}] L${f.line||'?'}: ${f.message||''}\\n`;
    if(f.code_snippet) md+=`  \\\\\`\\\\\`\\\\\`\\n${f.code_snippet}\\n  \\\\\`\\\\\`\\\\\`\\n`;
  });
  return md;
}
function buildHtml(d){
  let h=`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>AgentGuard Scan Report</title>`;
  h+=`<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}`;
  h+=`.crit{color:#da3633}.high{color:#f78166}.dim{color:#484f58}</style></head><body>`;
  h+=`<h1>AgentGuard Scan Report</h1><p>Path: ${d._path||document.getElementById('path').value}<br>Time: ${new Date().toLocaleString()}<br>Mode: ${mode}</p>`;
  h+=`<table><tr><td>Critical: ${d.critical||0}</td><td>High: ${d.high||0}</td><td>Medium: ${d.medium||0}</td><td>Low: ${d.low||0}</td></tr></table>`;
  if(d.fixed_count!==undefined) h+=`<p>Fixed: ${d.fixed_count} | Manual: ${d.manual_count} | Files: ${d.files_changed}</p>`;
  if(d.diff) h+=`<pre>${escHtml(d.diff)}</pre>`;
  if(d.findings) d.findings.forEach(f=>{
    const cls=f.severity==='CRITICAL'?'crit':f.severity==='HIGH'?'high':'';
    h+=`<div class="${cls}">[${f.rule_id||'?'}] L${f.line||'?'}: ${escHtml(f.message||'')}</div>`;
    if(f.code_snippet) h+=`<div class="dim">    ${escHtml(f.code_snippet)}</div>`;
  });
  h+=`</body></html>`;
  return h;
}

// ═══ Config ═════════════════════════════
function toggleConfig(){
  document.getElementById('configModal').classList.toggle('show');
}
function saveConfig(){
  const cfg={
    dsUrl:document.getElementById('cfgDsUrl').value,
    licenseUrl:document.getElementById('cfgLicenseUrl').value
  };
  try{localStorage.setItem('ag_config',JSON.stringify(cfg));}catch(e){}
  fetch('/config',{method:'POST',body:JSON.stringify(cfg),headers:{'Content-Type':'application/json'}});
  toggleConfig();
}

// ═══ Util ═══════════════════════════════
function escHtml(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_html(TEMPLATE)
        elif path == "/browse":
            self._do_browse()
        elif path == "/progress":
            self._json(_progress)
        elif path == "/scan":
            self._handle_scan(qs, pipeline=False)
        elif path == "/pipeline":
            self._handle_scan(qs, pipeline=True)
        elif path == "/config":
            self._json({"dsUrl": "http://127.0.0.1:57321", "licenseUrl": "http://47.236.24.76:8989"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/config":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                cfg = json.loads(body)
                # Could persist to file, for now just acknowledge
                self._json({"ok": True, "config": cfg})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})
        else:
            self.send_response(404)
            self.end_headers()

    def _do_browse(self):
        import tkinter.filedialog as fd
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = fd.askdirectory(title="Select project folder")
        root.destroy()
        self._json({"path": folder or ""})

    def _serve_html(self, html):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def _handle_scan(self, qs, pipeline=False):
        target = qs.get("path", ["."])[0]
        use_bandit = qs.get("bandit", ["0"])[0] == "true"
        use_ds = qs.get("ds", ["0"])[0] == "true"
        mode = qs.get("mode", ["dry-run"])[0]
        write = qs.get("write", ["0"])[0] == "true"

        try:
            if pipeline:
                _progress["phase"] = "Running pipeline..."
                _progress["done"] = 0
                _progress["total"] = 3

                from agentguard.pipeline import pipeline as run_pipe
                _progress["done"] = 1
                result = run_pipe(path=target, mode=mode, use_ds=use_ds, write=write, use_bandit=use_bandit)
                _progress["done"] = 3
                _progress["phase"] = "Done"
                scan = result.get("scan", {})
                fix = result.get("fix", {})
                self._json({
                    "critical": scan.get("critical", 0),
                    "high": scan.get("high", 0),
                    "medium": scan.get("medium", 0),
                    "low": scan.get("low", 0),
                    "total": scan.get("total", 0),
                    "fixed_count": fix.get("fixed_count", 0),
                    "manual_count": fix.get("manual_count", 0),
                    "files_changed": fix.get("files_changed", 0),
                    "diff": fix.get("diff", ""),
                    "findings": [],
                })
            else:
                _progress["phase"] = "Scanning..."
                _progress["done"] = 0
                _progress["total"] = 2

                if use_bandit:
                    from agentguard.scanner.bandit_adapter import scan_with_bandit
                    findings = scan_with_bandit(target)
                else:
                    from agentguard.scanner.code_scanner import CodeScanner
                    scanner = CodeScanner(tier="pro")
                    result = scanner.scan_directory(target)
                    findings = [{
                        "rule_id": f.rule_id, "severity": str(f.severity),
                        "line": f.line, "message": f.message,
                        "code_snippet": f.code_snippet or "",
                    } for f in result.findings]

                _progress["done"] = 2
                _progress["phase"] = "Done"

                crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                high = sum(1 for f in findings if f.get("severity") == "HIGH")
                med = sum(1 for f in findings if f.get("severity") == "MEDIUM")
                low = sum(1 for f in findings if f.get("severity") == "LOW")
                self._json({
                    "critical": crit, "high": high, "medium": med, "low": low,
                    "total": len(findings), "findings": findings,
                })
        except Exception as e:
            _progress["phase"] = f"Error: {e}"
            self._json({"error": str(e), "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": []})
        finally:
            _progress["phase"] = ""

    def log_message(self, format, *args):
        pass


def serve():
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"AgentGuard Desktop -> {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    serve()
