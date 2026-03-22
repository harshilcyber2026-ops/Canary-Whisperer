/* ═══════════════════════════════════════════════
   FLAGVAULT CTF — Canary Whisperer — script.js
   GDB typewriter, stack visualizer, format string
   probe simulator, payload builder, flag check
═══════════════════════════════════════════════ */

/* ─── CORRECT FLAG (obfuscated) ──────────────────
   FlagVault{c4n4ry_wh1sp3r3d_st4ck_sm4sh3d}
   Stored as base64 — decoded at runtime only.
─────────────────────────────────────────────── */
const _FLAG = atob('RmxhZ1ZhdWx0e2M0bjRyeV93aDFzcDNyM2Rfc3Q0Y2tfc200c2gzZH0=');

/* ══════════════════════════════════════════════
   1 · GDB TERMINAL TYPEWRITER
══════════════════════════════════════════════ */
const GDB_LINES = [
  { t: 'GNU gdb (Ubuntu 12.1) 12.1',                          c: '' },
  { t: 'Reading symbols from ./canary_whisperer...',           c: '' },
  { t: '(gdb) disas vuln',                                     c: 'var(--accent2)' },
  { t: '   0x0000000000401172 <+0>:   push   rbp',             c: 'var(--text-dim)' },
  { t: '   0x0000000000401173 <+1>:   mov    rbp,rsp',         c: 'var(--text-dim)' },
  { t: '   0x0000000000401176 <+4>:   sub    rsp,0x50',        c: 'var(--text-dim)' },
  { t: '   0x000000000040117a <+8>:   mov    rax,QWORD PTR fs:0x28',c:'var(--accent2)'},
  { t: '   0x0000000000401183 <+17>:  mov    QWORD PTR [rbp-0x8],rax  ← CANARY STORED', c:'var(--accent)'},
  { t: '   0x0000000000401187 <+21>:  lea    rax,[rbp-0x50]',  c: 'var(--text-dim)' },
  { t: '   0x000000000040118b <+25>:  call   0x401050 <read@plt>', c:'var(--text-dim)'},
  { t: '   0x0000000000401190 <+30>:  lea    rax,[rbp-0x50]',  c: 'var(--text-dim)' },
  { t: '   0x0000000000401194 <+34>:  mov    rdi,rax',         c: 'var(--text-dim)' },
  { t: '   0x0000000000401197 <+37>:  call   0x401060 <printf@plt>  ← printf(buf) NO FMT!', c:'var(--accent2)'},
  { t: '(gdb) x/8gx $rbp-0x50',                               c: 'var(--accent2)' },
  { t: '0x7ffe4a8b12a0:  0x4141414141414141  0x4141414141414141', c:'var(--text)' },
  { t: '0x7ffe4a8b12b0:  0x4141414141414141  0x4141414141414141', c:'var(--text)' },
  { t: '0x7ffe4a8b12c0:  0x4141414141414141  0x4141414141414141', c:'var(--text)' },
  { t: '0x7ffe4a8b12d0:  0x4141414141414141  0x4141414141414141', c:'var(--text)' },
  { t: '0x7ffe4a8b12e0:  [canary → 0x3a88f4c2e1f20d00]  0x00007f...', c:'var(--accent)'},
  { t: '(gdb) # canary at rbp-0x8, buf at rbp-0x50 → offset=64', c:'var(--accent3)'},
];

let gdbIdx = 0;
const gdbEl = document.getElementById('term-gdb');

function typeGDB() {
  if (gdbIdx >= GDB_LINES.length) return;
  const ln = GDB_LINES[gdbIdx++];
  const div = document.createElement('div');
  div.style.color = ln.c || 'var(--text)';
  div.style.opacity = '0';
  div.style.transition = 'opacity 0.25s';
  div.textContent = ln.t;
  gdbEl.appendChild(div);
  requestAnimationFrame(() => { div.style.opacity = '1'; });
  setTimeout(typeGDB, ln.t.length * 14 + 90);
}
setTimeout(typeGDB, 600);

/* ══════════════════════════════════════════════
   2 · STACK FRAME VISUALIZER
══════════════════════════════════════════════ */
const STACK_ROWS = [
  { addr: 'rbp+0x08', label: 'saved RIP',    role: 'rip',    note: 'overwrite → win() @ 0x401196', color:'var(--accent2)' },
  { addr: 'rbp+0x00', label: 'saved RBP',    role: 'rbp',    note: 'clobbered — set to 0x0',       color:'var(--accent3)' },
  { addr: 'rbp-0x08', label: 'CANARY',        role: 'canary', note: 'must be preserved → leak first!', color:'var(--accent)' },
  { addr: 'rbp-0x10', label: 'buf2[56..63]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x18', label: 'buf2[48..55]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x20', label: 'buf2[40..47]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x28', label: 'buf2[32..39]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x30', label: 'buf2[24..31]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x38', label: 'buf2[16..23]',  role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x40', label: 'buf2[8..15]',   role: 'buf', note:'pad bytes',     color:'var(--text-dim)' },
  { addr: 'rbp-0x50', label: 'buf2[0..7]',    role: 'buf', note:'overflow starts here!', color:'var(--text-dim)' },
];

function buildStackVis(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = STACK_ROWS.map((row, i) => {
    const isBuf    = row.role === 'buf';
    const isCanary = row.role === 'canary';
    const isRip    = row.role === 'rip';
    const isRbp    = row.role === 'rbp';
    const bg = isCanary ? 'rgba(0,232,200,0.08)' :
               isRip    ? 'rgba(255,45,107,0.10)' :
               isRbp    ? 'rgba(245,166,35,0.06)' :
                          'transparent';
    const bdr = isCanary ? '1px solid rgba(0,232,200,0.25)' :
                isRip    ? '1px solid rgba(255,45,107,0.25)' :
                isRbp    ? '1px solid rgba(245,166,35,0.18)' :
                           '1px solid transparent';
    return `
      <div class="svis-row" style="display:flex;align-items:center;gap:0;border:${bdr};background:${bg};margin-bottom:2px;border-radius:2px;cursor:default;transition:background 0.18s;"
           onmouseenter="this.style.background='rgba(0,232,200,0.05)'"
           onmouseleave="this.style.background='${bg}'">
        <div style="width:3px;background:${row.color};align-self:stretch;flex-shrink:0;border-radius:2px 0 0 2px;"></div>
        <div style="padding:0.38rem 0.8rem;display:flex;align-items:center;gap:1rem;width:100%;flex-wrap:wrap;">
          <span style="color:var(--accent3);font-size:0.68rem;min-width:80px;">${row.addr}</span>
          <span style="color:${row.color};font-size:0.73rem;min-width:110px;font-weight:${isCanary||isRip?'bold':'normal'};">${row.label}</span>
          <span style="color:var(--text-dim);font-size:0.67rem;flex:1;">${row.note}</span>
          ${isCanary ? '<span style="font-size:0.65rem;background:rgba(0,232,200,0.1);border:1px solid rgba(0,232,200,0.25);color:var(--accent);padding:1px 7px;border-radius:20px;">LEAK THIS</span>' : ''}
          ${isRip    ? '<span style="font-size:0.65rem;background:rgba(255,45,107,0.1);border:1px solid rgba(255,45,107,0.25);color:var(--accent2);padding:1px 7px;border-radius:20px;">OVERWRITE</span>' : ''}
        </div>
      </div>`;
  }).join('');
}

buildStackVis('stack-vis');
buildStackVis('stack-card-sidebar');

/* ══════════════════════════════════════════════
   3 · FORMAT STRING PROBE SIMULATOR
══════════════════════════════════════════════ */
// Simulated "stack" values the format string would read.
// Index = format string argument offset ($1 = idx 0, etc.)
function randHex64(seed) {
  const hi = (0x7ffe0000 + ((seed * 0x9e37 + 0x1234) & 0xffff)).toString(16).padStart(8,'0');
  const lo = ((seed * 0xdeadbabe + 0xcafe) & 0xffffffff).toString(16).padStart(8,'0');
  return '0x' + hi + lo;
}

// Canary sits at offset index 10 (= %11$p, 1-based)
const SIMULATED_STACK = Array.from({length:16}, (_, i) => {
  if (i === 10) return '0x3a88f4c2e1f20d00'; // canary — ends in 00
  if (i === 0)  return '0x00007ffd4a8b12a0'; // buf addr
  if (i === 14) return '0x0000000000401196'; // return addr (win)
  return randHex64(i * 7 + 13);
});

function updateFmt() {
  const n = parseInt(document.getElementById('probe-offset').value) || 1;
  document.getElementById('probe-fmt-label').textContent = `%${n}$p`;
}

function runProbe() {
  const n   = parseInt(document.getElementById('probe-offset').value);
  const out = document.getElementById('probe-output');
  if (isNaN(n) || n < 1 || n > 16) {
    out.innerHTML = `<span style="color:var(--accent2)">[!] offset must be 1–16</span>`;
    return;
  }
  const val     = SIMULATED_STACK[n - 1];
  const isCanary = val.endsWith('00');
  const isWin    = n === 15;
  let annotation = '';
  if (isCanary)  annotation = `<span style="color:var(--accent);margin-left:1rem;">← ends in 00 → CANARY!</span>`;
  else if (isWin) annotation = `<span style="color:var(--accent3);margin-left:1rem;">← return address</span>`;
  else            annotation = `<span style="color:var(--text-dim);margin-left:1rem;">← stack data</span>`;

  out.innerHTML = `
    <div style="color:var(--text-dim);">[*] Sent: <span style="color:var(--accent3)">%${n}$p</span></div>
    <div style="color:var(--text-dim);">[*] Received: <span style="color:${isCanary?'var(--accent)':'var(--text-hi)'}">${val}</span>${annotation}</div>
    ${isCanary ? `<div style="color:var(--accent);margin-top:0.3rem;">[+] Stack canary found at offset <strong>${n}</strong>! Use %${n}$p in your exploit.</div>` : ''}`;
  updateFmt();
}

function probeReset() {
  document.getElementById('probe-output').innerHTML =
    `<span style="color:var(--text-dim)">// probe cleared — enter an offset and click PROBE</span>`;
  document.getElementById('probe-offset').value = '11';
  updateFmt();
}

// init
updateFmt();
document.getElementById('probe-output').innerHTML =
  `<span style="color:var(--text-dim)">// set offset and click PROBE — try values 1–16 to find the canary</span>`;

/* ══════════════════════════════════════════════
   4 · LIVE CANARY VALIDATOR
══════════════════════════════════════════════ */
function validateCanary() {
  const raw = document.getElementById('canary-inp').value.trim();
  const el  = document.getElementById('canary-result');
  if (!raw) { el.innerHTML = ''; return; }
  try {
    const v   = BigInt(raw);
    const lsb = Number(v & BigInt(0xff));
    if (lsb === 0) {
      el.innerHTML = `<span style="color:var(--accent)">✓ VALID CANARY — LSB = 0x00 confirmed. Value: ${raw}</span>`;
    } else {
      el.innerHTML = `<span style="color:var(--accent2)">✗ NOT A CANARY — LSB = 0x${lsb.toString(16).padStart(2,'0')} (expected 0x00). Try a different offset.</span>`;
    }
  } catch {
    el.innerHTML = `<span style="color:var(--accent2)">✗ Invalid hex — format: 0x3a88f4c2e1f20d00</span>`;
  }
}

/* ══════════════════════════════════════════════
   5 · PAYLOAD BUILDER
══════════════════════════════════════════════ */
function buildPayload() {
  const canStr = document.getElementById('pb-canary').value.trim();
  const winStr = document.getElementById('pb-win').value.trim();
  const el     = document.getElementById('pb-result');
  if (!canStr && !winStr) { el.innerHTML = ''; return; }

  try {
    const canary  = BigInt(canStr || '0x0');
    const winAddr = BigInt(winStr || '0x0');
    const lsb     = Number(canary & BigInt(0xff));

    const canHex = '0x' + canary.toString(16).padStart(16,'0');
    const winHex = '0x' + winAddr.toString(16).padStart(16,'0');

    const warn = lsb !== 0
      ? `<div style="color:var(--accent2);font-size:0.68rem;margin-bottom:0.4rem;">[!] Canary LSB ≠ 0x00 — double-check your leak offset.</div>`
      : '';

    el.innerHTML = `${warn}
      <div style="color:var(--text-dim);">payload layout (${80} bytes total → RIP):</div>
      <div style="margin-top:0.3rem;">
        <span style="color:var(--text-dim);">[</span><span style="color:var(--text-hi);">'A' × 64</span><span style="color:var(--text-dim);">]</span>
        <span style="color:var(--text-dim);"> + </span>
        <span style="color:var(--text-dim);">[</span><span style="color:var(--accent)">${canHex}</span><span style="color:var(--text-dim);"> (canary)]</span>
        <span style="color:var(--text-dim);"> + </span>
        <span style="color:var(--text-dim);">[</span><span style="color:var(--accent3)">0x0000000000000000</span><span style="color:var(--text-dim);"> (rbp)]</span>
        <span style="color:var(--text-dim);"> + </span>
        <span style="color:var(--text-dim);">[</span><span style="color:var(--accent2)">${winHex}</span><span style="color:var(--text-dim);"> (RIP→win())]</span>
      </div>
      <div style="color:var(--accent3);margin-top:0.4rem;font-size:0.68rem;">→ total payload length: 80 bytes</div>`;
  } catch {
    el.innerHTML = `<span style="color:var(--accent2)">Invalid hex — use format 0x…</span>`;
  }
}

/* ══════════════════════════════════════════════
   6 · ACCORDION CARDS
══════════════════════════════════════════════ */
function toggleCard(id) {
  document.getElementById(id).classList.toggle('open');
}

/* ══════════════════════════════════════════════
   7 · HINTS
══════════════════════════════════════════════ */
function revealHint(id) {
  document.getElementById(id).classList.toggle('revealed');
}

/* ══════════════════════════════════════════════
   8 · COPY EXPLOIT BUTTON
══════════════════════════════════════════════ */
function copyExploit() {
  const pre  = document.getElementById('exploit-code');
  const text = pre.innerText || pre.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('[onclick="copyExploit()"]');
    const orig = btn.textContent;
    btn.textContent = 'COPIED!';
    btn.style.color = 'var(--accent)';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
  });
}

/* ══════════════════════════════════════════════
   9 · FLAG SUBMISSION
══════════════════════════════════════════════ */
function submitFlag() {
  const raw  = document.getElementById('flag-input').value.trim();
  const user = document.getElementById('inp-user').value.trim() || 'anonymous';
  const res  = document.getElementById('flag-result');

  const submitted = raw.startsWith('FlagVault{') ? raw : `FlagVault{${raw}}`;

  if (submitted === _FLAG) {
    res.className = 'submit-result correct';
    res.innerHTML = `✓ CORRECT — Canary bypassed, ${escH(user)}! Stack smashed safely.<br>
      <span style="font-size:0.72em;color:var(--text-dim);">+350 pts &nbsp;|&nbsp; ${new Date().toUTCString()}</span>`;
    document.querySelector('.submit-section').style.boxShadow = '0 0 48px rgba(0,232,200,0.22)';
    spawnParticles();
  } else {
    res.className = 'submit-result incorrect';
    res.innerHTML = `✗ INCORRECT — Canary still guarding. Check your leak and payload layout.`;
    document.querySelector('.submit-section').style.boxShadow = '0 0 24px rgba(255,45,107,0.18)';
    setTimeout(() => { document.querySelector('.submit-section').style.boxShadow = ''; }, 1500);
  }
}

function escH(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ══════════════════════════════════════════════
   10 · VICTORY PARTICLES
══════════════════════════════════════════════ */
function spawnParticles() {
  const cols = ['#00e8c8','#ff2d6b','#f5a623','#7c3aed','#3498db'];
  for (let i = 0; i < 36; i++) {
    const p  = document.createElement('div');
    const tx = (Math.random() - 0.5) * 300;
    const ty = -(90 + Math.random() * 160);
    p.style.cssText = `
      position:fixed;
      left:${30+Math.random()*40}%;
      top:${55+Math.random()*25}%;
      width:7px;height:7px;border-radius:50%;
      background:${cols[Math.floor(Math.random()*cols.length)]};
      pointer-events:none;z-index:10000;
      animation:pf_cw ${0.7+Math.random()*1.3}s ease-out forwards;
      --tx:${tx}px;--ty:${ty}px;
    `;
    document.body.appendChild(p);
    setTimeout(() => p.remove(), 2400);
  }
}
const _pStyle = document.createElement('style');
_pStyle.textContent = `@keyframes pf_cw{
  0%  {opacity:1;transform:translate(0,0) scale(1.1);}
  100%{opacity:0;transform:translate(var(--tx),var(--ty)) scale(0.2);}
}`;
document.head.appendChild(_pStyle);

/* ══════════════════════════════════════════════
   11 · SOLVERS LEADERBOARD
══════════════════════════════════════════════ */
const SOLVERS = [
  { name: 'fmt_str_fury',    time: '1h ago',  pts: 350 },
  { name: 'c4n4ry_k1ll3r',  time: '2h ago',  pts: 350 },
  { name: 'st4ck_wh1sp3r',  time: '4h ago',  pts: 330 },
  { name: 'null_byte_n1nj4', time: '6h ago',  pts: 320 },
  { name: 'rbp_sm4sh3r',    time: '8h ago',  pts: 310 },
  { name: 'printf_p0is0n',  time: '11h ago', pts: 300 },
];

const solEl = document.getElementById('solvers-list');
SOLVERS.forEach((s, i) => {
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:0.7rem 1.2rem;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:0.73rem;transition:background 0.18s;cursor:default;';
  row.onmouseenter = () => row.style.background = 'var(--surface2)';
  row.onmouseleave = () => row.style.background = '';
  row.innerHTML = `
    <span style="color:var(--text-dim);min-width:22px;">#${i+1}</span>
    <span style="color:var(--text-hi);flex:1;padding:0 0.6rem;">${s.name}</span>
    <span style="color:var(--text-dim);font-size:0.65rem;">${s.time}</span>
    <span style="color:var(--accent3);min-width:40px;text-align:right;">+${s.pts}</span>`;
  solEl.appendChild(row);
});

/* ══════════════════════════════════════════════
   12 · RESPONSIVE LAYOUT
══════════════════════════════════════════════ */
function doResize() {
  const l = document.getElementById('main-layout');
  if (l) l.style.gridTemplateColumns = window.innerWidth < 900 ? '1fr' : '1fr 360px';
}
window.addEventListener('resize', doResize);
doResize();
