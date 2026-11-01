/* Sundarabahu - login, sign-up, password reset and admin activity log.
   Cloudflare Worker. Storage: one KV namespace bound as DB.
   Secrets (set in the Cloudflare dashboard): ADMIN_PASSWORD  (required)
   Variables: ADMIN_USER (optional, default "sundarabahuadmin")                 */

const COOKIE = 'sb_session';
const PBKDF2_ITER = 100000;               // Workers' maximum
const enc = new TextEncoder();

/* ---------- small helpers ---------- */
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const json = (o, status = 200, headers = {}) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
const html = (s, status = 200) => new Response(s, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
const adminName = (env) => (env.ADMIN_USER || 'sundarabahuadmin').toLowerCase();

function timingEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function sha256(s) { return b64u(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64u(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, k, 256));
}
async function hmacKey(env) {
  return crypto.subtle.importKey('raw', enc.encode('sb|' + (env.SESSION_SECRET || env.ADMIN_PASSWORD || 'unset')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function makeToken(env, u, r, ttlSec) {
  const payload = b64u(enc.encode(JSON.stringify({ u, r, e: Date.now() + ttlSec * 1000 })));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload)));
  return payload + '.' + sig;
}
function cookieOf(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
async function getSession(req, env) {
  const tok = cookieOf(req, COOKIE);
  if (!tok || !env.DB) return null;
  const [payload, sig] = tok.split('.');
  if (!payload || !sig) return null;
  const good = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload)));
  if (!timingEq(good, sig)) return null;
  let d;
  try { d = JSON.parse(new TextDecoder().decode(unb64u(payload))); } catch { return null; }
  if (!d || d.e < Date.now()) return null;
  if (d.r === 'admin') return d.u === adminName(env) ? d : null;
  const u = await env.DB.get('u:' + d.u, 'json');
  if (!u || u.disabled) return null;
  return d;
}
const setCookie = (tok, maxAge) => `${COOKIE}=${tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;

function browserOf(req) {
  const ua = req.headers.get('user-agent') || '';
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Other';
  const o = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return b + (o ? ' / ' + o : '');
}
async function logEvent(env, req, type, user, note) {
  const ts = Date.now(), cf = req.cf || {};
  const key = 'l:' + String(9999999999999 - ts).padStart(13, '0') + '-' + Math.random().toString(36).slice(2, 6);
  await env.DB.put(key, '1', {
    metadata: { t: ts, u: user || '', e: type, c: cf.country || '', city: cf.city || '', b: browserOf(req), n: note || '' },
    expirationTtl: 60 * 60 * 24 * 400
  });
}
async function throttle(env, key, limit) {          // returns true if blocked
  const n = parseInt((await env.DB.get('f:' + key)) || '0', 10);
  return n >= limit;
}
async function bumpFail(env, key) {
  const n = parseInt((await env.DB.get('f:' + key)) || '0', 10) + 1;
  await env.DB.put('f:' + key, String(n), { expirationTtl: 900 });
}
const clearFail = (env, key) => env.DB.delete('f:' + key);

const validUser = (u) => /^[a-z0-9_.]{3,24}$/.test(u);

/* ---------- API ---------- */
async function api(req, env, url, p) {
  if (!env.DB) return json({ error: 'Server not configured: KV binding "DB" is missing.' }, 500);
  const isPost = req.method === 'POST';
  if (isPost && !(req.headers.get('content-type') || '').includes('application/json')) return json({ error: 'bad request' }, 400);
  const body = isPost ? await req.json().catch(() => ({})) : {};
  const ADMIN = adminName(env);

  if (p === '/api/me') {
    const s = await getSession(req, env);
    return json(s ? { user: s.u, role: s.r } : { user: null });
  }

  if (p === '/api/signup' && isPost) {
    const u = String(body.username || '').trim().toLowerCase(), pw = String(body.password || '');
    if (!validUser(u)) return json({ error: 'Username must be 3-24 characters: letters, digits, _ or .' }, 400);
    if (u === ADMIN) return json({ error: 'That username is reserved.' }, 409);
    if (pw.length < 8 || pw.length > 100) return json({ error: 'Password must be at least 8 characters.' }, 400);
    if (await env.DB.get('u:' + u)) return json({ error: 'That username is already taken.' }, 409);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const rec = { name: u, salt: b64u(salt), hash: await pbkdf2(pw, salt), created: Date.now(), last: Date.now(), logins: 1, disabled: false };
    await env.DB.put('u:' + u, JSON.stringify(rec));
    await logEvent(env, req, 'signup', u);
    return json({ ok: true, role: 'user' }, 200, { 'set-cookie': setCookie(await makeToken(env, u, 'user', 30 * 86400), 30 * 86400) });
  }

  if (p === '/api/login' && isPost) {
    const u = String(body.username || '').trim().toLowerCase(), pw = String(body.password || '');
    if (!u || !pw) return json({ error: 'Enter username and password.' }, 400);
    if (await throttle(env, u, 8)) { await logEvent(env, req, 'locked', u); return json({ error: 'Too many wrong attempts. Try again in 15 minutes.' }, 429); }
    if (u === ADMIN) {
      if (!env.ADMIN_PASSWORD) return json({ error: 'Admin password is not configured on the server.' }, 500);
      const ok = timingEq(await sha256(pw), await sha256(env.ADMIN_PASSWORD));
      if (!ok) { await bumpFail(env, u); await logEvent(env, req, 'login_failed', u); return json({ error: 'Wrong username or password.' }, 401); }
      await clearFail(env, u);
      await logEvent(env, req, 'admin_login', u);
      return json({ ok: true, role: 'admin' }, 200, { 'set-cookie': setCookie(await makeToken(env, u, 'admin', 12 * 3600), 12 * 3600) });
    }
    const rec = await env.DB.get('u:' + u, 'json');
    const good = rec && timingEq(await pbkdf2(pw, unb64u(rec.salt)), rec.hash);
    if (!good) { await bumpFail(env, u); await logEvent(env, req, 'login_failed', u); return json({ error: 'Wrong username or password.' }, 401); }
    if (rec.disabled) { await logEvent(env, req, 'login_blocked', u); return json({ error: 'This account has been disabled. Please contact the administrator.' }, 403); }
    await clearFail(env, u);
    rec.last = Date.now(); rec.logins = (rec.logins || 0) + 1;
    await env.DB.put('u:' + u, JSON.stringify(rec));
    await logEvent(env, req, 'login', u);
    return json({ ok: true, role: 'user' }, 200, { 'set-cookie': setCookie(await makeToken(env, u, 'user', 30 * 86400), 30 * 86400) });
  }

  if (p === '/api/logout' && isPost) {
    const s = await getSession(req, env);
    if (s) await logEvent(env, req, 'logout', s.u);
    return json({ ok: true }, 200, { 'set-cookie': setCookie('', 0) });
  }

  if (p === '/api/reset' && isPost) {              // friend uses the admin-issued code
    const u = String(body.username || '').trim().toLowerCase(), code = String(body.code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, ''), pw = String(body.password || '');
    if (pw.length < 8 || pw.length > 100) return json({ error: 'New password must be at least 8 characters.' }, 400);
    if (await throttle(env, 'r:' + u, 6)) return json({ error: 'Too many attempts. Try again later.' }, 429);
    const rec = await env.DB.get('u:' + u, 'json'), r = await env.DB.get('r:' + u, 'json');
    if (!rec || !r || r.exp < Date.now() || !timingEq(await sha256(code), r.h)) {
      await bumpFail(env, 'r:' + u); await logEvent(env, req, 'reset_failed', u);
      return json({ error: 'Invalid or expired reset code. Ask the administrator for a new one.' }, 400);
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    rec.salt = b64u(salt); rec.hash = await pbkdf2(pw, salt); rec.last = Date.now(); rec.logins = (rec.logins || 0) + 1;
    await env.DB.put('u:' + u, JSON.stringify(rec));
    await env.DB.delete('r:' + u); await clearFail(env, u); await clearFail(env, 'r:' + u);
    await logEvent(env, req, 'password_reset', u);
    return json({ ok: true, role: 'user' }, 200, { 'set-cookie': setCookie(await makeToken(env, u, 'user', 30 * 86400), 30 * 86400) });
  }

  /* ----- admin only ----- */
  if (p.startsWith('/api/admin/')) {
    const s = await getSession(req, env);
    if (!s || s.r !== 'admin') return json({ error: 'forbidden' }, 403);

    if (p === '/api/admin/users') {
      const out = []; let cursor;
      do {
        const l = await env.DB.list({ prefix: 'u:', cursor, limit: 1000 });
        for (const k of l.keys) {
          const r = await env.DB.get(k.name, 'json');
          if (r) out.push({ user: r.name, created: r.created, last: r.last, logins: r.logins || 0, disabled: !!r.disabled });
        }
        cursor = l.list_complete ? null : l.cursor;
      } while (cursor);
      out.sort((a, b) => b.created - a.created);
      return json({ users: out });
    }
    if (p === '/api/admin/log') {
      const want = Math.min(parseInt(url.searchParams.get('limit') || '500', 10) || 500, 5000);
      const out = []; let cursor;
      do {
        const l = await env.DB.list({ prefix: 'l:', cursor, limit: Math.min(1000, want - out.length) });
        for (const k of l.keys) if (k.metadata) out.push(k.metadata);
        cursor = l.list_complete ? null : l.cursor;
      } while (cursor && out.length < want);
      return json({ log: out });
    }
    const target = String(body.user || '').trim().toLowerCase();
    if (p === '/api/admin/reset-code' && isPost) {
      const rec = await env.DB.get('u:' + target, 'json');
      if (!rec) return json({ error: 'No such user.' }, 404);
      const alpha = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789', bytes = crypto.getRandomValues(new Uint8Array(8));
      const code = Array.from(bytes, (b) => alpha[b % alpha.length]).join('');
      await env.DB.put('r:' + target, JSON.stringify({ h: await sha256(code), exp: Date.now() + 24 * 3600 * 1000 }), { expirationTtl: 86400 });
      await logEvent(env, req, 'reset_code_issued', target, 'by admin');
      return json({ code: code.slice(0, 4) + '-' + code.slice(4), hours: 24 });
    }
    if (p === '/api/admin/disable' && isPost) {
      const rec = await env.DB.get('u:' + target, 'json');
      if (!rec) return json({ error: 'No such user.' }, 404);
      rec.disabled = !!body.disabled;
      await env.DB.put('u:' + target, JSON.stringify(rec));
      await logEvent(env, req, rec.disabled ? 'account_disabled' : 'account_enabled', target, 'by admin');
      return json({ ok: true });
    }
    if (p === '/api/admin/delete' && isPost) {
      await env.DB.delete('u:' + target); await env.DB.delete('r:' + target);
      await logEvent(env, req, 'account_deleted', target, 'by admin');
      return json({ ok: true });
    }
  }
  return json({ error: 'not found' }, 404);
}

/* ---------- pages ---------- */
const BASE_CSS = `*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#0c1b26;color:#e6edf3}
button,input,select{font:inherit}input{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #2c4357;background:#102535;color:#e6edf3;margin:5px 0 12px}
input:focus{outline:2px solid #FFD43B;border-color:transparent}button.pri{width:100%;padding:12px;border:0;border-radius:9px;background:#FFD43B;color:#1b1b1b;font-weight:700;cursor:pointer}
button.pri:disabled{opacity:.6}.err{color:#ff9b9b;min-height:20px;font-size:14px;margin:2px 0 10px}.ok{color:#63e6be}.mut{color:#8c96a0;font-size:13px}`;

const LOGIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sundarabahu - Sign in</title><style>${BASE_CSS}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:radial-gradient(1200px 600px at 20% -10%,#17405a 0%,#0c1b26 55%)}
.card{width:100%;max-width:400px;background:#0f2231;border:1px solid #23394c;border-radius:16px;padding:26px 24px;box-shadow:0 20px 50px rgba(0,0,0,.4)}
h1{margin:0 0 2px;font-size:24px;color:#FFD43B}.sub{margin:0 0 18px;color:#9fb3c3;font-size:14px}
.tabs{display:flex;gap:6px;margin-bottom:16px}.tabs button{flex:1;padding:9px 4px;border-radius:8px;border:1px solid #2c4357;background:transparent;color:#cbd5df;cursor:pointer}
.tabs button.on{background:#1b3b52;border-color:#FFD43B;color:#fff}.lang{position:absolute;top:14px;right:14px}.lang button{background:#102535;border:1px solid #2c4357;color:#cbd5df;border-radius:8px;padding:6px 10px;cursor:pointer}
.pw{position:relative}.pw input{padding-right:78px}.pw .eye{position:absolute;right:5px;top:5px;bottom:12px;width:68px;border:0;border-radius:7px;background:#1b3b52;color:#e6edf3;cursor:pointer;font-size:13px}.pw .eye:hover{background:#25506d}
a{color:#74c0fc;cursor:pointer}</style></head><body>
<div class="lang"><button id="lg">தமிழ்</button></div>
<div class="card"><h1>Sundarabahu</h1><p class="sub" id="sub">Class 12 Physics learning companion</p>
<div class="tabs"><button id="t1" class="on"></button><button id="t2"></button><button id="t3"></button></div>
<form id="f" autocomplete="on"><div id="fields"></div><div class="err" id="err" role="alert"></div><button class="pri" id="go" type="submit"></button></form>
<p class="mut" id="hint" style="margin-top:14px"></p></div>
<script>
var T={en:{sub:'Class 12 Physics learning companion',in:'Sign in',up:'Sign up',fg:'Forgot password',user:'Username',pw:'Password',pw2:'Confirm password',code:'Reset code (from administrator)',npw:'New password',
 go_in:'Sign in',go_up:'Create account',go_fg:'Set new password',hup:'Pick any username (3-24 letters, digits, _ or .) and a password of at least 8 characters.',
 hfg:'Ask the administrator for a reset code, then enter it here with a new password.',hin:'',mism:'Passwords do not match.',wait:'Please wait...',net:'Network error. Please try again.',show:'Show',hide:'Hide'},
 ta:{sub:'12-ஆம் வகுப்பு இயற்பியல் கற்றல் துணை',in:'உள்நுழை',up:'பதிவு செய்',fg:'கடவுச்சொல் மறந்தேன்',user:'பயனர் பெயர்',pw:'கடவுச்சொல்',pw2:'கடவுச்சொல்லை உறுதிசெய்',code:'மீட்டமைப்புக் குறியீடு (நிர்வாகியிடமிருந்து)',npw:'புதிய கடவுச்சொல்',
 go_in:'உள்நுழை',go_up:'கணக்கை உருவாக்கு',go_fg:'புதிய கடவுச்சொல்லை அமை',hup:'விரும்பிய பயனர் பெயரையும் (3-24 எழுத்து/இலக்கம்/_/.) குறைந்தது 8 எழுத்துக் கடவுச்சொல்லையும் தேர்க.',
 hfg:'நிர்வாகியிடம் மீட்டமைப்புக் குறியீடு பெற்று, புதிய கடவுச்சொல்லுடன் இங்கே உள்ளிடுக.',hin:'',mism:'கடவுச்சொற்கள் பொருந்தவில்லை.',wait:'காத்திருக்கவும்...',net:'இணையப் பிழை. மீண்டும் முயலுக.',show:'காட்டு',hide:'மறை'}};
var lang=localStorage.getItem('sb_lang')||'en',mode='in',$=function(i){return document.getElementById(i)};
function fld(id,label,type,ac){var i='<input id="'+id+'" type="'+type+'" autocomplete="'+ac+'" required>';
 if(type==='password')i='<div class="pw">'+i+'<button type="button" class="eye" data-for="'+id+'" aria-label="'+T[lang].show+'">\u{1F441} '+T[lang].show+'</button></div>';
 return '<label for="'+id+'" class="mut">'+label+'</label>'+i}
function render(){var t=T[lang];document.documentElement.lang=lang;$('sub').textContent=t.sub;$('t1').textContent=t.in;$('t2').textContent=t.up;$('t3').textContent=t.fg;$('lg').textContent=lang==='en'?'தமிழ்':'English';
 ['t1','t2','t3'].forEach(function(x,i){$(x).className=(['in','up','fg'][i]===mode)?'on':''});
 var h='';if(mode==='in')h=fld('u',t.user,'text','username')+fld('p',t.pw,'password','current-password');
 if(mode==='up')h=fld('u',t.user,'text','username')+fld('p',t.pw,'password','new-password')+fld('p2',t.pw2,'password','new-password');
 if(mode==='fg')h=fld('u',t.user,'text','username')+fld('c',t.code,'text','one-time-code')+fld('p',t.npw,'password','new-password');
 $('fields').innerHTML=h;$('go').textContent=t['go_'+mode];$('hint').textContent=mode==='up'?t.hup:mode==='fg'?t.hfg:'';$('err').textContent='';localStorage.setItem('sb_lang',lang)}
$('fields').addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.eye');if(!b)return;var i=$(b.getAttribute('data-for')),t=T[lang],h=i.type==='password';i.type=h?'text':'password';b.textContent='\u{1F441} '+(h?t.hide:t.show);b.setAttribute('aria-label',h?t.hide:t.show)});
$('lg').onclick=function(e){e.preventDefault();lang=lang==='en'?'ta':'en';render()};
['t1','t2','t3'].forEach(function(x,i){$(x).onclick=function(){mode=['in','up','fg'][i];render()}});
$('f').onsubmit=function(e){e.preventDefault();var t=T[lang],b={username:$('u').value},url='/api/login';
 if(mode==='up'){if($('p').value!==$('p2').value){$('err').textContent=t.mism;return}b.password=$('p').value;url='/api/signup'}
 else if(mode==='fg'){b.code=$('c').value;b.password=$('p').value;url='/api/reset'}else b.password=$('p').value;
 $('go').disabled=true;$('err').className='err ok';$('err').textContent=t.wait;
 fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().then(function(j){return [r.ok,j]})}).then(function(a){
  if(a[0]){location.href=a[1].role==='admin'?'/admin':'/'}else{$('err').className='err';$('err').textContent=a[1].error||'Error';$('go').disabled=false}
 }).catch(function(){$('err').className='err';$('err').textContent=t.net;$('go').disabled=false})};
render();
</script></body></html>`;

const ADMIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sundarabahu - Admin</title><style>${BASE_CSS}
body{padding:16px;max-width:1100px;margin:0 auto}h1{color:#FFD43B;margin:6px 0 2px}.top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.top a,.top button{color:#cbd5df;background:#102535;border:1px solid #2c4357;border-radius:8px;padding:7px 12px;text-decoration:none;cursor:pointer}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}.c{background:#0f2231;border:1px solid #23394c;border-radius:12px;padding:12px}.c b{font-size:26px;color:#FFD43B;display:block}
.tabs{display:flex;gap:6px;margin:10px 0}.tabs button{padding:9px 16px;border-radius:8px;border:1px solid #2c4357;background:transparent;color:#cbd5df;cursor:pointer}.tabs .on{background:#1b3b52;border-color:#FFD43B;color:#fff}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}.tools input,.tools select{width:auto;margin:0;padding:8px}.tools input{min-width:170px}
.wrap{overflow:auto;border:1px solid #23394c;border-radius:12px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:9px 11px;text-align:left;border-bottom:1px solid #1a3043;white-space:nowrap}
th{background:#12293b;position:sticky;top:0}tr:hover td{background:#10283a}.tag{padding:2px 8px;border-radius:99px;font-size:12px;background:#1b3b52}
.sg{background:#1e4d3b}.li{background:#1b3b52}.bad{background:#5a2330}.rs{background:#5a4a14}.row button{margin-right:5px;padding:5px 9px;border-radius:7px;border:1px solid #2c4357;background:#102535;color:#e6edf3;cursor:pointer}
.row .d{border-color:#7a3340;color:#ff9b9b}#toast{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:#FFD43B;color:#111;padding:12px 18px;border-radius:10px;font-weight:600;display:none;max-width:90vw;text-align:center}</style></head><body>
<div class="top"><div><h1>Sundarabahu - Admin</h1><div class="mut">Accounts and activity (times shown in IST)</div></div>
<div><a href="/">Open the app</a> <button id="rf">Refresh</button> <button id="lo">Log out</button></div></div>
<div class="cards"><div class="c"><b id="n1">-</b>registered users</div><div class="c"><b id="n2">-</b>sign-ups today</div><div class="c"><b id="n3">-</b>sign-ins today</div><div class="c"><b id="n4">-</b>failed attempts today</div></div>
<div class="tabs"><button id="b1" class="on">Activity log</button><button id="b2">Users</button></div>
<div id="p1"><div class="tools"><input id="q" placeholder="Filter by username..."><select id="ev"><option value="">All events</option></select><button id="csv" class="pri" style="width:auto;padding:8px 14px">Download CSV</button></div>
<div class="wrap" style="max-height:62vh"><table><thead><tr><th>When (IST)</th><th>Username</th><th>Event</th><th>Place</th><th>Device</th><th>Note</th></tr></thead><tbody id="lg"></tbody></table></div><div class="mut" id="lc" style="margin-top:6px"></div></div>
<div id="p2" style="display:none"><div class="wrap"><table><thead><tr><th>Username</th><th>Signed up</th><th>Last sign-in</th><th>Sign-ins</th><th>Status</th><th>Actions</th></tr></thead><tbody id="us"></tbody></table></div></div>
<div id="toast"></div>
<script>
var LOG=[],US=[],$=function(i){return document.getElementById(i)};
var NAMES={signup:'Signed up',login:'Signed in',admin_login:'Admin sign-in',logout:'Signed out',login_failed:'Wrong password',locked:'Locked (too many tries)',login_blocked:'Blocked (disabled)',reset_code_issued:'Reset code issued',password_reset:'Password reset',reset_failed:'Reset failed',account_disabled:'Account disabled',account_enabled:'Account enabled',account_deleted:'Account deleted'};
var CLS={signup:'sg',login:'li',admin_login:'li',login_failed:'bad',locked:'bad',login_blocked:'bad',reset_failed:'bad',reset_code_issued:'rs',password_reset:'rs',account_deleted:'bad',account_disabled:'bad'};
function ist(t){return t?new Date(t).toLocaleString('en-IN',{timeZone:'Asia/Kolkata',day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:true}):'-'}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function toast(m,ms){var t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(toast.h);toast.h=setTimeout(function(){t.style.display='none'},ms||3500)}
function api(u,b){return fetch(u,b?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}:{}).then(function(r){if(r.status===403){location.href='/';throw 0}return r.json()})}
function dayKey(t){return new Date(t).toLocaleDateString('en-CA',{timeZone:'Asia/Kolkata'})}
function stats(){var today=dayKey(Date.now()),s=0,i=0,f=0;LOG.forEach(function(l){if(dayKey(l.t)!==today)return;if(l.e==='signup')s++;if(l.e==='login'||l.e==='admin_login')i++;if(l.e==='login_failed'||l.e==='locked')f++});
 $('n1').textContent=US.length;$('n2').textContent=s;$('n3').textContent=i;$('n4').textContent=f}
function drawLog(){var q=$('q').value.trim().toLowerCase(),ev=$('ev').value,rows=LOG.filter(function(l){return (!q||(l.u||'').toLowerCase().indexOf(q)>=0)&&(!ev||l.e===ev)});
 $('lg').innerHTML=rows.map(function(l){return '<tr><td>'+ist(l.t)+'</td><td>'+esc(l.u)+'</td><td><span class="tag '+(CLS[l.e]||'')+'">'+esc(NAMES[l.e]||l.e)+'</span></td><td>'+esc([l.city,l.c].filter(Boolean).join(', ')||'-')+'</td><td>'+esc(l.b)+'</td><td>'+esc(l.n)+'</td></tr>'}).join('')||'<tr><td colspan="6" class="mut">No activity yet.</td></tr>';
 $('lc').textContent=rows.length+' of '+LOG.length+' events shown (latest 1000 loaded)'}
function drawUsers(){$('us').innerHTML=US.map(function(u){return '<tr class="row"><td><b>'+esc(u.user)+'</b></td><td>'+ist(u.created)+'</td><td>'+ist(u.last)+'</td><td>'+u.logins+'</td><td>'+(u.disabled?'<span class="tag bad">disabled</span>':'<span class="tag sg">active</span>')+'</td><td>'
 +'<button data-a="rs" data-u="'+esc(u.user)+'">Reset code</button><button data-a="ds" data-u="'+esc(u.user)+'">'+(u.disabled?'Enable':'Disable')+'</button><button class="d" data-a="rm" data-u="'+esc(u.user)+'">Delete</button></td></tr>'}).join('')||'<tr><td colspan="6" class="mut">No users yet.</td></tr>'}
function load(){return Promise.all([api('/api/admin/log?limit=1000'),api('/api/admin/users')]).then(function(r){LOG=r[0].log;US=r[1].users;
 var seen={};LOG.forEach(function(l){seen[l.e]=1});var cur=$('ev').value;$('ev').innerHTML='<option value="">All events</option>'+Object.keys(NAMES).filter(function(k){return seen[k]}).map(function(k){return '<option value="'+k+'">'+NAMES[k]+'</option>'}).join('');$('ev').value=cur;stats();drawLog();drawUsers()}).catch(function(){})}
$('us').onclick=function(e){var b=e.target.closest('button');if(!b)return;var u=b.dataset.u,a=b.dataset.a;
 if(a==='rs')api('/api/admin/reset-code',{user:u}).then(function(r){if(r.code){prompt('One-time reset code for '+u+' (valid '+r.hours+' h). Give it to them; they use "Forgot password" on the sign-in page.',r.code);load()}else toast(r.error)});
 if(a==='ds'){var u2=US.filter(function(x){return x.user===u})[0];api('/api/admin/disable',{user:u,disabled:!u2.disabled}).then(function(){load()})}
 if(a==='rm'&&confirm('Delete account "'+u+'"? This cannot be undone.'))api('/api/admin/delete',{user:u}).then(function(){load()})};
$('b1').onclick=function(){$('b1').className='on';$('b2').className='';$('p1').style.display='';$('p2').style.display='none'};
$('b2').onclick=function(){$('b2').className='on';$('b1').className='';$('p2').style.display='';$('p1').style.display='none'};
$('q').oninput=drawLog;$('ev').onchange=drawLog;$('rf').onclick=function(){load().then(function(){toast('Refreshed',1200)})};
$('lo').onclick=function(){api('/api/logout',{}).then(function(){location.href='/'})};
$('csv').onclick=function(){var rows=[['when_ist','username','event','city','country','device','note']].concat(LOG.map(function(l){return [ist(l.t),l.u,NAMES[l.e]||l.e,l.city,l.c,l.b,l.n]}));
 var s=rows.map(function(r){return r.map(function(c){return '"'+String(c==null?'':c).replace(/"/g,'""')+'"'}).join(',')}).join('\\n'),a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\\ufeff'+s],{type:'text/csv'}));a.download='sundarabahu-activity.csv';a.click()};
load();setInterval(load,30000);
</script></body></html>`;

const SETUP_HTML = (msg) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setup needed</title><style>${BASE_CSS}body{padding:30px;max-width:640px;margin:auto}</style><h2 style="color:#FFD43B">Server setup needed</h2><p>${msg}</p><p class="mut">See README-SETUP.txt in the deploy folder.</p>`;

function bar(user, role) {
  const link = role === 'admin' ? '<a href="/admin" style="color:#FFD43B;margin-right:8px">Admin</a>' : '';
  return `<div id="sbBar" style="position:fixed;left:8px;bottom:8px;z-index:2147483000;background:rgba(12,27,38,.88);color:#cbd5df;border:1px solid #2c4357;border-radius:99px;padding:5px 6px 5px 11px;font:12px system-ui,sans-serif;display:flex;align-items:center;gap:6px;backdrop-filter:blur(4px)">
<span>&#128100; ${user}</span>${link}<button onclick="fetch('/api/logout',{method:'POST',headers:{'content-type':'application/json'},body:'{}'}).then(function(){location.href='/'})" style="background:#FFD43B;color:#111;border:0;border-radius:99px;padding:4px 10px;font:600 12px system-ui;cursor:pointer">Log out</button>
<button onclick="document.getElementById('sbBar').style.display='none'" title="hide" style="background:none;border:0;color:#8c96a0;cursor:pointer;font-size:14px">&times;</button></div>`;
}

/* ---------- entry ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname;
    if (!env.DB) return html(SETUP_HTML('The KV namespace binding named <b>DB</b> is missing.'), 500);
    if (p.startsWith('/api/')) {
      try { return await api(req, env, url, p); } catch (e) { return json({ error: 'Server error' }, 500); }
    }
    const s = await getSession(req, env);
    if (p === '/admin') return s && s.r === 'admin' ? html(ADMIN_HTML) : Response.redirect(url.origin + '/', 302);
    if (!s) return html(LOGIN_HTML);
    const res = await env.ASSETS.fetch(req);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('text/html')) return res;
    const out = new HTMLRewriter().on('body', { element(el) { el.append(bar(s.u, s.r), { html: true }); } }).transform(res);
    const h = new Headers(out.headers); h.set('cache-control', 'private, no-store');
    return new Response(out.body, { status: out.status, headers: h });
  }
};
