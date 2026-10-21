"""Report writers: HTML dashboard, JSON, CSV."""
from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime

from . import __version__
from .model import SEVERITIES, WEIGHT, Context
from .playbook import advice


def summary(ctx: Context) -> dict:
    user = [s["privacy"] for n, s in ctx.scores.items() if not ctx.packages.get(n, {}).get("system")]
    top = sorted(user, reverse=True)[:10]
    privacy = int(0.6 * top[0] + 0.4 * sum(top) / len(top)) if top else 0
    sec = min(100, sum(WEIGHT[f.severity] for f in ctx.findings if f.category in ("SECURITY", "MALWARE")))
    return {
        "privacyRisk": min(privacy, 100),
        "securityRisk": sec,
        "suspicious": sum(1 for f in ctx.findings if f.category == "SUSPICIOUS" and f.severity in ("MEDIUM", "HIGH", "CRITICAL")),
        "unknownBinaries": ctx.unknown,
        "malware": sorted({f.package or "(device)" for f in ctx.findings if f.category == "MALWARE"}),
        "bySeverity": {s: sum(1 for f in ctx.findings if f.severity == s) for s in SEVERITIES},
    }


def to_json(ctx: Context) -> dict:
    manifest = ctx.ev.json("manifest.json", {}) or {}
    apps = []
    for n, p in sorted(ctx.packages.items()):
        r = ctx.apk_reports.get(n, {})
        v = ctx.vt.get(p.get("apkSha256") or "")
        apps.append({
            "package": n, "label": p.get("label"), "version": p.get("versionName"), "installer": p.get("installer"),
            "system": p.get("system"), "sideloaded": ctx.is_sideloaded(n), "launcher": p.get("hasLauncher"),
            "firstInstall": p.get("firstInstall"), "lastUpdate": p.get("lastUpdate"), "sha256": p.get("apkSha256"),
            "signer": (p.get("certSha256") or [None])[0], "signerSubject": (p.get("certSubjects") or [None])[0],
            "privacy": ctx.scores.get(n, {}).get("privacy", 0), "security": ctx.scores.get(n, {}).get("security", 0),
            "vt": None if not v else (f"{v['malicious']}/{v['total']}" if v["malicious"] >= 0 else "unknown"),
            "vtLabel": v.get("label") if v else None,
            "granted": sorted(x.rsplit(".", 1)[-1] for x in p.get("granted", []) if x.startswith("android.permission.")),
            "trackers": r.get("trackers", []), "hosts": r.get("hosts", [])[:40], "payloads": r.get("payloads", []),
            "dns": (ctx.network.get("dns_per_app") or {}).get(n, {}),
        })
    findings = []
    for f in ctx.findings:
        d = f.to_dict()
        d["advice"] = advice(f.id)
        prev = getattr(ctx, "prev_keys", None)
        d["new"] = prev is not None and f.key() not in prev
        findings.append(d)
    tl = sorted((e.__dict__ for e in ctx.timeline), key=lambda e: e["ts"], reverse=True)[:3000]
    return {
        "tool": "droidtriage", "version": __version__, "generated": datetime.now().isoformat(timespec="seconds"),
        "evidence": os.path.basename(ctx.ev.path), "collection": {k: manifest.get(k) for k in ("device", "startedAt", "capabilities", "sections")},
        "summary": summary(ctx), "coverage": ctx.coverage, "findings": findings, "apps": apps, "timeline": tl,
        "device": {k: v for k, v in ctx.device.items() if k not in ("settings",)},
        "enabled": {k: (sorted(v) if isinstance(v, set) else v) for k, v in ctx.enabled.items()},
        "network": ctx.network, "logHits": ctx.log_hits,
        "iocSources": ctx.iocs.sources, "iocCount": len(ctx.iocs),
    }


def write_all(ctx: Context, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    data = to_json(ctx)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, default=str)
    with open(os.path.join(out_dir, "findings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "category", "package", "title", "detail", "mitre", "source", "advice"])
        for f in data["findings"]:
            w.writerow([f["severity"], f["category"], f["package"] or "", f["title"], f["detail"], f["mitre"] or "", f["source"], f["advice"]])
    with open(os.path.join(out_dir, "apps.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        cols = ["package", "label", "version", "installer", "system", "sideloaded", "launcher", "firstInstall", "privacy", "security", "vt", "sha256", "signer"]
        w.writerow(cols)
        for a in data["apps"]:
            w.writerow([a.get(c) for c in cols])
    with open(os.path.join(out_dir, "timeline.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "severity", "source", "package", "what"])
        for e in data["timeline"]:
            w.writerow([e["ts"], e["severity"], e["source"], e["package"] or "", e["what"]])
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE.replace("__TITLE__", html.escape(data["collection"].get("device") or data["evidence"]))
                 .replace("__DATA__", payload))
    return data


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Droid Triage Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#14181f;--muted:#5d6675;--line:#e3e6eb;--accent:#2563eb;
--crit:#d92d20;--high:#e8590c;--med:#c48a00;--low:#2563eb;--info:#6b7280;--ok:#178a50}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1318;--card:#171c23;--text:#e6eaf0;--muted:#9aa4b2;--line:#29313c;--accent:#5b9dff;
--crit:#ff5a52;--high:#ff8a3d;--med:#f2c94c;--low:#5b9dff;--info:#9aa4b2;--ok:#3ecf8e}}
:root[data-theme="dark"]{--bg:#0f1318;--card:#171c23;--text:#e6eaf0;--muted:#9aa4b2;--line:#29313c;--accent:#5b9dff;
--crit:#ff5a52;--high:#ff8a3d;--med:#f2c94c;--low:#5b9dff;--info:#9aa4b2;--ok:#3ecf8e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:20px 16px 8px;max-width:1280px;margin:auto}h1{margin:0;font-size:22px}h2{font-size:17px;margin:28px 0 10px}
main{max-width:1280px;margin:auto;padding:0 16px 60px}.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:14px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;cursor:pointer}
.tile .v{font-size:30px;font-weight:700}.tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);z-index:5;overflow-x:auto;white-space:nowrap}
nav .in{max-width:1280px;margin:auto;padding:0 16px}nav a{display:inline-block;padding:10px 12px;color:var(--muted);text-decoration:none;font-weight:600}
nav a.on{color:var(--accent);border-bottom:2px solid var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin:10px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--card)}
.sev{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11px;font-weight:700;color:#fff}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med);color:#111}.LOW{background:var(--low)}.INFO{background:var(--info)}
.controls{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0}
button,input,select{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text)}
button.on{background:var(--accent);color:#fff;border-color:var(--accent)}input{min-width:220px}
details{margin-top:4px}summary{cursor:pointer;color:var(--accent)}pre{white-space:pre-wrap;word-break:break-word;font-size:12px;margin:6px 0}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 8px;margin:1px;font-size:11px;color:var(--muted)}
.cov-ok{color:var(--ok)}.cov-bad{color:var(--high)}section{display:none}section.on{display:block}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
</style></head><body>
<header><h1>Droid Triage Report</h1><div class="muted" id="sub"></div><div class="tiles" id="tiles"></div></header>
<nav><div class="in" id="nav"></div></nav>
<main>
<section id="s-findings"></section><section id="s-apps"></section><section id="s-timeline"></section>
<section id="s-network"></section><section id="s-logs"></section><section id="s-device"></section><section id="s-coverage"></section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];const sev=s=>`<span class="sev ${s}">${s}</span>`;
const col=v=>v>=60?'var(--crit)':v>=35?'var(--high)':v>=15?'var(--med)':'var(--ok)';
const S=D.summary;
document.getElementById('sub').textContent=`${D.collection.device||D.evidence} · collected ${D.collection.startedAt||'?'} · analysed ${D.generated} · ${D.iocCount} IOCs loaded`;
const tiles=[['Privacy risk',S.privacyRisk+'/100',col(S.privacyRisk),'apps'],['Security risk',S.securityRisk+'/100',col(S.securityRisk),'findings:SECURITY'],
['Suspicious activity',S.suspicious,S.suspicious?'var(--high)':'var(--ok)','findings:SUSPICIOUS'],['Unknown binaries',S.unknownBinaries.length,S.unknownBinaries.length?'var(--med)':'var(--ok)','findings:UNKNOWN'],
['Malware detected',S.malware.length,S.malware.length?'var(--crit)':'var(--ok)','findings:MALWARE']];
document.getElementById('tiles').innerHTML=tiles.map(t=>`<div class="tile" data-go="${t[3]}"><div class="l">${t[0]}</div><div class="v" style="color:${t[2]}">${t[1]}</div></div>`).join('');
const tabs=[['findings','Findings ('+D.findings.length+')'],['apps','Apps ('+D.apps.length+')'],['timeline','Timeline'],['network','Network'],['logs','Logcat'],['device','Device'],['coverage','Coverage & blind spots']];
document.getElementById('nav').innerHTML=tabs.map(t=>`<a href="#" data-tab="${t[0]}">${t[1]}</a>`).join('');
function show(t){document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id==='s-'+t));document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('on',a.dataset.tab===t))}
document.getElementById('nav').onclick=e=>{const t=e.target.dataset.tab;if(t){e.preventDefault();show(t)}};
document.getElementById('tiles').onclick=e=>{const g=e.target.closest('.tile')?.dataset.go;if(!g)return;const[t,c]=g.split(':');if(c){fCat=c;renderFindings()}show(t)};
function sortable(tbl){tbl.querySelectorAll('th').forEach((th,i)=>th.onclick=()=>{const rows=[...tbl.tBodies[0].rows];const asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
rows.sort((a,b)=>{const x=a.cells[i].dataset.v??a.cells[i].textContent,y=b.cells[i].dataset.v??b.cells[i].textContent;const nx=parseFloat(x),ny=parseFloat(y);
return (isNaN(nx)||isNaN(ny)?x.localeCompare(y):nx-ny)*(asc?1:-1)});rows.forEach(r=>tbl.tBodies[0].appendChild(r))})}
// Findings
let fSev=new Set(['CRITICAL','HIGH','MEDIUM','LOW']),fCat='',fQ='';
function renderFindings(){const el=document.getElementById('s-findings');
const list=D.findings.filter(f=>fSev.has(f.severity)&&(!fCat||f.category===fCat)&&(!fQ||JSON.stringify(f).toLowerCase().includes(fQ)));
el.innerHTML=`<h2>Findings</h2><div class="controls">${SEV.map(s=>`<button class="${fSev.has(s)?'on':''}" data-s="${s}">${s} (${D.summary.bySeverity[s]||0})</button>`).join('')}
<select id="fc"><option value="">all categories</option>${['MALWARE','SECURITY','SUSPICIOUS','PRIVACY','UNKNOWN'].map(c=>`<option ${c===fCat?'selected':''}>${c}</option>`).join('')}</select>
<input id="fq" placeholder="search…" value="${E(fQ)}"></div><div class="card"><table><thead><tr><th>Severity</th><th>Category</th><th>Package</th><th>Finding</th><th>ATT&CK</th></tr></thead><tbody>
${list.map(f=>`<tr><td data-v="${SEV.indexOf(f.severity)}">${sev(f.severity)}</td><td>${f.category}</td><td class="mono">${E(f.package||'device')}</td>
<td>${f.new?'<span class="sev HIGH">NEW</span> ':''}<b>${E(f.title)}</b>${f.detail?`<div class="muted">${E(f.detail).slice(0,400)}</div>`:''}${(f.evidence&&f.evidence.length)||f.advice?`<details><summary>evidence / next steps</summary>${f.advice?`<p>${E(f.advice)}</p>`:''}${(f.evidence||[]).map(x=>`<pre>${E(x)}</pre>`).join('')}</details>`:''}<div class="muted">${E(f.source)}</div></td><td class="mono">${E(f.mitre||'')}</td></tr>`).join('')}
</tbody></table>${list.length?'':'<p class="muted">Nothing matches.</p>'}</div>`;
el.querySelectorAll('button[data-s]').forEach(b=>b.onclick=()=>{const s=b.dataset.s;fSev.has(s)?fSev.delete(s):fSev.add(s);renderFindings()});
el.querySelector('#fc').onchange=e=>{fCat=e.target.value;renderFindings()};const q=el.querySelector('#fq');q.oninput=e=>{fQ=e.target.value.toLowerCase();renderFindings();const n=document.getElementById('fq');n.focus();n.setSelectionRange(n.value.length,n.value.length)};
sortable(el.querySelector('table'))}
renderFindings();
// Apps
(function(){let showSys=false;const el=document.getElementById('s-apps');
function r(){const list=D.apps.filter(a=>showSys||!a.system);el.innerHTML=`<h2>Applications</h2><div class="controls"><label><input type="checkbox" id="sys" ${showSys?'checked':''} style="min-width:0"> show system apps</label><span class="muted">click a column to sort</span></div>
<div class="card"><table><thead><tr><th>App</th><th>Security</th><th>Privacy</th><th>Source</th><th>Installed</th><th>VirusTotal</th><th>Details</th></tr></thead><tbody>
${list.sort((a,b)=>b.security-a.security||b.privacy-a.privacy).map(a=>`<tr><td><b>${E(a.label)}</b><div class="mono muted">${E(a.package)}</div></td>
<td data-v="${a.security}" style="color:${col(a.security)};font-weight:700">${a.security}</td><td data-v="${a.privacy}" style="color:${col(a.privacy)};font-weight:700">${a.privacy}</td>
<td>${a.system?'system':a.sideloaded?'<b style="color:var(--high)">sideloaded</b>':'store'}<div class="muted mono">${E(a.installer||'')}</div>${a.launcher===false&&!a.system?'<div style="color:var(--high)">hidden icon</div>':''}</td>
<td class="mono">${E((a.firstInstall||'').slice(0,16))}</td><td>${E(a.vt||'–')}<div class="muted">${E(a.vtLabel||'')}</div></td>
<td><details><summary>more</summary><div class="mono">sha256 ${E(a.sha256||'?')}<br>signer ${E(a.signer||'?')}<br>${E(a.signerSubject||'')}</div>
${a.granted.length?`<p>${a.granted.map(p=>`<span class="pill">${E(p)}</span>`).join('')}</p>`:''}
${a.trackers.length?`<p>Trackers: ${a.trackers.map(E).join(', ')}</p>`:''}${a.hosts.length?`<p>Endpoints in code: ${a.hosts.slice(0,25).map(E).join(', ')}</p>`:''}
${Object.keys(a.dns).length?`<p>DNS seen: ${Object.entries(a.dns).slice(0,25).map(([d,n])=>E(d)+' ×'+n).join(', ')}</p>`:''}
${a.payloads.length?`<p style="color:var(--high)">Payloads: ${a.payloads.map(p=>E(p.path+' ('+p.type+')')).join(', ')}</p>`:''}</details></td></tr>`).join('')}</tbody></table></div>`;
el.querySelector('#sys').onchange=e=>{showSys=e.target.checked;r()};sortable(el.querySelector('table'))}r()})();
// Timeline
(function(){const el=document.getElementById('s-timeline');let q='',min='INFO';
function r(){const mi=SEV.indexOf(min);const list=D.timeline.filter(e=>SEV.indexOf(e.severity)<=mi&&(!q||JSON.stringify(e).toLowerCase().includes(q))).slice(0,1500);
el.innerHTML=`<h2>Timeline</h2><p class="muted">Package installs, permission use (appops), settings changes, crashes, logcat events and DroidSentinel alerts, newest first. Logcat timestamps have no year.</p>
<div class="controls"><select id="tm">${SEV.map(s=>`<option ${s===min?'selected':''}>${s}</option>`).join('')}</select><input id="tq" placeholder="filter…" value="${E(q)}"></div>
<div class="card"><table><thead><tr><th>Time</th><th>Sev</th><th>Source</th><th>Package</th><th>Event</th></tr></thead><tbody>
${list.map(e=>`<tr><td class="mono">${E(e.ts)}</td><td>${sev(e.severity)}</td><td>${E(e.source)}</td><td class="mono">${E(e.package||'')}</td><td>${E(e.what)}</td></tr>`).join('')}</tbody></table></div>`;
el.querySelector('#tm').onchange=e=>{min=e.target.value;r()};el.querySelector('#tq').onchange=e=>{q=e.target.value.toLowerCase();r()}}r()})();
// Network
(function(){const N=D.network,el=document.getElementById('s-network');const vol=Object.entries(N.volume||{});const fl=Object.entries(N.dns_flagged||{});
const mb=b=>(b/1048576).toFixed(1)+' MB';
el.innerHTML=`<h2>Network</h2><div class="card"><h3>Flagged DNS lookups (DroidSentinel)</h3>${fl.length?`<table><tbody>${fl.map(([k,v])=>`<tr><td class="mono">${E(k)}</td><td>${v.map(E).join(', ')}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">None (or DNS monitor not enabled).</p>'}</div>
<div class="card"><h3>Traffic per app, 30 days (top uploaders)</h3>${vol.length?`<table><thead><tr><th>App</th><th>Upload</th><th>Download</th></tr></thead><tbody>${vol.map(([p,v])=>`<tr><td class="mono">${E(p)}</td><td data-v="${v[1]}">${mb(v[1])}</td><td data-v="${v[0]}">${mb(v[0])}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">No usage-access data.</p>'}</div>
<div class="card"><h3>Domains per app (DNS log)</h3>${Object.entries(N.dns_per_app||{}).map(([p,d])=>`<details><summary>${E(p)} (${Object.keys(d).length})</summary><p class="mono">${Object.entries(d).map(([x,n])=>E(x)+' ×'+n).join('<br>')}</p></details>`).join('')||'<p class="muted">No DNS log.</p>'}</div>
<div class="card"><h3>Hostnames seen in logs</h3><p class="mono">${Object.entries(N.log_domains||{}).slice(0,150).map(([d,n])=>E(d)+' ×'+n).join(', ')||'–'}</p></div>`;
el.querySelectorAll('table').forEach(sortable)})();
// Logs
(function(){const el=document.getElementById('s-logs');const h=Object.entries(D.logHits||{}).sort((a,b)=>SEV.indexOf(a[1].severity)-SEV.indexOf(b[1].severity));
el.innerHTML=`<h2>Logcat detections</h2><div class="card"><table><thead><tr><th>Severity</th><th>Rule</th><th>Hits</th><th>Packages</th></tr></thead><tbody>
${h.map(([k,v])=>`<tr><td data-v="${SEV.indexOf(v.severity)}">${sev(v.severity)}</td><td><b>${E(v.title)}</b> <span class="muted">${E(k)}</span><details><summary>samples</summary>${v.samples.map(s=>`<pre>${E(s)}</pre>`).join('')}</details></td>
<td data-v="${v.count}">${v.count}</td><td class="mono">${Object.entries(v.packages).map(([p,n])=>E(p)+' ×'+n).join('<br>')}</td></tr>`).join('')}</tbody></table>${h.length?'':'<p class="muted">No logcat or no hits.</p>'}</div>`;
el.querySelectorAll('table').forEach(sortable)})();
// Device
(function(){const d=D.device,el=document.getElementById('s-device');const p=d.props||{};
const rows=[['Model',(p['ro.product.manufacturer']||'')+' '+(p['ro.product.model']||'')],['Android',(p['ro.build.version.release']||'')+' (API '+(p['ro.build.version.sdk']||'?')+')'],
['Security patch',p['ro.build.version.security_patch']],['Fingerprint',p['ro.build.fingerprint']],['Verified boot',p['ro.boot.verifiedbootstate']],['Bootloader locked',p['ro.boot.flash.locked']],
['SELinux',d.selinux],['Encryption',p['ro.crypto.state']+' '+(p['ro.crypto.type']||'')],['Screen lock',d.screenLockSecure],['Root indicators',(d.rootIndicators||[]).join(', ')||'none'],
['User CA certs',(d.userCaCerts||[]).length],['Accessibility enabled',D.enabled.accessibility.join(', ')||'none'],['Notification listeners',D.enabled.notification.join(', ')||'none'],
['Device admins',D.enabled.admins.join(', ')||'none'],['Device owner',D.enabled.device_owner||'none'],['Keyboard',D.enabled.ime],['SMS app',D.enabled.sms],['Autofill',D.enabled.autofill],
['Overlay allowed',(d.overlayGranted||[]).join(', ')],['May install apps',(d.installSourcesAllowed||[]).join(', ')],['Accounts (types)',(d.accounts||[]).join(', ')],
['Users/profiles',(d.users||[]).map(u=>u.join(':')).join(', ')],['ADB-authorised computers',(d.adb_keys||[]).join(', ')],['Roles',Object.entries(d.roles||{}).map(([k,v])=>k+': '+v.join('/')).join(' · ')]];
el.innerHTML=`<h2>Device</h2><div class="card"><table><tbody>${rows.map(r=>`<tr><th style="width:220px">${E(r[0])}</th><td class="mono">${E(r[1]??'?')}</td></tr>`).join('')}</tbody></table></div>`})();
// Coverage
(function(){const el=document.getElementById('s-coverage');const c=Object.entries(D.coverage);
el.innerHTML=`<h2>Coverage & blind spots</h2><p class="muted">What this analysis could and could not see. A clean result only means "nothing found in the data available".</p>
<div class="card"><table><tbody>${c.map(([k,v])=>`<tr><th style="width:180px">${E(k)}</th><td class="${/^ok/.test(v)?'cov-ok':'cov-bad'}">${E(v)}</td></tr>`).join('')}</tbody></table></div>
<div class="card"><b>IOC sources:</b> ${D.iocSources.map(E).join(', ')||'none loaded – run <span class="mono">python3 -m droidtriage --update-iocs</span>'}</div>
<div class="card"><b>Never visible to this toolkit:</b> kernel-level / firmware implants, zero-click exploits that leave no app or crash trace, data inside other apps' private storage, iCloud/Google account compromise, SIM-swap / SS7 attacks, network-side interception without a CA certificate. See docs/RISK_MATRIX.md for how to investigate those.</div>`})();
show('findings');
</script></body></html>
"""
