(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))s(n);new MutationObserver(n=>{for(const i of n)if(i.type==="childList")for(const r of i.addedNodes)r.tagName==="LINK"&&r.rel==="modulepreload"&&s(r)}).observe(document,{childList:!0,subtree:!0});function a(n){const i={};return n.integrity&&(i.integrity=n.integrity),n.referrerPolicy&&(i.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?i.credentials="include":n.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function s(n){if(n.ep)return;n.ep=!0;const i=a(n);fetch(n.href,i)}})();const se="/api/v1",B="pm.access_token",F="pm.refresh_token";let H=localStorage.getItem(B),w=localStorage.getItem(F),ne=()=>{};class A extends Error{constructor(t,{status:a=0,code:s="NETWORK_ERROR",location:n=null}={}){super(t),this.name="ApiError",this.status=a,this.code=s,this.location=n}}function fe(e){ne=e}function K(){return!!H}function Y(e){H=e.access_token||null,w=e.refresh_token||null,H?localStorage.setItem(B,H):localStorage.removeItem(B),w?localStorage.setItem(F,w):localStorage.removeItem(F),ne(K())}function ie(){Y({})}async function ve(){if(!w)return!1;const e=await fetch(`${se}/auth/refresh`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({refresh_token:w})});return e.ok?(Y(await e.json()),!0):(ie(),!1)}async function c(e,t={}){const{method:a="GET",body:s,headers:n={},auth:i=!0,retry:r=!0}=t,d={...n};s!==void 0&&(d["content-type"]="application/json"),i&&H&&(d.authorization=`Bearer ${H}`);const u=await fetch(se+e,{method:a,headers:d,body:s===void 0?void 0:JSON.stringify(s)});if(u.headers.get("www-authenticate")&&r&&w&&await ve())return c(e,{...t,retry:!1});const f=u.headers.get("etag");if(u.status===204)return{data:null,etag:f,status:204};const k=await u.text();let p=null;if(k)try{p=JSON.parse(k)}catch{p=k}if(!u.ok){const h=p&&p.error||{};throw new A(h.message||`${u.status} ${u.statusText}`,{status:u.status,code:h.code||"HTTP_ERROR",location:h.location||null})}return{data:p,etag:f,status:u.status}}const C={setupStatus:()=>c("/setup",{auth:!1}),setup:(e,t,a)=>c("/auth/setup",{method:"POST",auth:!1,body:{username:e,password:t,totp_code:a||null}}),login:(e,t,a)=>c("/auth/login",{method:"POST",auth:!1,body:{username:e,password:t,totp_code:a||null}}),me:()=>c("/auth/me"),logout:()=>c("/auth/logout",{method:"POST",body:w?{refreshToken:w}:{}})},L={list:(e={})=>c(`/hosts${Z(e)}`),get:e=>c(`/hosts/${e}`),create:e=>c("/hosts",{method:"POST",body:e}),replace:(e,t,a)=>c(`/hosts/${e}`,{method:"PUT",body:t,headers:O(a)}),remove:(e,t)=>c(`/hosts/${e}`,{method:"DELETE",headers:O(t)}),setEnabled:(e,t,a)=>c(`/hosts/${e}/${t?"enable":"disable"}`,{method:"POST",headers:O(a)})},x={list:(e={})=>c(`/certificates${Z(e)}`),intent:e=>c(`/certificates/intent/${e}`),createIntent:e=>c("/certificates/intent",{method:"POST",body:e}),custom:e=>c(`/certificates/custom/${e}`),createCustom:e=>c("/certificates/custom",{method:"POST",body:e}),removeCustom:(e,t)=>c(`/certificates/custom/${e}`,{method:"DELETE",headers:O(t)})},j={get:()=>c("/config"),apply:()=>c("/config/apply",{method:"POST"}),revisions:(e={})=>c(`/config/revisions${Z(e)}`)},J={health:()=>c("/health",{auth:!1}),version:()=>c("/version",{auth:!1})};function Z(e){const t=new URLSearchParams;for(const[s,n]of Object.entries(e))n!=null&&n!==""&&t.set(s,n);const a=t.toString();return a?`?${a}`:""}function O(e){return{"if-match":e||"*"}}function o(e){return String(e??"").replace(/[&<>"']/g,t=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[t])}function R(e,t="neutral"){return`<span class="badge badge-${o(t)}">${o(e)}</span>`}const be={disabled:"neutral",auto:"ok",manual:"info",acme_configured:"ok",internal_ca:"info"};function oe(e){return R(e.replace(/_/g," "),be[e]||"neutral")}const ge={applied:"ok",failed:"danger",pending:"warn",issued:"ok",expiring_soon:"warn",expired:"danger",renewal_error:"danger"};function D(e){return R(e.replace(/_/g," "),ge[e]||"neutral")}function re(e){return e?R("enabled","ok"):R("disabled","neutral")}function U(e){return e==null?"—":new Date(e*1e3).toLocaleString()}function ye(e){return e==null?"—":new Date(e*1e3).toLocaleDateString()}function N(e){return`
    <header class="header">
      <div class="header-left">
        <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
          <rect width="32" height="32" rx="7" fill="var(--accent)"/>
          <path d="M8 11h16M8 16h12M8 21h8" stroke="#0d1117" stroke-width="2.5" stroke-linecap="round"/>
        </svg>
        <span class="app-title">caddy-rs proxy manager</span>
      </div>
      <nav class="header-nav">
        ${[["/","Dashboard"],["/hosts","Hosts"],["/certificates","Certificates"],["/config","Config"],["/settings","Settings"]].map(([a,s])=>`<a href="${a}" class="nav-link${a===e?" active":""}" data-nav="${a}">${s}</a>`).join("")}
      </nav>
      <div class="header-right">
        <span class="who" id="whoami"></span>
        <button type="button" class="btn btn-ghost" id="logout-btn">Sign out</button>
      </div>
    </header>`}function g(e="Loading…"){return`<div class="loading">${o(e)}</div>`}function M(e){return`<div class="empty">${o(e)}</div>`}function y(e){const t=e.location?` <code>${o(e.location)}</code>`:"";return`<div class="error-message">${o(e.message)}${t}</div>`}function v(e,t="ok"){const a=document.getElementById("toasts")||(()=>{const n=document.createElement("div");return n.id="toasts",document.body.appendChild(n),n})(),s=document.createElement("div");s.className=`toast toast-${t}`,s.textContent=e,a.appendChild(s),setTimeout(()=>s.remove(),4e3)}function _(e,t){S();const a=document.createElement("div");a.className="modal",a.id="modal",a.innerHTML=`
    <div class="modal-overlay" data-close></div>
    <div class="modal-content" role="dialog" aria-modal="true" aria-label="${o(e)}">
      <div class="modal-header">
        <h2>${o(e)}</h2>
        <button type="button" class="modal-close" data-close aria-label="Close">&times;</button>
      </div>
      <div class="modal-body">${t}</div>
    </div>`,a.addEventListener("click",n=>{n.target.hasAttribute("data-close")&&S()}),document.body.appendChild(a);const s=a.querySelector("input, select, textarea, button:not(.modal-close)");return s&&s.focus(),a}function S(){var e;(e=document.getElementById("modal"))==null||e.remove()}function de(e,t,a="Delete"){return new Promise(s=>{const n=_(e,`<p class="modal-text">${o(t)}</p>
       <div class="modal-footer">
         <button type="button" class="btn btn-ghost" data-cancel>Cancel</button>
         <button type="button" class="btn btn-danger" data-confirm>${o(a)}</button>
       </div>`),i=r=>{S(),s(r)};n.querySelector("[data-cancel]").addEventListener("click",()=>i(!1)),n.querySelector("[data-confirm]").addEventListener("click",()=>i(!0)),n.querySelector(".modal-overlay").addEventListener("click",()=>i(!1)),document.addEventListener("keydown",r=>{r.key==="Escape"&&i(!1)},{once:!0})})}function le(e){const t={};for(const[a,s]of new FormData(e).entries()){if(s instanceof File)continue;const n=typeof s=="string"?s.trim():s;t[a]=n}for(const a of e.querySelectorAll('input[type="checkbox"]'))t[a.name]=a.checked;return t}function te(e){if(e==null||e==="")return null;const t=Number(e);return Number.isFinite(t)?t:null}function z(e){return String(e||"").split(/[\s,]+/).map(t=>t.trim()).filter(Boolean)}async function ce(e,t=null){let a=!0,s=null;try{const{data:d}=await C.setupStatus();a=!!d.configured}catch(d){s=d}e.innerHTML=`
    <div class="login-page">
      <div class="login-card">
        <div class="login-header">
          <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--accent)"/>
            <path d="M8 11h16M8 16h12M8 21h8" stroke="#0d1117" stroke-width="2.5" stroke-linecap="round"/>
          </svg>
          <h1>caddy-rs proxy manager</h1>
          <p>${a?"Sign in to manage hosts and certificates":"Create the first administrator account"}</p>
        </div>
        ${s||t?`<div class="error-message">${o((s||{message:t}).message)}</div>`:""}
        <div id="login-error"></div>
        <form id="auth-form" autocomplete="on">
          <div class="form-group">
            <label for="username">Username</label>
            <input id="username" name="username" autocomplete="username" required autofocus />
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="${a?"current-password":"new-password"}" required />
            ${a?"":'<span class="form-hint">At least 8 characters. This account is created once.</span>'}
          </div>
          ${a?`<div class="form-group">
                   <label for="totp">Two-factor code <span class="muted">(if enabled)</span></label>
                   <input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" />
                 </div>`:""}
          <button type="submit" class="btn btn-primary btn-block" id="submit">
            ${a?"Sign in":"Create administrator"}
          </button>
        </form>
        <p class="login-footer">
          ${a?"Sessions are issued by <code>caddy-rs-pm</code> on this host.":"Setup is available only until the first account exists."}
        </p>
      </div>
    </div>`;const n=e.querySelector("#auth-form"),i=e.querySelector("#login-error"),r=e.querySelector("#submit");n.addEventListener("submit",async d=>{d.preventDefault(),i.innerHTML="",r.disabled=!0,r.textContent=a?"Signing in…":"Creating…";const u=new FormData(n),f=String(u.get("username")||"").trim(),k=String(u.get("password")||""),p=String(u.get("totp")||"").trim();try{const h=a?await C.login(f,k,p||null):await C.setup(f,k,p||null);Ke(h.data)}catch(h){if(!a&&h instanceof A&&h.status===409){await ce(e,h.message);return}const I=h instanceof A&&h.location?`${h.message} (${h.location})`:h.message||"Authentication failed";i.innerHTML=`<div class="error-message">${o(I)}</div>`,r.disabled=!1,r.textContent=a?"Sign in":"Create administrator"}})}async function $e(e){var i;e.innerHTML=`
    <div class="page">
      ${N("/")}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Dashboard</h1>
            <p class="page-subtitle">Live view of hosts, certificates and the applied configuration</p>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><span class="stat-value" id="stat-hosts">—</span><span class="stat-label">Hosts</span></div>
          <div class="stat"><span class="stat-value" id="stat-enabled">—</span><span class="stat-label">Enabled</span></div>
          <div class="stat"><span class="stat-value" id="stat-certs">—</span><span class="stat-label">Certificates</span></div>
          <div class="stat"><span class="stat-value" id="stat-revision">—</span><span class="stat-label">Config revision</span></div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Hosts</h2><a class="btn btn-ghost btn-sm" href="/hosts" data-nav="/hosts">Manage</a></div>
          <div class="table-container" id="hosts-table">${g()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Certificates</h2><a class="btn btn-ghost btn-sm" href="/certificates" data-nav="/certificates">Manage</a></div>
          <div class="table-container" id="certs-table">${g()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Recent applies</h2><a class="btn btn-ghost btn-sm" href="/config" data-nav="/config">Configuration</a></div>
          <div class="table-container" id="revisions-table">${g()}</div>
        </div>
      </main>
    </div>`;try{const{data:r}=await C.me(),d=e.querySelector("#whoami");d&&(d.textContent=`${r.username} · ${((i=r.role)==null?void 0:i.name)||"user"}`)}catch{}const[t,a,s,n]=await Promise.allSettled([L.list({limit:5}),x.list({limit:5}),j.revisions({limit:5}),J.version()]);if(n.status==="fulfilled"){const r=e.querySelector(".app-title");r&&(r.textContent=`caddy-rs proxy manager ${n.value.data.version}`)}if(t.status==="fulfilled"){const{items:r,total:d}=t.value.data;e.querySelector("#stat-hosts").textContent=String(d),e.querySelector("#stat-enabled").textContent=String(r.filter(u=>u.enabled).length),e.querySelector("#hosts-table").innerHTML=r.length?Se(r):M("No hosts yet. Create one from the Hosts page.")}else e.querySelector("#stat-hosts").textContent="—",e.querySelector("#hosts-table").innerHTML=y(t.reason);if(a.status==="fulfilled"){const{items:r,total:d}=a.value.data;e.querySelector("#stat-certs").textContent=String(d),e.querySelector("#certs-table").innerHTML=r.length?we(r):M("No certificates or intents yet.")}else e.querySelector("#stat-certs").textContent="—",e.querySelector("#certs-table").innerHTML=y(a.reason);if(s.status==="fulfilled"){const{items:r}=s.value.data,d=r[0];e.querySelector("#stat-revision").textContent=d?String(d.revision):"0",e.querySelector("#revisions-table").innerHTML=r.length?ke(r):M("Nothing applied yet.")}else e.querySelector("#stat-revision").textContent="—",e.querySelector("#revisions-table").innerHTML=y(s.reason)}function Se(e){return`
    <table>
      <thead><tr><th>ID</th><th>Domains</th><th>Kind</th><th>TLS</th><th>State</th></tr></thead>
      <tbody>
        ${e.map(t=>`
          <tr>
            <td>${t.id}</td>
            <td>${t.domains.map(a=>`<span class="domain">${o(a)}</span>`).join("")}</td>
            <td>${o(t.kind)}</td>
            <td>${oe(t.tlsMode)}</td>
            <td>${re(t.enabled)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`}function we(e){return`
    <table>
      <thead><tr><th>Domains</th><th>Origin</th><th>Status</th><th>Expires</th></tr></thead>
      <tbody>
        ${e.map(t=>`
          <tr>
            <td>${(t.domains||[]).map(a=>`<span class="domain">${o(a)}</span>`).join("")}</td>
            <td>${o(t.origin)}</td>
            <td>${D(t.status)}</td>
            <td>${U(t.expiresAtUnix)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`}function ke(e){return`
    <table>
      <thead><tr><th>Revision</th><th>Status</th><th>Changed</th><th>Recorded</th><th>Error</th></tr></thead>
      <tbody>
        ${e.map(t=>`
          <tr>
            <td>${t.revision}</td>
            <td>${D(t.status)}</td>
            <td>${t.changed?"yes":"no"}</td>
            <td>${U(t.recordedAtUnix)}</td>
            <td>${t.error?o(t.error):"—"}</td>
          </tr>`).join("")}
      </tbody>
    </table>`}const Ee=25,m={offset:0,domain:"",kind:"",enabled:""};async function Le(e){e.innerHTML=`
    <div class="page">
      ${N("/hosts")}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Hosts</h1>
            <p class="page-subtitle">Proxy, redirect and dead hosts compiled into the caddy-rs config</p>
          </div>
          <button type="button" class="btn btn-primary" id="create-host">New host</button>
        </div>

        <div class="card">
          <div class="card-header">
            <form class="filters" id="filters">
              <input name="domain" placeholder="Filter by domain" value="${o(m.domain)}" />
              <select name="kind">
                <option value="">Any kind</option>
                <option value="proxy">Proxy</option>
                <option value="redirect">Redirect</option>
                <option value="dead">Dead</option>
              </select>
              <select name="enabled">
                <option value="">Any state</option>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
              <button type="submit" class="btn btn-ghost btn-sm">Apply</button>
            </form>
          </div>
          <div class="table-container" id="hosts-table">${g()}</div>
          <div class="pagination hidden" id="pagination"></div>
        </div>
      </main>
    </div>`;const t=e.querySelector("#filters");t.querySelector('[name="kind"]').value=m.kind,t.querySelector('[name="enabled"]').value=m.enabled,t.addEventListener("submit",a=>{a.preventDefault();const s=le(t);m.domain=s.domain,m.kind=s.kind,m.enabled=s.enabled,m.offset=0,T(e)}),e.querySelector("#create-host").addEventListener("click",()=>void ue(e,null)),await T(e)}async function T(e){const t=e.querySelector("#hosts-table"),a=e.querySelector("#pagination");t.innerHTML=g();try{const{data:s}=await L.list({limit:Ee,offset:m.offset,domain:m.domain,kind:m.kind,enabled:m.enabled});if(!s.items.length){t.innerHTML=M(m.domain||m.kind||m.enabled?"No hosts match these filters.":"No hosts yet. Create the first one."),a.classList.add("hidden");return}t.innerHTML=`
      <table>
        <thead>
          <tr><th>ID</th><th>Domains</th><th>Kind</th><th>TLS</th><th>State</th><th>Revision</th><th></th></tr>
        </thead>
        <tbody>
          ${s.items.map(n=>`
            <tr>
              <td>${n.id}</td>
              <td>${n.domains.map(i=>`<span class="domain">${o(i)}</span>`).join("")}</td>
              <td>${o(n.kind)}</td>
              <td>${oe(n.tlsMode)}</td>
              <td>${re(n.enabled)}</td>
              <td>${n.revision}</td>
              <td class="actions">
                <button type="button" class="btn btn-ghost btn-sm" data-edit="${n.id}">Edit</button>
                <button type="button" class="btn btn-ghost btn-sm" data-toggle="${n.id}" data-enabled="${n.enabled}">
                  ${n.enabled?"Disable":"Enable"}
                </button>
                <button type="button" class="btn btn-danger btn-sm" data-delete="${n.id}">Delete</button>
              </td>
            </tr>`).join("")}
        </tbody>
      </table>`,t.querySelectorAll("[data-edit]").forEach(n=>{n.addEventListener("click",()=>void ue(e,Number(n.dataset.edit)))}),t.querySelectorAll("[data-toggle]").forEach(n=>{n.addEventListener("click",()=>void Te(e,Number(n.dataset.toggle),n.dataset.enabled!=="true"))}),t.querySelectorAll("[data-delete]").forEach(n=>{n.addEventListener("click",()=>void qe(e,Number(n.dataset.delete)))}),xe(a,s,e)}catch(s){t.innerHTML=y(s),a.classList.add("hidden")}}function xe(e,t,a){const s=Math.max(1,Math.ceil(t.total/t.limit)),n=Math.floor(t.offset/t.limit)+1;e.classList.toggle("hidden",s<=1),!(s<=1)&&(e.innerHTML=`
    <button type="button" class="btn btn-ghost btn-sm" ${t.offset===0?"disabled":""} data-page="prev">Previous</button>
    <span>Page ${n} of ${s} · ${t.total} hosts</span>
    <button type="button" class="btn btn-ghost btn-sm" ${t.offset+t.limit>=t.total?"disabled":""} data-page="next">Next</button>`,e.querySelector('[data-page="prev"]').addEventListener("click",()=>{m.offset=Math.max(0,t.offset-t.limit),T(a)}),e.querySelector('[data-page="next"]').addEventListener("click",()=>{m.offset=t.offset+t.limit,T(a)}))}async function Te(e,t,a){try{await L.setEnabled(t,a,"*"),v(`Host ${t} ${a?"enabled":"disabled"}.`),await T(e)}catch(s){v(s.message,"danger")}}async function qe(e,t){if(await de("Delete host",`Delete host ${t}? Its domains are released for reuse.`))try{await L.remove(t,"*"),v(`Host ${t} deleted.`),await T(e)}catch(a){v(a.message,"danger")}}async function ue(e,t){var I,Q,X,ee;let a=null,s=null,n=[],i=[];try{const[l,E]=await Promise.all([t===null?Promise.resolve({data:null,etag:null}):L.get(t),x.list({limit:200}).catch(()=>({data:{items:[]}}))]);a=l.data,s=l.etag;for(const b of E.data.items)b.origin==="manual"?i.push(b):n.push(b)}catch(l){v(l.message,"danger");return}const r=(a==null?void 0:a.spec)||{kind:"proxy",spec:{}},d=r.kind==="proxy"?r.spec:{},u=r.kind==="redirect"?r.spec:{},f=(a==null?void 0:a.tls)||{mode:"disabled",sslForced:!1,hstsEnabled:!1,hstsSubdomains:!1},p=_(t===null?"New host":`Edit host ${t}`,`<form id="host-form">
      <div class="form-group">
        <label for="domains">Domains</label>
        <input id="domains" name="domains" required value="${o(((a==null?void 0:a.domains)||[]).join(", "))}"
               placeholder="app.example.com, www.example.com" />
        <span class="form-hint">Comma or space separated. Every domain must be unique across hosts.</span>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label for="kind">Kind</label>
          <select id="kind" name="kind">
            <option value="proxy" ${r.kind==="proxy"?"selected":""}>Proxy</option>
            <option value="redirect" ${r.kind==="redirect"?"selected":""}>Redirect</option>
            <option value="dead" ${r.kind==="dead"?"selected":""}>Dead (404)</option>
          </select>
        </div>
        <div class="form-group">
          <label for="enabled">State</label>
          <select id="enabled" name="enabled">
            <option value="true" ${(a==null?void 0:a.enabled)!==!1?"selected":""}>Enabled</option>
            <option value="false" ${(a==null?void 0:a.enabled)===!1?"selected":""}>Disabled</option>
          </select>
        </div>
      </div>

      <fieldset id="proxy-fields">
        <legend>Proxy</legend>
        <div class="form-grid">
          <div class="form-group">
            <label for="scheme">Upstream scheme</label>
            <select id="scheme" name="scheme">
              <option value="http" ${((I=d.upstream)==null?void 0:I.scheme)!=="https"?"selected":""}>http</option>
              <option value="https" ${((Q=d.upstream)==null?void 0:Q.scheme)==="https"?"selected":""}>https</option>
            </select>
          </div>
          <div class="form-group">
            <label for="upstream-host">Upstream host</label>
            <input id="upstream-host" name="upstreamHost" value="${o(((X=d.upstream)==null?void 0:X.host)||"")}" placeholder="10.0.0.5" />
          </div>
          <div class="form-group">
            <label for="upstream-port">Upstream port</label>
            <input id="upstream-port" name="upstreamPort" type="number" min="1" max="65535"
                   value="${((ee=d.upstream)==null?void 0:ee.port)??""}" placeholder="8080" />
          </div>
        </div>
        <label class="checkbox"><input type="checkbox" name="websocket" ${d.websocket?"checked":""} /> WebSocket support</label>
        <label class="checkbox"><input type="checkbox" name="preserveHost" ${d.preserveHost!==!1?"checked":""} /> Preserve the Host header</label>
      </fieldset>

      <fieldset id="redirect-fields">
        <legend>Redirect</legend>
        <div class="form-grid">
          <div class="form-group">
            <label for="redirect-target">Target</label>
            <input id="redirect-target" name="redirectTarget" value="${o(u.target||"")}" placeholder="example.com" />
          </div>
          <div class="form-group">
            <label for="redirect-status">Status</label>
            <select id="redirect-status" name="redirectStatus">
              ${[301,302,307,308].map(l=>`<option value="${l}" ${(u.status??301)===l?"selected":""}>${l}</option>`).join("")}
            </select>
          </div>
          <div class="form-group">
            <label for="redirect-scheme">Scheme</label>
            <select id="redirect-scheme" name="redirectScheme">
              <option value="auto" ${(u.scheme??"auto")==="auto"?"selected":""}>auto (keep request scheme)</option>
              <option value="http" ${u.scheme==="http"?"selected":""}>http</option>
              <option value="https" ${u.scheme==="https"?"selected":""}>https</option>
            </select>
          </div>
        </div>
        <label class="checkbox"><input type="checkbox" name="preservePath" ${u.preservePath!==!1?"checked":""} /> Preserve the request path</label>
      </fieldset>

      <fieldset>
        <legend>TLS</legend>
        <div class="form-group">
          <label for="tls-mode">Mode</label>
          <select id="tls-mode" name="tlsMode">
            <option value="disabled" ${f.mode==="disabled"?"selected":""}>Disabled (plain HTTP)</option>
            <option value="auto" ${f.mode==="auto"?"selected":""}>Auto (managed certificate)</option>
            <option value="manual" ${f.mode==="manual"?"selected":""}>Manual (uploaded certificate)</option>
          </select>
        </div>
        <div class="form-group" id="auto-policy-group">
          <label for="auto-policy">Certificate intent</label>
          <select id="auto-policy" name="autoPolicyId">
            <option value="">Choose an intent…</option>
            ${n.map(l=>`<option value="${l.policyId}" ${f.autoPolicyId===l.policyId?"selected":""}>${o(l.name)} — ${o(l.domains.join(", "))}</option>`).join("")}
          </select>
          <span class="form-hint">Create intents on the Certificates page. None are configured yet if this list is empty.</span>
        </div>
        <div class="form-group" id="manual-cert-group">
          <label for="manual-cert">Certificate</label>
          <select id="manual-cert" name="certificateId">
            <option value="">Choose a certificate…</option>
            ${i.map(l=>`<option value="${l.id}" ${f.certificateId===l.id?"selected":""}>${o(l.name)} — ${o(l.domains.join(", "))}</option>`).join("")}
          </select>
          <span class="form-hint">Upload certificates on the Certificates page.</span>
        </div>
        <label class="checkbox"><input type="checkbox" name="sslForced" ${f.sslForced?"checked":""} /> Force HTTPS</label>
        <label class="checkbox"><input type="checkbox" name="hstsEnabled" ${f.hstsEnabled?"checked":""} /> Send HSTS</label>
        <label class="checkbox"><input type="checkbox" name="hstsSubdomains" ${f.hstsSubdomains?"checked":""} /> HSTS includes subdomains</label>
      </fieldset>

      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-host">${t===null?"Create":"Save"}</button>
      </div>
    </form>`).querySelector("#host-form"),h=()=>{const l=p.querySelector("#kind").value;p.querySelector("#proxy-fields").classList.toggle("hidden",l!=="proxy"),p.querySelector("#redirect-fields").classList.toggle("hidden",l!=="redirect");const E=p.querySelector("#tls-mode").value;p.querySelector("#auto-policy-group").classList.toggle("hidden",E!=="auto"),p.querySelector("#manual-cert-group").classList.toggle("hidden",E!=="manual")};p.querySelector("#kind").addEventListener("change",h),p.querySelector("#tls-mode").addEventListener("change",h),h(),p.querySelector("[data-close]").addEventListener("click",S),p.addEventListener("submit",async l=>{l.preventDefault();const E=p.querySelector("#save-host");E.disabled=!0;try{const b=He(p);t===null?await L.create(b):await L.replace(t,b,s),S(),v(t===null?"Host created.":`Host ${t} updated.`),await T(e)}catch(b){E.disabled=!1;const me=b instanceof A&&b.location?`${b.message} (${b.location})`:b.message;v(me,"danger")}})}function He(e){const t=le(e),a=t.kind,s=t.tlsMode,n={mode:s,sslForced:!!t.sslForced,hstsEnabled:!!t.hstsEnabled,hstsSubdomains:!!t.hstsSubdomains};s==="auto"&&(n.autoPolicyId=te(t.autoPolicyId)),s==="manual"&&(n.certificateId=te(t.certificateId));let i;return a==="proxy"?i={kind:"proxy",spec:{upstream:{scheme:t.scheme||"http",host:t.upstreamHost,port:Number(t.upstreamPort)},websocket:!!t.websocket,preserveHost:!!t.preserveHost}}:a==="redirect"?i={kind:"redirect",spec:{scheme:t.redirectScheme||"auto",target:t.redirectTarget,status:Number(t.redirectStatus)||301,preservePath:!!t.preservePath}}:i={kind:"dead"},{domains:z(t.domains),tls:n,spec:i,enabled:t.enabled!=="false"}}const Ce=50,$={tab:"intents",offset:0};async function Me(e){e.innerHTML=`
    <div class="page">
      ${N("/certificates")}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Certificates</h1>
            <p class="page-subtitle">Managed certificate intents and uploaded certificates</p>
          </div>
          <div class="btn-group">
            <button type="button" class="btn btn-primary" id="new-intent">New intent</button>
            <button type="button" class="btn btn-ghost" id="upload-certificate">Upload certificate</button>
          </div>
        </div>

        <div class="tabs">
          <button type="button" class="tab" data-tab="intents">Intents</button>
          <button type="button" class="tab" data-tab="manual">Uploaded</button>
        </div>

        <div class="card">
          <div class="table-container" id="cert-table">${g()}</div>
          <div class="pagination hidden" id="pagination"></div>
        </div>
      </main>
    </div>`;const t=e.querySelectorAll("[data-tab]");t.forEach(a=>{a.classList.toggle("active",a.dataset.tab===$.tab),a.addEventListener("click",()=>{$.tab=a.dataset.tab,$.offset=0,t.forEach(s=>s.classList.toggle("active",s===a)),q(e)})}),e.querySelector("#new-intent").addEventListener("click",()=>void Oe(e)),e.querySelector("#upload-certificate").addEventListener("click",()=>void Re(e)),await q(e)}async function q(e){const t=e.querySelector("#cert-table"),a=e.querySelector("#pagination");t.innerHTML=g();try{const{data:s}=await x.list({limit:Ce,offset:$.offset}),n=s.items.filter(i=>$.tab==="manual"?i.origin==="manual":i.origin!=="manual");if(!n.length){t.innerHTML=M($.tab==="manual"?"No uploaded certificates. Upload a PEM chain and key to reference it from a host.":"No certificate intents. An intent lets caddy-rs obtain and renew a certificate."),a.classList.add("hidden");return}t.innerHTML=$.tab==="manual"?Ae(n):Pe(n),De(e,t),Ne(a,s,e)}catch(s){t.innerHTML=s.status===503?`${y(s)}<div class="card-body muted">Certificate status is read from caddy-rs. Start the data plane and reload; creating an intent still works.</div>`:y(s),a.classList.add("hidden")}}function Pe(e){return`
    <table>
      <thead>
        <tr><th>Domains</th><th>Issuer</th><th>Challenge</th><th>Status</th><th>Expires</th><th>Revision</th><th></th></tr>
      </thead>
      <tbody>
        ${e.map(t=>`
          <tr>
            <td>${t.domains.map(a=>`<span class="domain">${o(a)}</span>`).join("")}</td>
            <td>${o(t.issuer)}</td>
            <td>${o(t.challenge)}</td>
            <td>${D(t.status)}${t.renewalError?`<div class="form-hint">${o(t.renewalError)}</div>`:""}</td>
            <td>${U(t.expiresAtUnix)}</td>
            <td>${t.revision}</td>
            <td class="actions"></td>
          </tr>`).join("")}
      </tbody>
    </table>`}function Ae(e){return`
    <table>
      <thead>
        <tr><th>Domains</th><th>Key</th><th>Status</th><th>Expires</th><th>Fingerprint</th><th>Revision</th><th></th></tr>
      </thead>
      <tbody>
        ${e.map(t=>`
          <tr>
            <td>${t.domains.map(a=>`<span class="domain">${o(a)}</span>`).join("")}</td>
            <td>${o(t.keyType)}</td>
            <td>${D(t.status)}</td>
            <td>${ye(t.expiresAtUnix)}</td>
            <td><span class="chip" title="${o(t.fingerprintSha256)}">${o(t.fingerprintSha256.slice(0,16))}…</span></td>
            <td>${t.revision}</td>
            <td class="actions">
              <button type="button" class="btn btn-danger btn-sm" data-delete-cert="${t.id}">Delete</button>
            </td>
          </tr>`).join("")}
      </tbody>
    </table>`}function De(e,t){t.querySelectorAll("[data-delete-cert]").forEach(a=>{a.addEventListener("click",()=>void Ie(e,Number(a.dataset.deleteCert)))})}function Ne(e,t,a){const s=Math.max(1,Math.ceil(t.total/t.limit));e.classList.toggle("hidden",s<=1),!(s<=1)&&(e.innerHTML=`
    <button type="button" class="btn btn-ghost btn-sm" ${t.offset===0?"disabled":""} data-page="prev">Previous</button>
    <span>Page ${Math.floor(t.offset/t.limit)+1} of ${s}</span>
    <button type="button" class="btn btn-ghost btn-sm" ${t.offset+t.limit>=t.total?"disabled":""} data-page="next">Next</button>`,e.querySelector('[data-page="prev"]').addEventListener("click",()=>{$.offset=Math.max(0,t.offset-t.limit),q(a)}),e.querySelector('[data-page="next"]').addEventListener("click",()=>{$.offset=t.offset+t.limit,q(a)}))}async function Ie(e,t){if(await de("Delete certificate",`Delete uploaded certificate ${t}? Hosts referencing it must be changed first.`))try{const{etag:a}=await x.custom(t);await x.removeCustom(t,a),v(`Certificate ${t} deleted.`),await q(e)}catch(a){v(a.message,"danger")}}function Oe(e){const a=_("New certificate intent",`<form id="intent-form">
      <div class="form-group">
        <label for="intent-domains">Domains</label>
        <input id="intent-domains" name="domains" required placeholder="app.example.com, *.example.com" />
        <span class="form-hint">Up to 100 names. Wildcards need a DNS-01 challenge, which this build does not support.</span>
      </div>
      <div class="form-grid">
        <div class="form-group">
          <label for="intent-issuer">Issuer</label>
          <select id="intent-issuer" name="issuer">
            <option value="letsencrypt">Let's Encrypt</option>
            <option value="zerossl">ZeroSSL</option>
            <option value="internal">Internal CA</option>
          </select>
        </div>
        <div class="form-group">
          <label for="intent-challenge">Challenge</label>
          <select id="intent-challenge" name="challenge">
            <option value="http01">HTTP-01</option>
            <option value="tls-alpn01">TLS-ALPN-01</option>
          </select>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-intent">Create</button>
      </div>
    </form>`).querySelector("#intent-form");a.querySelector("[data-close]").addEventListener("click",S),a.addEventListener("submit",async s=>{s.preventDefault();const n=a.querySelector("#save-intent");n.disabled=!0;const i=Object.fromEntries(new FormData(a).entries());try{await x.createIntent({domains:z(i.domains),issuer:i.issuer,challenge:i.challenge}),S(),v("Certificate intent created."),await q(e)}catch(r){n.disabled=!1,v(pe(r),"danger")}})}function Re(e){const a=_("Upload certificate",`<form id="upload-form">
      <div class="form-group">
        <label for="upload-domains">Domains</label>
        <input id="upload-domains" name="domains" required placeholder="app.example.com, www.example.com" />
      </div>
      <div class="form-group">
        <label for="upload-chain">Certificate chain (PEM)</label>
        <textarea id="upload-chain" name="certificate" rows="7" required
                  placeholder="-----BEGIN CERTIFICATE-----"></textarea>
      </div>
      <div class="form-group">
        <label for="upload-key">Private key (PEM)</label>
        <textarea id="upload-key" name="privateKey" rows="7" required
                  placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
        <span class="form-hint">The key is stored in the PM data directory and never returned by the API.</span>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary" id="save-certificate">Upload</button>
      </div>
    </form>`).querySelector("#upload-form");a.querySelector("[data-close]").addEventListener("click",S),a.addEventListener("submit",async s=>{s.preventDefault();const n=a.querySelector("#save-certificate");n.disabled=!0;const i=Object.fromEntries(new FormData(a).entries());try{await x.createCustom({domains:z(i.domains),certificate:i.certificate,privateKey:i.privateKey}),S(),v("Certificate uploaded."),await q(e)}catch(r){n.disabled=!1,v(pe(r),"danger")}})}function pe(e){return e instanceof A&&e.location?`${e.message} (${e.location})`:e.message}const G={tab:"config"};async function je(e){e.innerHTML=`
    <div class="page">
      ${N("/config")}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Configuration</h1>
            <p class="page-subtitle">The assembled Caddy JSON and the durable apply history</p>
          </div>
          <button type="button" class="btn btn-primary" id="apply">Apply to caddy-rs</button>
        </div>

        <div id="apply-result"></div>

        <div class="tabs">
          <button type="button" class="tab" data-tab="config">Assembled config</button>
          <button type="button" class="tab" data-tab="revisions">Apply history</button>
        </div>

        <div class="card" id="panel">${g()}</div>
      </main>
    </div>`;const t=e.querySelectorAll("[data-tab]");t.forEach(a=>{a.classList.toggle("active",a.dataset.tab===G.tab),a.addEventListener("click",()=>{G.tab=a.dataset.tab,t.forEach(s=>s.classList.toggle("active",s===a)),W(e)})}),e.querySelector("#apply").addEventListener("click",()=>void Be(e)),await W(e)}async function W(e){const t=e.querySelector("#panel");t.innerHTML=g(),G.tab==="config"?await Ue(t):await _e(t)}async function Ue(e){try{const{data:t,etag:a}=await j.get();e.innerHTML=`
      <div class="card-header">
        <h2>Assembled Caddy JSON</h2>
        <span class="chip" title="Weak ETag for this representation">${o(a||"no etag")}</span>
      </div>
      <div class="code-block"><pre>${o(JSON.stringify(t,null,2))}</pre></div>
      <div class="meta-row">
        <span>Hosts and certificate policies are compiled on read, so this view is always current.</span>
      </div>`}catch(t){e.innerHTML=`<div class="card-body">${y(t)}</div>`}}async function _e(e){try{const{data:t}=await j.revisions({limit:50});if(!t.items.length){e.innerHTML=M("Nothing has been applied yet. Create a host, then apply.");return}e.innerHTML=`
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Revision</th><th>Status</th><th>Changed</th><th>Hash</th><th>Recorded</th><th>Error</th></tr>
          </thead>
          <tbody>
            ${t.items.map(a=>`
              <tr>
                <td>${a.revision}</td>
                <td>${D(a.status)}</td>
                <td>${a.changed?"yes":"no"}</td>
                <td><span class="chip" title="${o(a.hash)}">${o(a.hash.slice(0,12))}…</span></td>
                <td>${U(a.recordedAtUnix)}</td>
                <td>${a.error?o(a.error):"—"}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`}catch(t){e.innerHTML=`<div class="card-body">${y(t)}</div>`}}async function Be(e){const t=e.querySelector("#apply"),a=e.querySelector("#apply-result");t.disabled=!0,t.textContent="Applying…",a.innerHTML="";try{const{data:s}=await j.apply();a.innerHTML=`<div class="success-message">Revision ${s.revision} ${s.changed?"applied":"already up to date"} · hash <span class="chip">${o(s.hash.slice(0,16))}…</span></div>`,await W(e)}catch(s){a.innerHTML=y(s),v(s.message,"danger")}finally{t.disabled=!1,t.textContent="Apply to caddy-rs"}}async function Fe(e){var s;e.innerHTML=`
    <div class="page">
      ${N("/settings")}
      <main class="main-content">
        <div class="page-header">
          <div>
            <h1>Settings</h1>
            <p class="page-subtitle">Session and server facts reported by this daemon</p>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Session</h2></div>
          <div id="session">${g()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Server</h2></div>
          <div id="server">${g()}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Sign out</h2></div>
          <div class="setting">
            <div>
              <h3>End this session</h3>
              <p>Revokes the refresh token used by this browser. Other devices stay signed in.</p>
            </div>
            <button type="button" class="btn btn-danger" id="sign-out">Sign out</button>
          </div>
        </div>
      </main>
    </div>`,e.querySelector("#sign-out").addEventListener("click",()=>{he()});const t=e.querySelector("#session"),a=e.querySelector("#server");try{const{data:n}=await C.me();t.innerHTML=`
      <div class="setting"><div><h3>Username</h3><p>${o(n.username)}</p></div></div>
      <div class="setting"><div><h3>User ID</h3><p>${o(n.id)}</p></div></div>
      <div class="setting"><div><h3>Role</h3><p>${o(((s=n.role)==null?void 0:s.name)||"unknown")}</p></div></div>
      <div class="setting"><div><h3>Two-factor</h3><p>${n.totp_enabled?"enabled":"not enabled"}</p></div></div>
      <div class="setting"><div><h3>Auth epoch</h3><p>${o(n.auth_epoch)}</p></div></div>`}catch(n){t.innerHTML=`<div class="card-body">${y(n)}</div>`}try{const[{data:n},{data:i}]=await Promise.all([J.version(),J.health()]);a.innerHTML=`
      <div class="setting"><div><h3>Proxy manager</h3><p>${o(n.version)}</p></div></div>
      <div class="setting"><div><h3>caddy-rs core</h3><p>${o(n.caddyRs)}</p></div></div>
      <div class="setting"><div><h3>Health</h3><p>${o(i.status)}</p></div></div>
      <div class="setting"><div><h3>Setup complete</h3><p>${i.setup?"yes":"no"}</p></div></div>`}catch(n){a.innerHTML=`<div class="card-body">${y(n)}</div>`}}const ae=[{pattern:/^\/login$/,render:ce,requiresAuth:!1},{pattern:/^\/$/,render:$e,requiresAuth:!0},{pattern:/^\/hosts$/,render:Le,requiresAuth:!0},{pattern:/^\/certificates$/,render:Me,requiresAuth:!0},{pattern:/^\/config$/,render:je,requiresAuth:!0},{pattern:/^\/settings$/,render:Fe,requiresAuth:!0}];function P(e,{replace:t=!1}={}){t?window.history.replaceState({},"",e):window.history.pushState({},"",e),V()}async function V(){const e=window.location.pathname,t=ae.find(s=>s.pattern.test(e))??ae[1];if(t.requiresAuth&&!K()){P("/login",{replace:!0});return}if(!t.requiresAuth&&K()&&e==="/login"){P("/",{replace:!0});return}const a=document.getElementById("app");a.replaceChildren();try{await t.render(a)}catch(s){console.error("render failed",s),a.innerHTML=`<div class="main-content"><div class="error-message">${s&&s.message?s.message:"Failed to render page"}</div></div>`}}async function he(){try{await C.logout()}catch(e){console.warn("logout failed; clearing local session anyway",e)}ie(),P("/login",{replace:!0})}function Ke(e){Y(e),P("/",{replace:!0})}document.addEventListener("click",e=>{const t=e.target.closest("[data-nav]");t&&(e.preventDefault(),P(t.getAttribute("data-nav"))),e.target.closest("#logout-btn")&&(e.preventDefault(),he())});window.addEventListener("popstate",()=>void V());fe(e=>{!e&&!window.location.pathname.startsWith("/login")&&P("/login",{replace:!0})});V();
