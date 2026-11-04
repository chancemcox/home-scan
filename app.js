'use strict';
const $=id=>document.getElementById(id);
let data=[],cf={routes:[],configured:false},selected=null;
const suffix='.local.chancecox.com';
function cell(row,text,cls){const td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;row.append(td);return td}
function routesFor(id){return cf.routes.filter(r=>r.device_id===id)}
function render(){
 const q=$('search').value.toLowerCase();$('rows').replaceChildren();
 for(const d of data.filter(d=>[d.ip,d.hostname,d.mac,...routesFor(d.device_id).map(r=>r.hostname)].join(' ').toLowerCase().includes(q))){
  const tr=document.createElement('tr');const name=cell(tr,d.hostname||'Unnamed device');const mac=document.createElement('small');mac.className='mono';mac.textContent=d.mac||'MAC not discovered';name.append(mac);
  cell(tr,d.ip,'mono');cell(tr,d.status==='seen'?'● Seen':d.status==='unknown'?'◌ Status unavailable':'○ Not seen',d.online?'up':d.status==='unknown'?'unknown':'down');
  const routeCell=cell(tr,'');const routes=routesFor(d.device_id).filter(r=>r.enabled||r.state==='pending'||r.state==='error');
  if(!routes.length){routeCell.textContent='Not enabled';routeCell.className='down'}
  for(const r of routes){const tag=document.createElement('span');tag.className='route-tag';tag.textContent=(r.kind==='local'?'DNS · ':'Tunnel · ')+r.hostname;routeCell.append(tag);const state=document.createElement('small');state.className='route-state';state.textContent=r.message||({synced:'Config synced',pending:'Pending',disabled:'Disabled',waiting:'Waiting',error:'Retrying'}[r.state]||r.state);routeCell.append(state)}
  cell(tr,new Date(d.last_seen).toLocaleString());const action=cell(tr,'');const button=document.createElement('button');button.textContent='Configure';button.disabled=!d.mac;button.title=d.mac?'Configure Cloudflare for this device':'A MAC address is required';button.setAttribute('aria-label','Configure '+(d.hostname||d.ip));button.addEventListener('click',()=>openDevice(d));action.append(button);$('rows').append(tr);
 }
 if(!$('rows').children.length){const tr=document.createElement('tr');const td=cell(tr,data.length?'No matching devices.':'Waiting for the first scan…');td.colSpan=6;$('rows').append(tr)}
}
function openDevice(d){
 selected=d.device_id;const routes=routesFor(selected);const local=routes.find(r=>r.kind==='local');const tunnel=routes.find(r=>r.kind==='tunnel');
 $('device-title').textContent=d.hostname||d.ip;$('device-identity').textContent=d.mac;$('device-current').textContent='Current IP: '+d.ip+' · Settings follow this MAC address.';
 $('local-enabled').checked=!!local?.enabled;$('tunnel-enabled').checked=!!tunnel?.enabled;
 $('local-host').value=(local?.hostname||'').replace(suffix,'');$('tunnel-host').value=(tunnel?.hostname||'').replace(suffix,'');$('tunnel-port').value=tunnel?.port||80;$('tunnel-protocol').value=tunnel?.protocol||'http';$('form-error').textContent='';updateFields();$('device-dialog').showModal();
}
function updateFields(){const local=$('local-enabled').checked,tunnel=$('tunnel-enabled').checked;$('local-host').disabled=!local;$('local-host').required=local;for(const id of ['tunnel-host','tunnel-port','tunnel-protocol'])$(id).disabled=!tunnel;$('tunnel-host').required=tunnel}
async function post(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const result=await r.json();if(!r.ok)throw Error(result.error||'Request failed');return result}
$('device-form').addEventListener('submit',async event=>{event.preventDefault();$('save-button').disabled=true;$('form-error').textContent='';try{await post('/api/cloudflare/settings',{device_id:selected,local:{enabled:$('local-enabled').checked,hostname:$('local-host').value},tunnel:{enabled:$('tunnel-enabled').checked,hostname:$('tunnel-host').value,protocol:$('tunnel-protocol').value,port:Number($('tunnel-port').value)}});$('device-dialog').close();await refresh()}catch(e){$('form-error').textContent=e.message}finally{$('save-button').disabled=false}});
for(const id of ['local-enabled','tunnel-enabled'])$(id).addEventListener('change',updateFields);
for(const button of document.querySelectorAll('[data-close]'))button.addEventListener('click',()=>$(button.dataset.close).close());
$('connection-button').addEventListener('click',()=>{$('connection-status').textContent=cf.configured?'Connected to '+cf.zone+(cf.tunnel_configured?' with tunnel support.':' for local DNS.'):'Cloudflare is not connected yet.';$('connection-dialog').showModal()});
$('sync-button').addEventListener('click',async()=>{try{await post('/api/cloudflare/sync',{});$('cloud-state').textContent='Cloudflare sync queued…'}catch(e){$('notice').textContent=e.message}});
$('search').addEventListener('input',render);
async function refresh(){try{const r=await fetch('/api/devices');if(!r.ok)throw Error('Request failed');const j=await r.json();data=j.devices;cf=j.cloudflare;$('total').textContent=data.length;$('online').textContent=data.filter(d=>d.online).length;$('route-count').textContent=cf.routes.filter(r=>r.enabled).length;$('status').textContent=j.stale?'Awaiting scanner':'● Scanner active';$('notice').textContent=j.latest?.error?'Last network scan failed: '+j.latest.error:j.stale?'No recent scan received. Check the scanner service.':'';$('cloud-state').textContent=cf.configured?'Cloudflare connected · '+cf.zone:'Cloudflare not connected · Configure devices, then connect your account';$('sync-button').disabled=!cf.configured;$('meta').textContent=j.network+' · Scans every 60 seconds · '+(j.latest?'Last attempt: '+new Date(j.latest.finished).toLocaleString():'No scans yet');render()}catch(e){$('status').textContent='Connection lost';$('notice').textContent='Cannot reach HomeScan. Retrying…'}}
refresh();setInterval(refresh,10000);
