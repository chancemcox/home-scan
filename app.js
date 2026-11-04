'use strict';
const $=id=>document.getElementById(id);
let data=[],cf={routes:[],configured:false},decoState={enabled:false,configured:false},selected=null,editingTunnel=null,editingTunnelDetail=null,tunnelInventory=[],zoneInventory=[];
let sortKey='hostname',sortDir=1;
let suffix='.house.chancecox.com';
const statusRank={seen:0,unknown:1,not_seen:2};
function cell(row,text,cls){const td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;row.append(td);return td}
function routesFor(id){return cf.routes.filter(r=>r.device_id===id)}
function activeRoutes(d){return routesFor(d.device_id).filter(r=>r.enabled||r.state==='pending'||r.state==='error')}
function routeKey(d){const routes=activeRoutes(d);if(!routes.length)return '';return routes.map(r=>r.hostname).sort().join(' ')}
function matches(d){
 const q=$('search').value.trim().toLowerCase();
 const status=$('filter-status').value;
 const cloud=$('filter-cloudflare').value;
 if(status&&d.status!==status)return false;
 const routes=activeRoutes(d);
 if(cloud==='enabled'&&!routes.some(r=>r.enabled))return false;
 if(cloud==='disabled'&&routes.some(r=>r.enabled))return false;
 if(cloud==='attention'&&!routes.some(r=>r.state==='error'||r.state==='pending'||r.state==='waiting'))return false;
 if(!q)return true;
 return [d.ip,d.hostname,d.mac,...routesFor(d.device_id).map(r=>r.hostname)].join(' ').toLowerCase().includes(q);
}
function compare(a,b){
 let av,bv;
 if(sortKey==='status'){av=statusRank[a.status]??9;bv=statusRank[b.status]??9}
 else if(sortKey==='cloudflare'){av=routeKey(a);bv=routeKey(b)}
 else if(sortKey==='last_seen'){av=Date.parse(a.last_seen)||0;bv=Date.parse(b.last_seen)||0}
 else if(sortKey==='ip'){av=a.ip.split('.').map(n=>n.padStart(3,'0')).join('.');bv=b.ip.split('.').map(n=>n.padStart(3,'0')).join('.')}
 else{av=(a.hostname||'').toLowerCase();bv=(b.hostname||'').toLowerCase()}
 if(av<bv)return -sortDir;if(av>bv)return sortDir;
 const an=(a.hostname||a.ip||'').toLowerCase(),bn=(b.hostname||b.ip||'').toLowerCase();
 return an<bn?-1:an>bn?1:0;
}
function syncSortHeaders(){
 for(const button of document.querySelectorAll('button.sort')){
  button.setAttribute('aria-sort',button.dataset.sort===sortKey?(sortDir>0?'ascending':'descending'):'none');
 }
}
function render(){
 const rows=data.filter(matches).sort(compare);
 $('rows').replaceChildren();
 $('filter-meta').textContent=rows.length===data.length?'':`Showing ${rows.length} of ${data.length} devices`;
 for(const d of rows){
  const tr=document.createElement('tr');const name=cell(tr,d.hostname||'Unnamed device');const mac=document.createElement('small');mac.className='mono';mac.textContent=d.mac||'MAC not discovered';name.append(mac);
  cell(tr,d.ip,'mono');cell(tr,d.status==='seen'?'● Seen':d.status==='unknown'?'◌ Status unavailable':'○ Not seen',d.online?'up':d.status==='unknown'?'unknown':'down');
  const routeCell=cell(tr,'');const routes=activeRoutes(d);
  if(!routes.length){routeCell.textContent='Not enabled';routeCell.className='down'}
  for(const r of routes){const tag=document.createElement('span');tag.className='route-tag';tag.textContent=(r.kind==='local'?'DNS · ':'Tunnel · ')+r.hostname;routeCell.append(tag);const state=document.createElement('small');state.className='route-state';state.textContent=r.message||({synced:'Config synced',pending:'Pending',disabled:'Disabled',waiting:'Waiting',error:'Retrying'}[r.state]||r.state);routeCell.append(state)}
  cell(tr,new Date(d.last_seen).toLocaleString());const action=cell(tr,'');const button=document.createElement('button');button.textContent='Configure';button.disabled=!d.mac;button.title=d.mac?'Configure Cloudflare for this device':'A MAC address is required';button.setAttribute('aria-label','Configure '+(d.hostname||d.ip));button.addEventListener('click',()=>openDevice(d));action.append(button);$('rows').append(tr);
 }
 if(!rows.length){const tr=document.createElement('tr');const td=cell(tr,data.length?'No matching devices.':'Waiting for the first scan…');td.colSpan=6;$('rows').append(tr)}
 syncSortHeaders();
}
function renderTunnels(payload){
 const body=$('tunnel-rows');body.replaceChildren();
 tunnelInventory=payload.tunnels||[];
 if(payload.error){$('tunnels-meta').textContent=payload.error}
 else{$('tunnels-meta').textContent=payload.tunnels?.length?`${payload.tunnels.length} tunnel${payload.tunnels.length===1?'':'s'}`:'No tunnels returned for this account.'}
 if(!payload.tunnels?.length){const tr=document.createElement('tr');const td=cell(tr,payload.error||'No tunnels found.');td.colSpan=7;body.append(tr);return}
 for(const t of payload.tunnels){
  const tr=document.createElement('tr');
  const name=cell(tr,t.name||'Unnamed tunnel');
  if(t.homescan){const badge=document.createElement('small');badge.className='badge';badge.textContent='HomeScan';name.append(badge)}
  const hosts=cell(tr,'');if(!t.hostnames?.length)hosts.textContent='—';for(const route of t.hostnames||[]){const tag=document.createElement('span');tag.className='route-tag';tag.textContent=`${route.hostname||'*'}${route.path?' · '+route.path:''} → ${route.service}`;hosts.append(tag)}
  cell(tr,t.status||'unknown',t.status==='healthy'?'up':t.connections?'unknown':'down');
  cell(tr,String(t.connections??0));
  cell(tr,t.created_at?new Date(t.created_at).toLocaleString():'—');
  cell(tr,t.id,'mono');
  const action=cell(tr,'');const button=document.createElement('button');button.textContent='Edit';button.disabled=!t.editable;button.title=t.editable?'Edit tunnel name and ingress configuration':'Locally managed tunnels must be edited in their local configuration';button.addEventListener('click',()=>openTunnel(t.id));action.append(button);
  body.append(tr);
 }
}
async function openTunnel(id){
 editingTunnel=id;$('tunnel-edit-error').textContent='';$('tunnel-edit-save').disabled=true;
 $('tunnel-edit-id').textContent=id;$('tunnel-edit-name').value='Loading…';$('tunnel-edit-config').value='';$('tunnel-dialog').showModal();
 try{
  const r=await fetch('/api/cloudflare/tunnel?id='+encodeURIComponent(id));const result=await r.json();if(!r.ok)throw Error(result.error||'Could not load tunnel');
  editingTunnelDetail=result;$('tunnel-edit-name').value=result.name;$('tunnel-edit-config').value=JSON.stringify(result.config,null,2);renderPortEditors();renderTunnelLinks();$('tunnel-edit-save').disabled=false;
 }catch(e){$('tunnel-edit-error').textContent=e.message}
}
function renderPortEditors(){
 const box=$('tunnel-rule-ports');box.replaceChildren();
 (editingTunnelDetail?.config?.ingress||[]).forEach((rule,index)=>{let url;try{url=new URL(rule.service)}catch(_){return}if(!['http:','https:','tcp:','ssh:','rdp:','smb:'].includes(url.protocol))return;const row=document.createElement('div');row.className='port-editor';const label=document.createElement('label');label.textContent=`${rule.hostname||'*'}${rule.path?' · '+rule.path:''}`;const input=document.createElement('input');input.type='number';input.min='1';input.max='65535';input.value=url.port||({'http:':80,'https:':443}[url.protocol]||'');input.addEventListener('input',()=>{if(!input.value)return;url.port=input.value;editingTunnelDetail.config.ingress[index].service=url.toString().replace(/\/$/,'');$('tunnel-edit-config').value=JSON.stringify(editingTunnelDetail.config,null,2)});row.append(label,input);box.append(row)});
 if(!box.children.length)box.textContent='No URL-based ingress services have editable ports.';
}
function renderTunnelLinks(){
 const detail=editingTunnelDetail;if(!detail)return;
 const ruleSelect=$('tunnel-link-rule');ruleSelect.replaceChildren();
 (detail.config.ingress||[]).forEach((rule,index)=>{if(!rule.hostname&&!rule.path)return;const option=document.createElement('option');option.value=String(index);option.textContent=`${rule.hostname||'*'}${rule.path?' · '+rule.path:''} → ${rule.service}`;ruleSelect.append(option)});
 const deviceSelect=$('tunnel-link-device');deviceSelect.replaceChildren();
 for(const d of data.filter(d=>d.mac).sort((a,b)=>(a.hostname||a.ip).localeCompare(b.hostname||b.ip))){const option=document.createElement('option');option.value=d.device_id;option.textContent=`${d.hostname||'Unnamed'} · ${d.ip} · ${d.mac}`;deviceSelect.append(option)}
 $('tunnel-link-save').disabled=!ruleSelect.options.length||!deviceSelect.options.length;
 const list=$('tunnel-links');list.replaceChildren();
 for(const link of detail.links||[]){const row=document.createElement('div');row.className='linked-origin';const device=data.find(d=>d.device_id===link.device_id);const text=document.createElement('span');text.textContent=`${link.hostname||'*'}${link.path?' · '+link.path:''} → ${device?.hostname||device?.ip||link.device_id} · ${link.message||link.state}`;const remove=document.createElement('button');remove.type='button';remove.textContent='Unlink';remove.addEventListener('click',()=>removeTunnelLink(link.id));row.append(text,remove);list.append(row)}
}
async function reloadTunnelDetail(){
 const r=await fetch('/api/cloudflare/tunnel?id='+encodeURIComponent(editingTunnel));const result=await r.json();if(!r.ok)throw Error(result.error||'Could not load tunnel');editingTunnelDetail=result;$('tunnel-edit-config').value=JSON.stringify(result.config,null,2);renderPortEditors();renderTunnelLinks();
}
async function removeTunnelLink(id){try{await post('/api/cloudflare/tunnels/link',{action:'delete',link_id:id});await reloadTunnelDetail()}catch(e){$('tunnel-edit-error').textContent=e.message}}
async function loadTunnels(){
 $('tunnels-meta').textContent='Loading tunnels…';
 try{
  const r=await fetch('/api/cloudflare/tunnels');
  if(!r.ok)throw Error('Request failed');
  renderTunnels(await r.json());
 }catch(e){renderTunnels({tunnels:[],error:'Could not load Cloudflare tunnels.'})}
}
async function openCreateRoute(){
 $('create-route-error').textContent='';
 const tunnel=$('create-route-tunnel');tunnel.replaceChildren();for(const t of tunnelInventory.filter(t=>t.editable)){const o=document.createElement('option');o.value=t.id;o.textContent=`${t.name} · ${t.status}`;tunnel.append(o)}
 const devices=$('create-route-device');devices.replaceChildren();for(const d of data.filter(d=>d.mac).sort((a,b)=>(a.hostname||a.ip).localeCompare(b.hostname||b.ip))){const o=document.createElement('option');o.value=d.device_id;o.textContent=`${d.hostname||'Unnamed'} · ${d.ip} · ${d.mac}`;devices.append(o)}
 const zones=$('create-route-zone');zones.replaceChildren();
 try{const r=await fetch('/api/cloudflare/zones');const result=await r.json();if(!r.ok||result.error)throw Error(result.error||'Could not load domains');zoneInventory=result.zones||[];for(const z of zoneInventory){const o=document.createElement('option');o.value=z.id;o.textContent=z.name;zones.append(o)}}catch(e){$('create-route-error').textContent=e.message}
 $('create-route-save').disabled=!tunnel.options.length||!zones.options.length||!devices.options.length;$('create-route-dialog').showModal();
}
function openDevice(d){
 selected=d.device_id;const routes=routesFor(selected);const local=routes.find(r=>r.kind==='local');const tunnel=routes.find(r=>r.kind==='tunnel');
 $('device-title').textContent=d.hostname||d.ip;$('device-identity').textContent=d.mac;$('device-current').textContent='Current IP: '+d.ip+' · Settings follow this MAC address.';
 $('local-enabled').checked=!!local?.enabled;$('tunnel-enabled').checked=!!tunnel?.enabled;
 $('local-host').value=(local?.hostname||'').replace(suffix,'');$('tunnel-host').value=(tunnel?.hostname||'').replace(suffix,'');$('tunnel-port').value=tunnel?.port||80;$('tunnel-protocol').value=tunnel?.protocol||'http';$('form-error').textContent='';updateFields();$('device-dialog').showModal();
}
function updateFields(){const local=$('local-enabled').checked,tunnel=$('tunnel-enabled').checked;$('local-host').disabled=!local;$('local-host').required=local;for(const id of ['tunnel-host','tunnel-port','tunnel-protocol'])$(id).disabled=!tunnel;$('tunnel-host').required=tunnel}
function updateDecoFields(){
 const on=$('deco-enabled').checked;
 for(const id of ['deco-host','deco-username','deco-password'])$(id).disabled=!on;
 $('deco-host').required=on;
}
function openSettings(){
 $('deco-enabled').checked=!!decoState.enabled;
 $('deco-host').value=decoState.host||'';
 $('deco-username').value=decoState.username||'admin';
 $('deco-password').value='';
 $('deco-password-hint').textContent=decoState.password_set?'Password is set. Leave blank to keep it.':'Password is stored only on this HomeScan host.';
 $('settings-error').textContent='';
 updateDecoFields();
 $('settings-dialog').showModal();
}
async function post(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const result=await r.json();if(!r.ok)throw Error(result.error||'Request failed');return result}
$('device-form').addEventListener('submit',async event=>{event.preventDefault();$('save-button').disabled=true;$('form-error').textContent='';try{await post('/api/cloudflare/settings',{device_id:selected,local:{enabled:$('local-enabled').checked,hostname:$('local-host').value},tunnel:{enabled:$('tunnel-enabled').checked,hostname:$('tunnel-host').value,protocol:$('tunnel-protocol').value,port:Number($('tunnel-port').value)}});$('device-dialog').close();await refresh()}catch(e){$('form-error').textContent=e.message}finally{$('save-button').disabled=false}});
$('settings-form').addEventListener('submit',async event=>{
 event.preventDefault();$('settings-save').disabled=true;$('settings-error').textContent='';
 try{
  const body={enabled:$('deco-enabled').checked,host:$('deco-host').value.trim(),username:$('deco-username').value.trim()||'admin'};
  const password=$('deco-password').value;
  if(password)body.password=password;
  decoState=await post('/api/deco/settings',body);
  $('settings-dialog').close();
  applyStatus();
 }catch(e){$('settings-error').textContent=e.message}
 finally{$('settings-save').disabled=false}
});
$('tunnel-form').addEventListener('submit',async event=>{
 event.preventDefault();$('tunnel-edit-save').disabled=true;$('tunnel-edit-error').textContent='';
 try{
  let config;try{config=JSON.parse($('tunnel-edit-config').value)}catch(_){throw Error('Configuration must be valid JSON.')}
  await post('/api/cloudflare/tunnels/update',{tunnel_id:editingTunnel,name:$('tunnel-edit-name').value,config});
  $('tunnel-dialog').close();await loadTunnels();
 }catch(e){$('tunnel-edit-error').textContent=e.message}
 finally{$('tunnel-edit-save').disabled=false}
});
$('tunnel-link-save').addEventListener('click',async()=>{
 $('tunnel-link-save').disabled=true;$('tunnel-edit-error').textContent='';
 try{const rule=editingTunnelDetail.config.ingress[Number($('tunnel-link-rule').value)];await post('/api/cloudflare/tunnels/link',{tunnel_id:editingTunnel,hostname:rule.hostname||'',path:rule.path||'',device_id:$('tunnel-link-device').value});await reloadTunnelDetail()}
 catch(e){$('tunnel-edit-error').textContent=e.message}finally{$('tunnel-link-save').disabled=false}
});
$('create-route-form').addEventListener('submit',async event=>{event.preventDefault();$('create-route-save').disabled=true;$('create-route-error').textContent='';try{await post('/api/cloudflare/tunnels/create-route',{tunnel_id:$('create-route-tunnel').value,zone_id:$('create-route-zone').value,hostname:$('create-route-host').value,device_id:$('create-route-device').value,protocol:$('create-route-protocol').value,port:Number($('create-route-port').value)});$('create-route-dialog').close();$('create-route-host').value='';await loadTunnels();await refresh()}catch(e){$('create-route-error').textContent=e.message}finally{$('create-route-save').disabled=false}});
for(const id of ['local-enabled','tunnel-enabled'])$(id).addEventListener('change',updateFields);
$('deco-enabled').addEventListener('change',updateDecoFields);
for(const button of document.querySelectorAll('[data-close]'))button.addEventListener('click',()=>$(button.dataset.close).close());
$('connection-button').addEventListener('click',()=>{$('connection-status').textContent=cf.configured?'Connected to '+cf.zone+(cf.tunnel_configured?' with tunnel support.':' for local DNS.'):'Cloudflare is not connected yet.';$('connection-dialog').showModal()});
$('settings-button').addEventListener('click',openSettings);
$('tunnels-refresh').addEventListener('click',loadTunnels);
$('tunnel-create').addEventListener('click',openCreateRoute);
$('sync-button').addEventListener('click',async()=>{try{await post('/api/cloudflare/sync',{});$('cloud-state').textContent='Cloudflare sync queued…'}catch(e){$('notice').textContent=e.message}});
$('search').addEventListener('input',render);
$('filter-status').addEventListener('change',render);
$('filter-cloudflare').addEventListener('change',render);
for(const button of document.querySelectorAll('button.sort'))button.addEventListener('click',()=>{if(sortKey===button.dataset.sort)sortDir*=-1;else{sortKey=button.dataset.sort;sortDir=1}render()});
function applyStatus(){
 $('cloud-state').textContent=cf.configured?'Cloudflare connected · '+cf.zone:'Cloudflare not connected · Configure devices, then connect your account';
 $('sync-button').disabled=!cf.configured;
 if(!decoState.configured)$('deco-state').textContent='Deco: not configured';
 else if(!decoState.enabled)$('deco-state').textContent='Deco: off';
 else if(decoState.auth_cooldown)$('deco-state').textContent='Deco: auth cooldown';
 else $('deco-state').textContent='Deco: on · '+(decoState.host||'mesh');
}
function apply(j){
 data=j.devices;cf=j.cloudflare;decoState=j.deco||decoState;
 if(cf.suffix){suffix='.'+cf.suffix;for(const el of document.querySelectorAll('.hostname-input span'))el.textContent=suffix}
 $('total').textContent=data.length;$('online').textContent=data.filter(d=>d.online).length;$('route-count').textContent=cf.routes.filter(r=>r.enabled).length;
 $('status').textContent=j.stale?'Awaiting scanner':'● Scanner active';
 $('notice').textContent=j.latest?.error?'Last network scan failed: '+j.latest.error:j.stale?'No recent scan received. Check the scanner service.':'';
 applyStatus();
 $('meta').textContent=j.network+' · Scans every 60 seconds · '+(j.latest?'Last attempt: '+new Date(j.latest.finished).toLocaleString():'No scans yet');
 render();
}
async function refresh(){try{const r=await fetch('/api/devices');if(!r.ok)throw Error('Request failed');apply(await r.json())}catch(e){$('status').textContent='Connection lost';$('notice').textContent='Cannot reach HomeScan. Retrying…'}}
function connect(){const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws');ws.addEventListener('message',e=>{try{apply(JSON.parse(e.data))}catch(_){}});ws.addEventListener('close',()=>{$('status').textContent='Connection lost';$('notice').textContent='Cannot reach HomeScan. Retrying…';setTimeout(connect,2000)});ws.addEventListener('error',()=>ws.close())}
refresh();connect();loadTunnels();
