'use strict';
const BASE=(document.querySelector('meta[name="homescan-base"]')||{}).content||'';
const url=path=>BASE+path;
const $=id=>document.getElementById(id);
let data=[],cf={routes:[],configured:false},decoState={enabled:false,configured:false},haState={enabled:false,role:'',scanning:true},scanNetworks=[],selected=null,editingTunnel=null,editingTunnelDetail=null,tunnelInventory=[],zoneInventory=[];
let sortKey='hostname',sortDir=1;
let suffix='';
let socket=null,reconnectTimer=0,pollTimer=0,haveData=false,live=false,backoff=2000,refreshing=false;
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
  const action=cell(tr,'');action.className='row-actions';
  const edit=document.createElement('button');edit.textContent='Edit';edit.disabled=!t.editable;edit.title=t.editable?'Edit tunnel name and ingress configuration':'Locally managed tunnels must be edited in their local configuration';edit.addEventListener('click',()=>openTunnel(t.id));action.append(edit);
  const remove=document.createElement('button');remove.textContent='Delete';remove.className='danger';remove.disabled=!t.editable||t.homescan;remove.title=t.homescan?'The HomeScan tunnel cannot be deleted here':t.editable?'Delete this Cloudflare tunnel and its public hostnames':'Locally managed tunnels must be deleted in their local configuration';remove.addEventListener('click',()=>deleteTunnel(t));action.append(remove);
  body.append(tr);
 }
}
async function deleteTunnel(t){
 if(!confirm(`Delete tunnel "${t.name||t.id}" and clean up its public hostnames? This cannot be undone.`))return;
 try{await post('/api/cloudflare/tunnels/delete',{tunnel_id:t.id});if(editingTunnel===t.id)$('tunnel-dialog').close();await loadTunnels()}
 catch(e){alert(e.message)}
}
async function openTunnel(id){
 editingTunnel=id;$('tunnel-edit-error').textContent='';$('tunnel-edit-save').disabled=true;
 $('tunnel-edit-id').textContent=id;$('tunnel-edit-name').value='Loading…';$('tunnel-edit-config').value='';$('tunnel-dialog').showModal();
 try{
  const r=await fetch(url('/api/cloudflare/tunnel?id='+encodeURIComponent(id)));const result=await r.json();if(!r.ok)throw Error(result.error||'Could not load tunnel');
  editingTunnelDetail=result;$('tunnel-edit-name').value=result.name;$('tunnel-edit-config').value=JSON.stringify(result.config,null,2);renderPortEditors();renderTunnelLinks();$('tunnel-edit-save').disabled=false;
 }catch(e){$('tunnel-edit-error').textContent=e.message}
}
function syncIngressService(index,url){
 editingTunnelDetail.config.ingress[index].service=url.toString().replace(/\/$/,'');
 $('tunnel-edit-config').value=JSON.stringify(editingTunnelDetail.config,null,2);
}
function renderPortEditors(){
 const box=$('tunnel-rule-ports');box.replaceChildren();
 (editingTunnelDetail?.config?.ingress||[]).forEach((rule,index)=>{
  if(!rule.hostname&&!rule.path)return;
  let url;try{url=new URL(rule.service)}catch(_){url=null}
  const row=document.createElement('div');row.className='port-editor';
  const label=document.createElement('label');label.textContent=`${rule.hostname||'*'}${rule.path?' · '+rule.path:''}`;
  row.append(label);
  if(url&&['http:','https:','tcp:','ssh:','rdp:','smb:'].includes(url.protocol)){
   const host=document.createElement('input');host.type='text';host.value=url.hostname||'';host.placeholder='192.168.1.10';host.autocomplete='off';host.spellcheck=false;host.title='Origin host (LAN IP or hostname the connector can reach)';
   host.addEventListener('input',()=>{if(!host.value.trim())return;url.hostname=host.value.trim();syncIngressService(index,url)});
   const port=document.createElement('input');port.type='number';port.min='1';port.max='65535';port.value=url.port||({'http:':80,'https:':443}[url.protocol]||'');port.title='Origin port';
   port.addEventListener('input',()=>{if(!port.value)return;url.port=port.value;syncIngressService(index,url)});
   row.append(host,port);
  }else{
   const note=document.createElement('span');note.className='port-spacer';note.textContent=rule.service||'—';note.title='Non-URL origin; edit JSON below';row.append(note);
  }
  const remove=document.createElement('button');remove.type='button';remove.textContent='Delete';remove.className='danger';remove.title='Delete this public hostname';
  remove.addEventListener('click',()=>deleteTunnelHostname(rule));row.append(remove);box.append(row);
 });
 if(!box.children.length)box.textContent='No public hostnames on this tunnel yet.';
}
async function deleteTunnelHostname(rule){
 const label=`${rule.hostname||'*'}${rule.path?' · '+rule.path:''}`;
 if(!confirm(`Delete public hostname ${label}? DNS pointing at this tunnel will be cleaned up when possible.`))return;
 $('tunnel-edit-error').textContent='';
 try{
  const result=await post('/api/cloudflare/tunnels/delete-hostname',{tunnel_id:editingTunnel,hostname:rule.hostname||'',path:rule.path||''});
  editingTunnelDetail=result;$('tunnel-edit-config').value=JSON.stringify(result.config,null,2);renderPortEditors();renderTunnelLinks();await loadTunnels();
 }catch(e){$('tunnel-edit-error').textContent=e.message}
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
 const r=await fetch(url('/api/cloudflare/tunnel?id='+encodeURIComponent(editingTunnel)));const result=await r.json();if(!r.ok)throw Error(result.error||'Could not load tunnel');editingTunnelDetail=result;$('tunnel-edit-config').value=JSON.stringify(result.config,null,2);renderPortEditors();renderTunnelLinks();
}
async function removeTunnelLink(id){try{await post('/api/cloudflare/tunnels/link',{action:'delete',link_id:id});await reloadTunnelDetail()}catch(e){$('tunnel-edit-error').textContent=e.message}}
async function loadTunnels(){
 $('tunnels-meta').textContent='Loading tunnels…';
 try{
  const r=requireAuth(await fetch(url('/api/cloudflare/tunnels')));
  if(!r.ok)throw Error('Request failed');
  renderTunnels(await r.json());
 }catch(e){
  if(e.message==='Sign in required.')return;
  renderTunnels({tunnels:[],error:'Could not load Cloudflare tunnels.'})
 }
}
function fillZoneSelect(select,selectedId,filter=''){
 const q=String(filter||'').trim().toLowerCase();
 const rows=q?zoneInventory.filter(z=>z.name.toLowerCase().includes(q)):zoneInventory.slice();
 select.replaceChildren();
 if(!rows.length){const o=document.createElement('option');o.value='';o.textContent=q?'No domains match this filter':'No domains on this token';select.append(o);return}
 for(const z of rows){const o=document.createElement('option');o.value=z.id;o.textContent=z.name;select.append(o)}
 if(selectedId){
  if([...select.options].some(o=>o.value===selectedId))select.value=selectedId;
  else{
   const keep=zoneInventory.find(z=>z.id===selectedId);
   if(keep){const o=document.createElement('option');o.value=keep.id;o.textContent=keep.name;select.prepend(o);select.value=keep.id}
  }
 }
}
async function loadZones(){
 const r=requireAuth(await fetch(url('/api/cloudflare/zones')));
 const result=await r.json();
 if(!r.ok||result.error)throw Error(result.error||'Could not load domains');
 zoneInventory=result.zones||[];
 return zoneInventory;
}
async function openCreateRoute(preferredTunnel,preferredDevice){
 $('create-route-error').textContent='';$('create-route-host').value='';
 const tunnel=$('create-route-tunnel');tunnel.replaceChildren();for(const t of tunnelInventory.filter(t=>t.editable)){const o=document.createElement('option');o.value=t.id;o.textContent=`${t.name} · ${t.status}`;tunnel.append(o)}
 if(preferredTunnel)tunnel.value=preferredTunnel;
 const devices=$('create-route-device');devices.replaceChildren();for(const d of data.filter(d=>d.mac).sort((a,b)=>(a.hostname||a.ip).localeCompare(b.hostname||b.ip))){const o=document.createElement('option');o.value=d.device_id;o.textContent=`${d.hostname||'Unnamed'} · ${d.ip} · ${d.mac}`;devices.append(o)}
 if(preferredDevice)devices.value=preferredDevice;
 const zones=$('create-route-zone');
 try{await loadZones();fillZoneSelect(zones,cf.zone_id||'')}catch(e){$('create-route-error').textContent=e.message;zones.replaceChildren()}
 $('create-route-save').disabled=!tunnel.options.length||!zones.options.length||!devices.options.length;$('create-route-dialog').showModal();
}
function openDevice(d){
 selected=d.device_id;const routes=routesFor(selected);const local=routes.find(r=>r.kind==='local');const tunnel=routes.find(r=>r.kind==='tunnel');
 $('device-title').textContent=d.hostname||d.ip;$('device-identity').textContent=d.mac;$('device-current').textContent='Current IP: '+d.ip+' · Settings follow this MAC address.';
 $('local-enabled').checked=!!local?.enabled;$('tunnel-enabled').checked=!!tunnel?.enabled;
 $('local-host').value=(local?.hostname||'').endsWith(suffix)?(local.hostname||'').slice(0,-suffix.length):(local?.hostname||'');
 const tunnelHost=tunnel?.hostname||'';
 $('tunnel-host').value=tunnelHost.endsWith(suffix)?tunnelHost.slice(0,-suffix.length):tunnelHost;
 $('tunnel-port').value=tunnel?.port||80;$('tunnel-protocol').value=tunnel?.protocol||'http';$('form-error').textContent='';updateFields();$('device-dialog').showModal();
}
function updateFields(){const local=$('local-enabled').checked,tunnel=$('tunnel-enabled').checked;$('local-host').disabled=!local;$('local-host').required=local;for(const id of ['tunnel-host','tunnel-port','tunnel-protocol'])$(id).disabled=!tunnel;$('tunnel-host').required=tunnel}
function updateDecoFields(){
 const on=$('deco-enabled').checked;
 for(const id of ['deco-host','deco-username','deco-password'])$(id).disabled=!on;
 $('deco-host').required=on;
}
function updateDnsZoneCount(){
 const el=$('dns-zone-count');
 if(!el)return;
 const n=zoneInventory.length;
 if(!n){el.textContent='No domains visible to this API token.';return}
 el.textContent=n+' domain'+(n===1?'':'s')+' available to this API token.'+(n<5?' Recreate the token with Zone Resources → All zones from an account to see the rest.':'');
}
async function fillSettingsDomain(){
 const select=$('dns-zone');
 const placeholder=(text)=>{select.replaceChildren();const o=document.createElement('option');o.value='';o.textContent=text;select.append(o);select.required=false;if($('dns-zone-filter'))$('dns-zone-filter').disabled=true;updateDnsZoneCount()};
 if(!cf.configured){placeholder('Connect Cloudflare to load domains');select.disabled=true;return}
 select.disabled=false;if($('dns-zone-filter'))$('dns-zone-filter').disabled=false;
 try{
  await loadZones();
  if(!zoneInventory.length){placeholder('No domains on this token');return}
  const current=zoneInventory.find(z=>z.id===cf.zone_id)||zoneInventory.find(z=>z.name===cf.zone)||zoneInventory.find(z=>cf.suffix===z.name||(cf.suffix||'').endsWith('.'+z.name))||zoneInventory[0];
  fillZoneSelect(select,current.id,$('dns-zone-filter')?.value||'');
  select.required=true;
  updateDnsZoneCount();
 }catch(e){placeholder(e.message||'Could not load domains')}
}
async function openSettings(){
 $('scan-networks').textContent=(scanNetworks||[]).join('\n')||'No reachable private subnet found yet.';
 $('deco-enabled').checked=!!decoState.enabled;
 $('deco-host').value=decoState.host||'';
 $('deco-username').value=decoState.username||'admin';
 $('deco-password').value='';
 $('deco-password-hint').textContent=decoState.password_set?'Password is set. Leave blank to keep it.':'Password is stored only on this HomeScan host.';
 $('settings-error').textContent='';
 updateDecoFields();
 $('dns-zone').replaceChildren();
 const loading=document.createElement('option');loading.value='';loading.textContent='Loading domains…';$('dns-zone').append(loading);
 $('settings-dialog').showModal();
 await fillSettingsDomain();
}
function requireAuth(r){if(r.status===401){location.replace(url('/login'));throw Error('Sign in required.')}return r}
async function post(path,body){const r=requireAuth(await fetch(url(path),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));const result=await r.json();if(!r.ok)throw Error(result.error||'Request failed');return result}
$('device-form').addEventListener('submit',async event=>{event.preventDefault();$('save-button').disabled=true;$('form-error').textContent='';try{await post('/api/cloudflare/settings',{device_id:selected,local:{enabled:$('local-enabled').checked,hostname:$('local-host').value},tunnel:{enabled:$('tunnel-enabled').checked,hostname:$('tunnel-host').value,protocol:$('tunnel-protocol').value,port:Number($('tunnel-port').value)}});$('device-dialog').close();await refresh()}catch(e){$('form-error').textContent=e.message}finally{$('save-button').disabled=false}});
$('settings-form').addEventListener('submit',async event=>{
 event.preventDefault();$('settings-save').disabled=true;$('settings-error').textContent='';
 try{
  if(cf.configured){
   const zoneId=$('dns-zone').value;
   if(!zoneId)throw Error('Choose a Cloudflare zone.');
   const zone=zoneInventory.find(z=>z.id===zoneId);
   const domain=await post('/api/cloudflare/domain',{zone_id:zoneId,suffix:zone?.name||'',dns_subnet:''});
   cf.suffix=domain.suffix;cf.zone=domain.zone||domain.suffix;cf.zone_id=domain.zone_id||zoneId;cf.dns_subnet='';
   if(cf.suffix){suffix='.'+cf.suffix;for(const el of document.querySelectorAll('.hostname-input span,.dns-suffix-label'))el.textContent=suffix}
   else{suffix='';for(const el of document.querySelectorAll('.hostname-input span,.dns-suffix-label'))el.textContent='.(set Cloudflare zone)'}
  }
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
$('create-route-form').addEventListener('submit',async event=>{event.preventDefault();$('create-route-save').disabled=true;$('create-route-error').textContent='';try{const created=await post('/api/cloudflare/tunnels/create-route',{tunnel_id:$('create-route-tunnel').value,zone_id:$('create-route-zone').value,hostname:$('create-route-host').value,device_id:$('create-route-device').value,protocol:$('create-route-protocol').value,port:Number($('create-route-port').value)});$('create-route-host').value='';$('create-route-error').textContent='';await loadTunnels();await refresh();$('create-route-host').placeholder=created.hostname?`Added ${created.hostname}. Add another?`:'files'}catch(e){$('create-route-error').textContent=e.message}finally{$('create-route-save').disabled=false}});
for(const id of ['local-enabled','tunnel-enabled'])$(id).addEventListener('change',updateFields);
$('deco-enabled').addEventListener('change',updateDecoFields);
for(const button of document.querySelectorAll('[data-close]'))button.addEventListener('click',()=>$(button.dataset.close).close());
function openConnection(){
 $('connection-status').textContent=cf.configured?'Connected to '+cf.zone+(cf.tunnel_configured?' with tunnel support.':' for local DNS.'):'Cloudflare is not connected yet.';
 $('cf-token').value='';
 $('cf-token').placeholder=cf.configured?'Leave blank to keep the current token':'Paste Cloudflare API token';
 $('cf-token').required=!cf.configured;
 $('cf-token-hint').textContent=cf.configured?'A token is already saved. Paste a new one only when rotating credentials.':'The token is stored only on this HomeScan host and is never shown again.';
 $('cf-tunnel').checked=cf.configured?!!cf.tunnel_configured:true;
 $('connection-error').textContent='';
 $('connection-dialog').showModal();
}
$('connection-button').addEventListener('click',openConnection);
$('connection-form').addEventListener('submit',async event=>{
 event.preventDefault();$('connection-save').disabled=true;$('connection-error').textContent='';
 try{
  const body={tunnel:$('cf-tunnel').checked};
  const token=$('cf-token').value.trim();
  if(token)body.api_token=token;
  const result=await post('/api/cloudflare/connect',body);
  cf.configured=!!result.configured;cf.zone=result.zone||cf.zone;cf.tunnel_configured=!!result.tunnel_configured;
  cf.database=result.database||cf.database||{shared:!!result.database_shared};
  applyStatus();$('connection-dialog').close();await refresh();await loadTunnels();
 }catch(e){$('connection-error').textContent=e.message}
 finally{$('connection-save').disabled=false}
});
$('logout-button').addEventListener('click',async()=>{try{await fetch(url('/api/logout'),{method:'POST'})}catch(_){}location.replace(url('/login'))});
$('settings-button').addEventListener('click',openSettings);
$('tunnels-refresh').addEventListener('click',loadTunnels);
$('tunnel-create').addEventListener('click',()=>openCreateRoute());
$('tunnel-add-hostname').addEventListener('click',()=>{
 const linked=$('tunnel-link-device').value||editingTunnelDetail?.links?.[0]?.device_id||'';
 $('tunnel-dialog').close();openCreateRoute(editingTunnel,linked);
});
$('sync-button').addEventListener('click',async()=>{try{await post('/api/cloudflare/sync',{});$('cloud-state').textContent='Cloudflare sync queued…'}catch(e){$('notice').textContent=e.message}});
$('dns-zone-filter')?.addEventListener('input',()=>{
 fillZoneSelect($('dns-zone'),$('dns-zone').value,$('dns-zone-filter').value);
});
$('search').addEventListener('input',render);
$('filter-status').addEventListener('change',render);
$('filter-cloudflare').addEventListener('change',render);
for(const button of document.querySelectorAll('button.sort'))button.addEventListener('click',()=>{if(sortKey===button.dataset.sort)sortDir*=-1;else{sortKey=button.dataset.sort;sortDir=1}render()});
function applyStatus(){
 const dbLabel=cf.database?.kind==='durable-object'?' · shared DO memory':'';
 $('cloud-state').textContent=cf.configured?'Cloudflare connected · '+cf.zone+dbLabel:'Cloudflare not connected · Configure devices, then connect your account';
 $('sync-button').disabled=!cf.configured;
 if(!decoState.configured)$('deco-state').textContent='Deco: not configured';
 else if(!decoState.enabled)$('deco-state').textContent='Deco: off';
 else if(decoState.auth_cooldown)$('deco-state').textContent='Deco: auth cooldown';
 else $('deco-state').textContent='Deco: on · '+(decoState.host||'mesh');
 if(!haState.enabled)$('ha-state').textContent='Cluster: off';
 else if(haState.role==='leader'){
  const dnsWarn=String(haState.message||'').includes('DNS update failed')||String(haState.message||'').includes('cluster store unavailable');
  $('ha-state').textContent=dnsWarn
    ?('Cluster: active · '+(haState.local_ip||haState.hostname||'leader')+' · DNS offline')
    :('Cluster: active · '+(haState.local_ip||haState.hostname||'leader'));
 }
 else if(haState.role==='follower')$('ha-state').textContent='Cluster: standby · '+(haState.leader?.ip||haState.hostname||'watching');
 else $('ha-state').textContent='Cluster: '+(haState.message||haState.role||'starting');
}
function inventoryNotice(j){
 return j.latest?.error?'Last network scan failed: '+j.latest.error:j.stale?'No recent scan received. Check the scanner service.':'';
}
function apply(j){
 if(!j||!Array.isArray(j.devices)||!j.cloudflare||!Array.isArray(j.cloudflare.routes))return;
 haveData=true;backoff=2000;
 data=j.devices;cf=j.cloudflare;decoState=j.deco||decoState;haState=j.ha||haState;scanNetworks=Array.isArray(j.networks)?j.networks:scanNetworks;
 if(cf.suffix){suffix='.'+cf.suffix;for(const el of document.querySelectorAll('.hostname-input span,.dns-suffix-label'))el.textContent=suffix}
 else{suffix='';for(const el of document.querySelectorAll('.hostname-input span,.dns-suffix-label'))el.textContent='.(set Cloudflare zone)'}
 $('total').textContent=data.length;$('online').textContent=data.filter(d=>d.online).length;$('route-count').textContent=cf.routes.filter(r=>r.enabled).length;
 if(haState.enabled&&haState.role==='follower')$('status').textContent='Standby node';
 else $('status').textContent=j.stale?'Awaiting scanner':'● Scanner active';
 $('notice').textContent=haState.enabled&&haState.role==='follower'
  ?('Standby. Leader is '+(haState.leader?.ip||haState.hostname)+'. Scans are accepted only on the active node.')
  :inventoryNotice(j);
 applyStatus();
 $('meta').textContent=j.network+' · Scans every 60 seconds · '+(j.latest?'Last attempt: '+new Date(j.latest.finished).toLocaleString():'No scans yet');
 render();
}
function markDown(){
 $('status').textContent='Connection lost';
 $('notice').textContent=haveData?'Cannot refresh inventory. Retrying…':'Cannot reach HomeScan. Retrying…';
}
function schedulePoll(delay){
 clearTimeout(pollTimer);
 pollTimer=setTimeout(()=>{refresh()},delay);
}
async function refresh(){
 if(refreshing)return;
 refreshing=true;
 try{
  const r=requireAuth(await fetch(url('/api/devices')));
  if(!r.ok)throw Error('Request failed');
  apply(await r.json());
  if(!live)schedulePoll(5000);
 }catch(e){
  if(e.message==='Sign in required.')return;
  markDown();
  schedulePoll(backoff);
  backoff=Math.min(Math.round(backoff*1.5),15000);
 }finally{refreshing=false}
}
function connect(){
 clearTimeout(reconnectTimer);
 const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+url('/ws'));
 socket=ws;
 ws.addEventListener('open',()=>{live=true});
 ws.addEventListener('message',e=>{
  try{apply(JSON.parse(e.data));live=true;clearTimeout(pollTimer)}catch(_){}
 });
 ws.addEventListener('close',()=>{
  if(socket!==ws)return;
  live=false;
  if(haveData)$('status').textContent='Reconnecting…';
  else markDown();
  schedulePoll(500);
  reconnectTimer=setTimeout(connect,2000);
 });
 ws.addEventListener('error',()=>ws.close());
}
refresh();connect();loadTunnels();
