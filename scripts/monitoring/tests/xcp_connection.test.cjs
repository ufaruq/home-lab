'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const source=path.resolve(__dirname,'../../../monitoring/xcp/reconcile-host.cjs');
const id='11111111-1111-4111-8111-111111111111',hostId='22222222-2222-4222-8222-222222222222',poolId='33333333-3333-4333-8333-333333333333',duplicate='44444444-4444-4444-8444-444444444444';
const config={server_id:id,previous_host:'10.10.0.10',host:'192.168.10.10',host_id:hostId,pool_id:poolId,host_name:'example-host',certificate_sha256:'a'.repeat(64),duplicate_server_id:duplicate};
function implementation(){assert.ok(fs.existsSync(source),'Host connection repair is not implemented');return require(source);}
function fixture(){
 const servers={[id]:{id,host:config.previous_host,enabled:true,status:'connecting',allowUnauthorized:true},[duplicate]:{id:duplicate,host:config.host,enabled:true,status:'disconnected',error:{code:'SESSION_AUTHENTICATION_FAILED'}}};
 const calls=[];let mismatch=false,authenticationFails=false;
 async function call(method,p={}){calls.push([method,p]);
  if(method==='server.getAll')return Object.values(servers).map(x=>({...x}));
  if(method==='xo.getAllObjects')return {[hostId]:{type:'host',id:hostId,name_label:mismatch?'different':'example-host',$pool:poolId}};
  const s=servers[p.id];assert.ok(s);
  if(method==='server.disable'){s.enabled=false;s.status='disconnected';return;}
  if(method==='server.set'){assert.deepEqual(Object.keys(p).sort(),['host','id']);s.host=p.host;return;}
  if(method==='server.enable'){if(authenticationFails&&s.host===config.host)throw new Error('private authentication details');s.enabled=true;s.status='connected';s.poolId=poolId;return;}
  throw new Error('Unexpected method');
 }
 return {servers,calls,call,mismatch:()=>{mismatch=true;},authFailure:()=>{authenticationFails=true;}};
}
test('repairs only the stale endpoint while retaining saved credentials and TLS options',async()=>{
 const f=fixture();let probed=false;
 const result=await implementation().reconcileConnection(f.call,config,async(host,pin)=>{assert.equal(host,config.host);assert.equal(pin,config.certificate_sha256);probed=true;},async()=>{});
 assert.ok(probed);assert.equal(result.changed,true);assert.equal(f.servers[id].host,config.host);assert.equal(f.servers[id].allowUnauthorized,true);assert.equal(f.servers[duplicate].enabled,false);
 assert.ok(!JSON.stringify(f.calls).includes('password'));
});
test('a healthy exact connection reconciles without changes',async()=>{
 const f=fixture();Object.assign(f.servers[id],{host:config.host,status:'connected',poolId,enabled:true});f.servers[duplicate].enabled=false;
 const result=await implementation().reconcileConnection(f.call,config,async()=>{},async()=>{});
 assert.equal(result.changed,false);assert.ok(f.calls.every(([m])=>['server.getAll','xo.getAllObjects'].includes(m)));
});
test('a TLS fingerprint mismatch prevents every mutation',async()=>{
 const f=fixture();await assert.rejects(()=>implementation().reconcileConnection(f.call,config,async()=>{throw new Error('certificate mismatch');}),/certificate|pin/i);
 assert.ok(f.calls.every(([m])=>['server.getAll','xo.getAllObjects'].includes(m)));
});
test('unexpected saved endpoint or a live duplicate is refused before mutation',async()=>{
 for(const variant of ['host','duplicate']){
  const f=fixture();if(variant==='host')f.servers[id].host='192.168.20.20';else f.servers[duplicate].status='connected';
  await assert.rejects(()=>implementation().reconcileConnection(f.call,config,async()=>{},async()=>{}));
  assert.ok(f.calls.every(([m])=>['server.getAll','xo.getAllObjects'].includes(m)));
 }
});
test('a wrong post-connect identity restores the original endpoint',async()=>{
 const f=fixture();f.mismatch();await assert.rejects(()=>implementation().reconcileConnection(f.call,config,async()=>{},async()=>{}),/identity|rollback/i);
 assert.equal(f.servers[id].host,config.previous_host);assert.equal(f.servers[duplicate].enabled,true);
});
test('authentication failure rolls back without exposing the raw API exception',async()=>{
 const f=fixture();f.authFailure();await assert.rejects(()=>implementation().reconcileConnection(f.call,config,async()=>{},async()=>{}),e=>!e.message.includes('private'));
 assert.equal(f.servers[id].host,config.previous_host);
});
test('repair input rejects public destinations, credential fields and malformed pins',()=>{
 const {validateConnection}=implementation();
 for(const patch of [{host:'8.8.8.8'},{host:'127.0.0.1'},{certificate_sha256:'bad'},{password:'never-copy-host-credentials'}])assert.throws(()=>validateConnection({...config,...patch}));
 assert.doesNotThrow(()=>validateConnection(config));
});
test('a healthy primary can retire only an explicitly declared stale unreachable duplicate',async()=>{
 const f=fixture();Object.assign(f.servers[id],{host:config.host,status:'connected',poolId,enabled:true});
 Object.assign(f.servers[duplicate],{host:config.previous_host,error:{code:'EHOSTUNREACH'}});
 const result=await implementation().reconcileConnection(f.call,{...config,duplicate_host:config.previous_host},async()=>{},async()=>{});
 assert.equal(result.connected,true);assert.equal(f.servers[id].status,'connected');assert.equal(f.servers[duplicate].enabled,false);
 assert.deepEqual(f.calls.filter(([m])=>!['server.getAll','xo.getAllObjects'].includes(m)),[['server.disable',{id:duplicate}]]);
});
test('a failed duplicate cleanup never disconnects a healthy primary',async()=>{
 const f=fixture();Object.assign(f.servers[id],{host:config.host,status:'connected',poolId,enabled:true});
 const call=async(m,p)=>{if(m==='server.disable'&&p.id===duplicate)throw new Error('private raw error');return f.call(m,p);};
 await assert.rejects(()=>implementation().reconcileConnection(call,config,async()=>{},async()=>{}),e=>!e.message.includes('private'));
 assert.equal(f.servers[id].status,'connected');assert.ok(!f.calls.some(([m])=>['server.disable','server.enable','server.set'].includes(m)));
});
