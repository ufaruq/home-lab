'use strict';
const fs=require('node:fs'),tls=require('node:tls'),net=require('node:net'),crypto=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function privateAddress(host){
  if(net.isIP(host)!==4)return false;
  const [a,b]=host.split('.').map(Number);
  return a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168);
}
function validateConnection(c){
  const keys=['server_id','previous_host','host','host_id','pool_id','host_name','certificate_sha256','duplicate_server_id','duplicate_host'];
  if(!c||Object.keys(c).some(x=>!keys.includes(x))||!['server_id','host_id','pool_id'].every(k=>UUID.test(c[k]||''))||!privateAddress(c.host)||!privateAddress(c.previous_host)||!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$/.test(c.host_name||'')||!/^[0-9a-f]{64}$/.test(c.certificate_sha256||'')||(c.duplicate_server_id!==undefined&&(!UUID.test(c.duplicate_server_id)||c.duplicate_server_id===c.server_id)))throw new Error('invalid_host_connection_input');
  if(c.duplicate_host!==undefined&&(!c.duplicate_server_id||!privateAddress(c.duplicate_host)))throw new Error('invalid_duplicate_host_input');
  return c;
}
function probeCertificate(host,fingerprint){
  return new Promise((resolve,reject)=>{
    // The certificate is authenticated against the exact pin obtained over
    // independently pinned host SSH; no credentials are sent by this probe.
    const socket=tls.connect({host,port:443,rejectUnauthorized:false});
    let settled=false;
    const finish=error=>{if(settled)return;settled=true;socket.destroy();error?reject(new Error(error)):resolve();};
    socket.setTimeout(5000,()=>finish('host_tls_probe_timeout'));
    socket.on('error',()=>finish('host_tls_probe_unreachable'));
    socket.on('secureConnect',()=>{
      const raw=socket.getPeerCertificate().raw;
      if(!raw)return finish('host_tls_certificate_missing');
      const actual=crypto.createHash('sha256').update(raw).digest();
      finish(crypto.timingSafeEqual(actual,Buffer.from(fingerprint,'hex'))?undefined:'host_tls_certificate_pin_mismatch');
    });
  });
}
async function reconcileConnection(call,c,probe=probeCertificate,delay=ms=>new Promise(r=>setTimeout(r,ms))){
  validateConnection(c);
  const all=Object.values(await call('server.getAll')),server=all.find(x=>x.id===c.server_id),duplicate=all.find(x=>x.id===c.duplicate_server_id);
  if(!server||![c.previous_host,c.host].includes(server.host))throw new Error('unexpected_saved_host_connection');
  if(c.duplicate_server_id&&(!duplicate||duplicate.host!==(c.duplicate_host||c.host)||duplicate.status==='connected'||(duplicate.enabled&&!['SESSION_AUTHENTICATION_FAILED','EHOSTUNREACH','UND_ERR_CONNECT_TIMEOUT','ECONNREFUSED'].includes(duplicate.error?.code))))throw new Error('unexpected_duplicate_connection');
  if(all.some(x=>x.id!==c.server_id&&x.id!==c.duplicate_server_id&&x.host===c.host&&x.enabled))throw new Error('unowned_duplicate_connection');
  await probe(c.host,c.certificate_sha256);
  const identity=async()=>{
    const objects=await call('xo.getAllObjects'),host=objects[c.host_id];
    return host?.type==='host'&&host.id===c.host_id&&host.name_label===c.host_name&&(host.$pool===c.pool_id||host.$poolId===c.pool_id);
  };
  const healthy=server.host===c.host&&server.status==='connected'&&server.poolId===c.pool_id;
  if(healthy&&!(await identity()))throw new Error('connected_host_identity_mismatch');
  if(healthy){
    if(!duplicate?.enabled)return {changed:false,connected:true,duplicate_disabled:!!duplicate};
    try{await call('server.disable',{id:duplicate.id});}
    catch{throw new Error('host_connection_duplicate_disable_failed');}
    return {changed:true,connected:true,duplicate_disabled:true};
  }
  let phase='disconnect';
  try{
    if(!healthy){
      await call('server.disable',{id:c.server_id});
      phase='address';
      if(server.host!==c.host)await call('server.set',{id:c.server_id,host:c.host});
      phase='authenticate';
      await call('server.enable',{id:c.server_id});
      phase='identity';
      let verified=false;
      for(let i=0;i<8;i++){if(await identity()){verified=true;break;}await delay(1000);}
      if(!verified)throw new Error('connected_host_identity_mismatch');
      const current=Object.values(await call('server.getAll')).find(x=>x.id===c.server_id);
      if(current?.status!=='connected'||current.poolId!==c.pool_id)throw new Error('connected_pool_identity_mismatch');
    }
    phase='duplicate';
    if(duplicate?.enabled)await call('server.disable',{id:duplicate.id});
    return {changed:true,connected:true,duplicate_disabled:!!duplicate};
  }catch{
    let category='source_unavailable';
    try{
      const failed=Object.values(await call('server.getAll')).find(x=>x.id===c.server_id);
      const code=failed?.error?.code;
      if(['SESSION_AUTHENTICATION_FAILED','EHOSTUNREACH','ECONNREFUSED','UND_ERR_CONNECT_TIMEOUT','HOST_IS_SLAVE','DEPTH_ZERO_SELF_SIGNED_CERT'].includes(code))category=code.toLowerCase();
    }catch{}
    let rollback=true;
    try{
      await call('server.disable',{id:c.server_id});
      if(server.host!==c.host)await call('server.set',{id:c.server_id,host:server.host});
      if(server.enabled)await call('server.enable',{id:c.server_id});
    }catch{rollback=false;}
    if(duplicate?.enabled){try{await call('server.enable',{id:duplicate.id});}catch{rollback=false;}}
    throw new Error('host_connection_'+phase+'_'+category+'_'+(rollback?'rollback_complete':'rollback_incomplete'));
  }
}
async function main(){
  process.umask(0o077);const input=JSON.parse(fs.readFileSync(0,'utf8'));
  const c=validateConnection(input.connection);
  if(c.host_id!==input.expected_host_id||c.pool_id!==input.expected_pool_id||c.host_name!==input.expected_host_name)throw new Error('host_connection_inventory_mismatch');
  const {connect}=require('./xo.cjs'),client=await connect(input.admin,true);
  try{if(client.user.permission!=='admin')throw new Error('administrator_required');console.log(JSON.stringify(await reconcileConnection(client.call,c)));}
  finally{client.close();}
}
if(require.main===module)main().catch(error=>{const message=String(error.message);console.error(/^[a-z_]+$/.test(message)?message:'host_connection_repair_failed');process.exitCode=1;});
module.exports={validateConnection,probeCertificate,reconcileConnection};
