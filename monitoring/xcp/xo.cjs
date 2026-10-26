'use strict';
const READ_METHODS=['session.signInWithPassword','xo.getAllObjects','host.stats','vm.stats','acl.getCurrentPermissions'];
const ADMIN_METHODS=[...READ_METHODS,'user.getAll','user.create','group.getAll','acl.get','acl.add'];
async function connect(credentials, administrator=false) {
  const WebSocket=require('/usr/local/lib/node_modules/xo-server/node_modules/ws');
  const ws=new WebSocket('ws://127.0.0.1/api/',{maxPayload:4*1024*1024,handshakeTimeout:8000});
  let sequence=0;const pending=new Map();const allowed=new Set(administrator?ADMIN_METHODS:READ_METHODS);
  const rejectAll=()=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error('xo_connection_closed'));}pending.clear();};
  ws.on('close',rejectAll);ws.on('error',rejectAll);
  ws.on('message',raw=>{
    let m;try{m=JSON.parse(raw.toString());}catch{return;}
    const p=pending.get(String(m.id));if(!p)return;
    pending.delete(String(m.id));clearTimeout(p.timer);
    if(m.error)p.reject(new Error('xo_api_'+String(m.error.code).replace(/[^0-9-]/g,'')));
    else p.resolve(m.result);
  });
  const call=(method,params={})=>new Promise((resolve,reject)=>{
    if(!allowed.has(method))return reject(new Error('xo_method_forbidden'));
    if(ws.readyState!==WebSocket.OPEN)return reject(new Error('xo_connection_closed'));
    const id=String(++sequence);
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error('xo_request_timeout'));},12000);
    pending.set(id,{resolve,reject,timer});
    ws.send(JSON.stringify({jsonrpc:'2.0',id,method,params}),error=>{
      if(error){pending.delete(id);clearTimeout(timer);reject(new Error('xo_send_failed'));}
    });
  });
  try {
    await new Promise((resolve,reject)=>{ws.once('open',resolve);ws.once('error',()=>reject(new Error('xo_transport_failed')));});
    const user=await call('session.signInWithPassword',{email:credentials.email,password:credentials.password});
    return {user,call,close:()=>ws.close()};
  } catch(error) {ws.close();throw error;}
}
module.exports={connect};
