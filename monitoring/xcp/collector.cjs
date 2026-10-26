'use strict';
const fs=require('node:fs');
const path=require('node:path');
const https=require('node:https');
const {connect}=require('./xo.cjs');
const {validateConfig,assertReader,buildPoints,encodePoints}=require('./metrics.cjs');
const {collectVmFleet}=require('./vm-runtime.cjs');
function readPrivateConfig(file) {
  const info=fs.lstatSync(file),parent=fs.statSync(path.dirname(file));
  if(!info.isFile()||info.isSymbolicLink())throw new Error('Config must be a regular file, no symlink');
  if(info.uid!==process.getuid()||(info.mode&0o077)||(parent.mode&0o077)||parent.uid!==process.getuid())throw new Error('Config permissions must be private');
  if(info.size>32768)throw new Error('Config size limit');
  return JSON.parse(fs.readFileSync(file,'utf8'));
}
function pushMetrics(c,body,request=https.request) {
  return new Promise((resolve,reject)=>{
    const req=request(c.metrics_url,{method:'POST',rejectUnauthorized:true,headers:{
      Authorization:'Basic '+Buffer.from(c.metrics_username+':'+c.metrics_token).toString('base64'),
      'Content-Type':'text/plain','Content-Length':Buffer.byteLength(body),
    }},res=>{
      const status=res.statusCode;
      res.on('end',()=>status>=200&&status<300?resolve(status):reject(new Error('http_'+status)));
      res.on('error',()=>reject(new Error('upload_response_failed')));
      res.resume(); // Response bodies may echo input: discard without logging.
    });
    req.setTimeout(10000,()=>req.destroy(new Error('upload_timeout')));
    req.on('error',()=>reject(new Error('upload_transport_failed')));
    req.end(body);
  });
}
async function collect(c,now=Date.now()/1000) {
  const client=await connect({email:c.xoa_email,password:c.xoa_password});
  try {
    assertReader(client.user);
    const objects=await client.call('xo.getAllObjects');const host=objects[c.host_id];
    if(!host||(host.$pool!==c.pool_id&&host.$poolId!==c.pool_id))throw new Error('host_pool_mismatch');
    const envelope=await client.call('host.stats',{host:c.host_id,granularity:'seconds'});
    const points=buildPoints(c,{host,objects,envelope},Date.now()/1000);
    const fleet=await collectVmFleet(c,objects,client.call);
    const health=points.find(x=>x.measurement==='homelab_xcp_collector');
    health.fields.vm_targets=fleet.statuses.length;
    health.fields.vm_running=fleet.statuses.filter(x=>x.running).length;
    health.fields.vm_failures=fleet.statuses.filter(x=>x.failed).length;
    if(health.fields.vm_failures)health.fields.success=0;
    const all=[...points,...fleet.points];encodePoints(all);
    return {points:all,vm_statuses:fleet.statuses};
  }finally{client.close();}
}
function errorCode(error) {
  const m=String(error?.message||'');
  if(/^(xo_[a-z_]+|xo_api_-?\d+|http_\d+|upload_[a-z_]+|host_pool_mismatch)$/.test(m))return m;
  if(/stale|freshness|future/i.test(m))return 'source_stale';
  if(/permission|read-only/i.test(m))return 'reader_permission_invalid';
  if(/limit|payload/i.test(m))return 'metric_limit_exceeded';
  return 'collection_failed';
}
function saveStatus(configFile,status) {
  const destination=path.join(path.dirname(configFile),'status.json');const temp=destination+'.'+process.pid;
  fs.writeFileSync(temp,JSON.stringify(status,null,2)+'\n',{mode:0o600,flag:'wx'});
  fs.renameSync(temp,destination);
}
async function main() {
  process.umask(0o077);
  const mode=process.argv[2],file=process.argv[3];
  if(!['--check','--run'].includes(mode)||!file)throw new Error('invalid_command');
  const c=validateConfig(readPrivateConfig(file));const now=Date.now()/1000;
  const status={attempted_at:now,collection_ok:false,delivery_ok:false,sample_count:0};let points;
  try{const result=await collect(c,now);points=result.points;status.vm_statuses=result.vm_statuses;status.collection_ok=!result.vm_statuses.some(x=>x.failed);status.source_at=points.find(x=>x.measurement==='homelab_xcp_collector').fields.source_timestamp_seconds;}
  catch(error){status.error_code=errorCode(error);}
  if(mode==='--check') {
    console.log(JSON.stringify({...status,sample_count:points?points.reduce((n,p)=>n+Object.keys(p.fields).length,0):0}));
    if(!status.collection_ok)process.exitCode=1;return;
  }
  if(!points)points=[{measurement:'homelab_xcp_collector',tags:{job:'homelab_xcp',host:c.host_name,environment:'homelab',role:'hypervisor'},fields:{success:0},timestamp:now}];
  status.sample_count=points.reduce((n,p)=>n+Object.keys(p.fields).length,0);
  try{status.http_status=await pushMetrics(c,encodePoints(points));status.delivery_ok=true;}
  catch(error){status.error_code=errorCode(error);}
  saveStatus(file,status);console.log(JSON.stringify(status));
  if(!status.collection_ok||!status.delivery_ok)process.exitCode=1;
}
if(require.main===module)main().catch(error=>{console.error(errorCode(error));process.exitCode=1;});
module.exports={readPrivateConfig,pushMetrics,collect,errorCode};
