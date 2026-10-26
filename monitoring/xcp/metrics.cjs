'use strict';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const finite = value => typeof value === 'number' && Number.isFinite(value);
const last = values => Array.isArray(values) && finite(values.at(-1)) ? values.at(-1) : undefined;
const positive = value => finite(value) && value >= 0 ? value : undefined;

function validateConfig(c) {
  if (!c || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(c.host_name || '') || !UUID.test(c.host_id || '') || !UUID.test(c.pool_id || '')) throw new Error('Invalid monitored host identity');
  const allowed=new Set(['host_name','host_id','pool_id','storage_ids','metrics_url','metrics_username','metrics_token','xoa_email','xoa_password','vm_targets','excluded_vm_ids']);
  if(Object.keys(c).some(x=>!allowed.has(x)))throw new Error('Unexpected private config field');
  require('./vm-metrics.cjs').validateVmSelection(c.vm_targets||[],c.excluded_vm_ids||[]);
  if (!Array.isArray(c.storage_ids) || c.storage_ids.length > 16 || c.storage_ids.some(x => !UUID.test(x)) || new Set(c.storage_ids).size !== c.storage_ids.length) throw new Error('Storage limit/identity invalid');
  let url;
  try { url = new URL(c.metrics_url); } catch { throw new Error('Invalid HTTPS endpoint'); }
  if (url.protocol !== 'https:' || !/^prometheus-[a-z0-9-]+\.grafana\.net$/.test(url.hostname) || url.port || url.username || url.password || url.search || url.hash || url.pathname !== '/api/v1/push/influx/write') throw new Error('Invalid Grafana HTTPS endpoint');
  if (!/^\d+$/.test(c.metrics_username || '') || typeof c.metrics_token !== 'string' || c.metrics_token.length < 16 || !c.xoa_email || typeof c.xoa_password !== 'string' || c.xoa_password.length < 16) throw new Error('Missing private credentials');
  return c;
}
function assertReader(user) {
  if (!user || !['none', 'read'].includes(user.permission)) throw new Error('Collector requires read-only XOA permission');
}
function buildPoints(config, source, now = Date.now()/1000) {
  validateConfig(config);
  const {host, envelope, objects} = source;
  if (host?.id !== config.host_id || host.name_label !== config.host_name || host.power_state !== 'Running') throw new Error('Monitored host identity/state differs');
  const stamp = envelope?.endTimestamp;
  if (!finite(stamp) || now-stamp > 180 || stamp-now > 30) throw new Error('Source statistics stale or future; freshness required');
  const s = envelope.stats || {};
  const tags = {job:'homelab_xcp',host:config.host_name,environment:'homelab',role:'hypervisor'};
  const points = [];
  const fields = {};
  const cpus = Object.values(s.cpus || {}).map(last);
  if (cpus.length && cpus.length <= 512 && cpus.every(x=>finite(x)&&x>=0&&x<=100)) fields.cpu_used_percent = cpus.reduce((a,b)=>a+b,0)/cpus.length;
  const total=last(s.memory), free=last(s.memoryFree);
  if (finite(total) && total>0) fields.memory_total_bytes=total;
  if (finite(total) && finite(free) && free>=0 && free<=total) {
    fields.memory_free_bytes=free;fields.memory_used_bytes=total-free;
  }
  const load=positive(last(s.load));if(load!==undefined) fields.load=load;
  let rrdSamples=Object.keys(fields).length;
  let boot=host.startTime;
  if (typeof boot==='string') boot=/^\d+(\.\d+)?$/.test(boot)?Number(boot):Date.parse(boot)/1000;
  if (finite(boot) && boot>1e12) boot/=1000;
  if(finite(boot)&&boot>0&&boot<=now) fields.uptime_seconds=now-boot;
  if(Object.keys(fields).length)points.push({measurement:'homelab_xcp',tags,fields,timestamp:stamp});
  const devices=[...new Set([...Object.keys(s.pifs?.rx||{}),...Object.keys(s.pifs?.tx||{})])];
  if(devices.length>16 || devices.some(x=>!/^\d{1,2}$/.test(x)))throw new Error('Interface limit/identity invalid');
  for(const d of devices) {
    const f={};const rx=positive(last(s.pifs?.rx?.[d])),tx=positive(last(s.pifs?.tx?.[d]));
    if(rx!==undefined)f.receive_bytes_per_second=rx;
    if(tx!==undefined)f.transmit_bytes_per_second=tx;
    rrdSamples+=Object.keys(f).length;
    if(Object.keys(f).length)points.push({measurement:'homelab_xcp_network',tags:{...tags,device:'eth'+d},fields:f,timestamp:stamp});
  }
  const seenPrefixes=new Set();
  for(const id of config.storage_ids) {
    const prefix=id.slice(0,8);
    if(seenPrefixes.has(prefix))throw new Error('Ambiguous storage prefix');
    seenPrefixes.add(prefix);
    const sr=Object.values(objects||{}).find(x=>x.id===id&&x.type==='SR');
    if(!sr)continue;
    const f={};
    if(finite(sr.size)&&sr.size>0&&finite(sr.physical_usage)&&sr.physical_usage>=0&&sr.physical_usage<=sr.size) {
      f.total_bytes=sr.size;f.used_bytes=sr.physical_usage;f.available_bytes=sr.size-sr.physical_usage;
    }
    for(const [group,name] of [['ioThroughput','bytes_per_second'],['iops','iops']]) {
      for(const [direction,label] of [['r','read'],['w','write']]) {
        const value=positive(last(s[group]?.[direction]?.[prefix]));
        if(value!==undefined){f[label+'_'+name]=value;rrdSamples++;}
      }
    }
    if(Object.keys(f).length)points.push({measurement:'homelab_xcp_storage',tags:{...tags,storage:id},fields:f,timestamp:stamp});
  }
  if(!rrdSamples)throw new Error('Missing current RRD statistics');
  points.push({measurement:'homelab_xcp_collector',tags,fields:{success:1,source_timestamp_seconds:stamp},timestamp:now});
  encodePoints(points,{maxSeries:128}); // preserve the original host-only budget
  return points;
}
function encodePoints(points,{maxSeries=1024}={}) {
  let series=0;const identities=new Set();
  const label=x=>{
    if(typeof x!=='string'||x.length>128||/[\x00-\x1f\x7f]/.test(x))throw new Error('Invalid label');
    return x.replace(/\\/g,'\\\\').replace(/ /g,'\\ ').replace(/,/g,'\\,').replace(/=/g,'\\=');
  };
  const lines=points.map(p=>{
    if(!/^[a-z][a-z0-9_]*$/.test(p.measurement))throw new Error('Invalid measurement');
    const tags=Object.entries(p.tags).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>{
      if(!/^[a-z][a-z0-9_]*$/.test(k))throw new Error('Invalid label key');return k+'='+label(v);
    }).join(',');
    const fields=Object.entries(p.fields).map(([k,v])=>{
      if(!/^[a-z][a-z0-9_]*$/.test(k)||!finite(v))throw new Error('Invalid numeric field');
      const id=p.measurement+','+tags+' '+k;if(identities.has(id))throw new Error('Duplicate series');identities.add(id);series++;
      return k+'='+v;
    }).join(',');
    if(!fields||!finite(p.timestamp))throw new Error('Missing sample');
    return p.measurement+','+tags+' '+fields+' '+(BigInt(Math.round(p.timestamp*1000))*1000000n).toString();
  });
  const body=lines.join('\n')+'\n';
  if(series>maxSeries)throw new Error('Metric series limit exceeded');
  if(Buffer.byteLength(body)>65536)throw new Error('Metric payload limit exceeded');
  return body;
}
module.exports={validateConfig,assertReader,buildPoints,encodePoints};
