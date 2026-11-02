'use strict';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const finite=x=>typeof x==='number'&&Number.isFinite(x);
const last=x=>Array.isArray(x)&&finite(x.at(-1))?x.at(-1):undefined;
const nonnegative=x=>finite(x)&&x>=0?x:undefined;
function validateTarget(t){
  if(!t||!/^[a-z][a-z0-9_]{0,62}$/.test(t.name||'')||!UUID.test(t.id||'')||typeof t.expected_name!=='string'||!t.expected_name.length||t.expected_name.length>128||/[\x00-\x1f]/.test(t.expected_name)||!['homelab','lab'].includes(t.environment)||!/^[a-z][a-z0-9_-]{0,62}$/.test(t.role||''))throw new Error('Invalid VM identity/labels');
  if(/parrot/i.test(t.name+' '+t.expected_name))throw new Error('Parrot is excluded');
  if(Object.keys(t).some(k=>!['name','id','expected_name','environment','role'].includes(k)))throw new Error('Unexpected VM selection field');
}
function validateVmSelection(targets=[],excluded=[]){
  if(!Array.isArray(targets)||targets.length>16||!Array.isArray(excluded)||excluded.length>16||excluded.some(x=>!UUID.test(x))||(targets.length&&!excluded.length))throw new Error('VM selection/exclusion limit invalid');
  const names=new Set(),ids=new Set();
  for(const t of targets){validateTarget(t);if(excluded.includes(t.id))throw new Error('VM UUID is excluded');if(names.has(t.name)||ids.has(t.id))throw new Error('Duplicate VM selection');names.add(t.name);ids.add(t.id);}
}
function matching(t,vm){return vm&&vm.type==='VM'&&vm.id===t.id&&vm.name_label===t.expected_name&&!/parrot/i.test(vm.name_label);}
function inventoryPoints(t,vm,now,hostName='datacenter1'){
  validateTarget(t);
  const state=matching(t,vm)?({Running:1,Halted:0,Paused:2,Suspended:3}[vm.power_state]??-1):-1;
  return [{measurement:'homelab_xcp_vm',tags:{job:'homelab_xcp',host:hostName,vm:t.name,environment:t.environment,role:t.role},fields:{power_state:state,stats_available:0},timestamp:now}];
}
function buildVmPoints(t,vm,objects,envelope,now=Date.now()/1000,hostName='datacenter1'){
  validateTarget(t);
  if(!matching(t,vm))throw new Error('VM identity differs or is excluded');
  const points=inventoryPoints(t,vm,now,hostName),status=points[0],tags=status.tags;
  if(vm.power_state!=='Running')return points;
  const stamp=envelope?.endTimestamp;
  if(!finite(stamp)||now-stamp>180||stamp-now>30)throw new Error('VM statistics stale; freshness required');
  const s=envelope.stats||{},fields={};let rrd=0;
  const cpu=Object.values(s.cpus||{}).map(last);
  if(cpu.length&&cpu.length<=512&&cpu.every(x=>finite(x)&&x>=0&&x<=100)){fields.cpu_used_percent=cpu.reduce((a,b)=>a+b,0)/cpu.length;rrd++;}
  const memory=last(s.memory),free=last(s.memoryFree);
  if(finite(memory)&&memory>0){fields.memory_assigned_bytes=memory;rrd++;}
  if(finite(memory)&&finite(free)&&free>=0&&free<=memory){fields.memory_free_bytes=free;fields.memory_used_bytes=memory-free;}
  if(finite(vm.CPUs?.number)&&vm.CPUs.number>0)fields.vcpu_count=vm.CPUs.number;
  let boot=vm.startTime;if(typeof boot==='string')boot=/^\d+(\.\d+)?$/.test(boot)?Number(boot):Date.parse(boot)/1000;
  if(finite(boot)&&boot>1e12)boot/=1000;
  if(finite(boot)&&boot>0&&boot<=now)fields.uptime_seconds=now-boot;
  const vdis=[...new Set((vm.$VBDs||[]).map(id=>objects[id]).filter(x=>x?.type==='VBD'&&!x.is_cd_drive).map(x=>x.VDI))].map(id=>objects[id]).filter(x=>x?.type==='VDI');
  if(vdis.length>4)throw new Error('VM disk limit exceeded');
  if(vdis.length&&vdis.every(x=>finite(x.size)&&x.size>=0))fields.disk_provisioned_bytes=vdis.reduce((n,x)=>n+x.size,0);
  if(vdis.length&&vdis.every(x=>finite(x.usage)&&x.usage>=0))fields.disk_allocated_bytes=vdis.reduce((n,x)=>n+x.usage,0);
  if(Object.keys(fields).length)points.push({measurement:'homelab_xcp_vm',tags,fields,timestamp:stamp});
  const interfaces=[...new Set([...Object.keys(s.vifs?.rx||{}),...Object.keys(s.vifs?.tx||{})])];
  if(interfaces.length>8||interfaces.some(x=>!/^\d{1,2}$/.test(x)))throw new Error('VM interface limit/identity invalid');
  for(const device of interfaces){
    const f={};for(const [direction,label] of [['rx','receive'],['tx','transmit']]){const value=nonnegative(last(s.vifs?.[direction]?.[device]));if(value!==undefined)f[label+'_bytes_per_second']=value;}
    rrd+=Object.keys(f).length;if(Object.keys(f).length)points.push({measurement:'homelab_xcp_vm_network',tags:{...tags,device:'vif'+device},fields:f,timestamp:stamp});
  }
  const diskKeys=[...new Set(['ioThroughput','iops','xvds'].flatMap(group=>['r','w'].flatMap(direction=>Object.keys(s[group]?.[direction]||{}))))];
  if(diskKeys.length>4||diskKeys.some(x=>!/^([a-z]|\d{1,2})$/.test(x)))throw new Error('VM disk metric limit/identity invalid');
  for(const device of diskKeys){
    const f={};for(const [direction,label] of [['r','read'],['w','write']]){
      const throughput=nonnegative(last(s.ioThroughput?.[direction]?.[device]))??nonnegative(last(s.xvds?.[direction]?.[device]));
      const iops=nonnegative(last(s.iops?.[direction]?.[device]));
      if(throughput!==undefined)f[label+'_bytes_per_second']=throughput;if(iops!==undefined)f[label+'_iops']=iops;
    }
    rrd+=Object.keys(f).length;if(Object.keys(f).length)points.push({measurement:'homelab_xcp_vm_disk',tags:{...tags,disk:/^[a-z]$/.test(device)?'xvd'+device:'disk'+device},fields:f,timestamp:stamp});
  }
  if(!rrd)throw new Error('Missing current VM statistics');
  status.fields.stats_available=1;status.fields.source_timestamp_seconds=stamp;
  if(points.reduce((n,p)=>n+Object.keys(p.fields).length,0)>48)throw new Error('Per-VM series limit exceeded');
  return points;
}
module.exports={validateVmSelection,buildVmPoints,inventoryPoints,matching};
