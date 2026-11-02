const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../../../monitoring/xcp');
const now=1800000000;
const id='11111111-1111-4111-8111-111111111111';
const excluded='99999999-9999-4999-8999-999999999999';
const target={name:'wazuh',id,expected_name:'Wazuh',environment:'homelab',role:'security'};
function impl(name='vm-metrics.cjs'){const p=path.join(root,name);assert.ok(fs.existsSync(p),'VM collection is not implemented');return require(p);}
function source(){return {
 vm:{id,name_label:'Wazuh',type:'VM',power_state:'Running',startTime:now-600,CPUs:{number:4},$VBDs:['vbd']},
 objects:{vbd:{type:'VBD',is_cd_drive:false,VDI:'vdi'},vdi:{type:'VDI',size:1000,usage:400}},
 envelope:{endTimestamp:now-5,interval:5,stats:{cpus:{0:[10,10],1:[20,30]},memory:[800,800],memoryFree:[300,200],vifs:{rx:{0:[4,5]},tx:{0:[6,7]}},ioThroughput:{r:{a:[8,9]},w:{a:[10,11]}},iops:{r:{a:[1,2]},w:{a:[3,4]}}}},
};}
test('running VM metrics reflect real CPU, guest RAM, NICs and disk allocation/I/O',()=>{
 const {buildVmPoints}=impl();const s=source();const points=buildVmPoints(target,s.vm,s.objects,s.envelope,now);
 const vm=points.find(x=>x.fields.cpu_used_percent!==undefined);
 assert.equal(vm.fields.cpu_used_percent,20);assert.equal(vm.fields.memory_assigned_bytes,800);assert.equal(vm.fields.memory_used_bytes,600);
 assert.equal(vm.fields.disk_provisioned_bytes,1000);assert.equal(vm.fields.disk_allocated_bytes,400);assert.equal(vm.fields.uptime_seconds,600);
 const disk=points.find(x=>x.measurement==='homelab_xcp_vm_disk');assert.equal(disk.tags.disk,'xvda');assert.equal(disk.fields.write_bytes_per_second,11);
 const net=points.find(x=>x.measurement==='homelab_xcp_vm_network');assert.equal(net.tags.device,'vif0');assert.equal(net.fields.receive_bytes_per_second,5);
 assert.ok(points.every(x=>x.tags.vm==='wazuh'));
});
test('halted VM has current power status without fabricated resource values',()=>{
 const {buildVmPoints}=impl();const s=source();s.vm.power_state='Halted';
 const points=buildVmPoints(target,s.vm,s.objects,null,now);
 assert.equal(points.length,1);assert.deepEqual(points[0].fields,{power_state:0,stats_available:0});assert.equal(points[0].timestamp,now);
});
test('guest memory usage is absent when tools do not report memoryFree',()=>{
 const s=source();delete s.envelope.stats.memoryFree;
 const p=impl().buildVmPoints(target,s.vm,s.objects,s.envelope,now).find(x=>x.fields.memory_assigned_bytes!==undefined);
 assert.ok(!('memory_used_bytes' in p.fields));assert.equal(p.fields.memory_assigned_bytes,800);
});
test('stale VM statistics and mismatched identities fail closed',()=>{
 const {buildVmPoints}=impl();const s=source();s.envelope.endTimestamp=now-181;
 assert.throws(()=>buildVmPoints(target,s.vm,s.objects,s.envelope,now),/stale|fresh/i);
 s.vm.name_label='different';assert.throws(()=>buildVmPoints(target,s.vm,s.objects,s.envelope,now),/identity/i);
});
test('Parrot is rejected by alias, current name, or persistent VM UUID',()=>{
 const {validateVmSelection,buildVmPoints}=impl();
 assert.throws(()=>validateVmSelection([{...target,name:'parrot_htb'}],[excluded]),/Parrot|excluded/i);
 assert.throws(()=>validateVmSelection([{...target,id:excluded}],[excluded]),/excluded/i);
 const s=source();s.vm.name_label='Parrot renamed';assert.throws(()=>buildVmPoints(target,s.vm,s.objects,s.envelope,now),/Parrot|excluded|identity/i);
});
test('unbounded interface identities cannot become cloud labels',()=>{
 const s=source();s.envelope.stats.vifs.rx=Object.fromEntries(Array.from({length:9},(_,i)=>[i,[1,2]]));
 assert.throws(()=>impl().buildVmPoints(target,s.vm,s.objects,s.envelope,now),/interface|limit/i);
});
test('collection queries only selected running VMs, retaining halted status',async()=>{
 const {collectVmFleet}=impl('vm-runtime.cjs');const s=source();s.vm.$pool='pool';
 const off={...target,name:'maps',id:'22222222-2222-4222-8222-222222222222',expected_name:'Maps'};
 const objects={...s.objects,[id]:s.vm,[off.id]:{...s.vm,id:off.id,name_label:'Maps',power_state:'Halted'},[excluded]:{...s.vm,id:excluded,name_label:'Parrot'}};
 const calls=[];const call=async(method,p)=>{calls.push([method,p]);return s.envelope;};
 const result=await collectVmFleet({host_name:'datacenter1',pool_id:'pool',vm_targets:[target,off],excluded_vm_ids:[excluded]},objects,call,()=>now*1000);
 assert.deepEqual(calls,[['vm.stats',{id,granularity:'seconds'}]]);
 assert.equal(result.statuses.length,2);assert.ok(result.statuses.every(x=>!x.failed));assert.ok(!JSON.stringify(result.points).includes('parrot'));
});
test('one failing VM does not discard other VM samples',async()=>{
 const {collectVmFleet}=impl('vm-runtime.cjs');const s=source();s.vm.$pool='pool';
 const other={...target,name:'portainer',id:'22222222-2222-4222-8222-222222222222',expected_name:'Portainer'};
 const objects={...s.objects,[id]:s.vm,[other.id]:{...s.vm,id:other.id,name_label:'Portainer'}};
 const call=async(m,p)=>{if(p.id===id)throw new Error('private raw API error');return s.envelope;};
 const result=await collectVmFleet({host_name:'datacenter1',pool_id:'pool',vm_targets:[target,other],excluded_vm_ids:[excluded]},objects,call,()=>now*1000);
 assert.equal(result.statuses.filter(x=>x.failed).length,1);assert.ok(result.points.some(x=>x.tags.vm==='portainer'&&x.fields.cpu_used_percent!==undefined));
 assert.ok(!JSON.stringify(result).includes('private raw'));
});
test('a selected UUID with a changed Parrot name or wrong pool is never queried',async()=>{
 const {collectVmFleet}=impl('vm-runtime.cjs');const s=source();
 const c={host_name:'datacenter1',pool_id:'pool',vm_targets:[target],excluded_vm_ids:[excluded]};
 for(const vm of [{...s.vm,$pool:'pool',name_label:'Parrot HTB os'},{...s.vm,$pool:'another-pool'}]){
  let calls=0;
  const result=await collectVmFleet(c,{[id]:vm},async()=>{calls++;return s.envelope;},()=>now*1000);
  assert.equal(calls,0);assert.equal(result.statuses[0].failed,true);assert.equal(result.points[0].fields.power_state,-1);
 }
});
test('combined payload remains capped at 1024 series',()=>{
 const {encodePoints}=require(path.join(root,'metrics.cjs'));
 const points=n=>Array.from({length:n},(_,i)=>({measurement:'x',tags:{host:'x'},fields:{['f'+i]:1},timestamp:now}));
 assert.doesNotThrow(()=>encodePoints(points(512)));
 assert.throws(()=>encodePoints(points(1025)),/series/i);
});
