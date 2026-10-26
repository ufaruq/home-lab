'use strict';
const {validateVmSelection,buildVmPoints,inventoryPoints,matching}=require('./vm-metrics.cjs');
async function collectVmFleet(c,objects,call,clock=Date.now){
  const targets=c.vm_targets||[];validateVmSelection(targets,c.excluded_vm_ids||[]);
  const results=new Array(targets.length),deadline=clock()+40000;let index=0;
  async function worker(){
    while(index<targets.length){
      const i=index++,target=targets[i],vm=objects[target.id],now=clock()/1000;
      let points,status={name:target.name,running:vm?.power_state==='Running',failed:false,stats_available:false};
      const valid=matching(target,vm)&&(vm.$pool===c.pool_id||vm.$poolId===c.pool_id)&&!(c.excluded_vm_ids||[]).includes(target.id);
      if(!valid){points=inventoryPoints(target,null,now,c.host_name);status={...status,running:false,failed:true,error_code:'vm_identity_unavailable'};}
      else if(vm.power_state!=='Running')points=buildVmPoints(target,vm,objects,null,now,c.host_name);
      else{
        try{
          if(clock()>deadline)throw new Error('deadline');
          const envelope=await call('vm.stats',{id:target.id,granularity:'seconds'});
          points=buildVmPoints(target,vm,objects,envelope,clock()/1000,c.host_name);status.stats_available=true;
        }catch{points=inventoryPoints(target,vm,clock()/1000,c.host_name);status={...status,failed:true,error_code:'vm_statistics_unavailable'};}
      }
      results[i]={points,status};
    }
  }
  await Promise.all([worker(),worker()]);
  return {points:results.flatMap(x=>x.points),statuses:results.map(x=>x.status)};
}
module.exports={collectVmFleet};
