'use strict';
const fs=require('node:fs');
const {connect}=require('./xo.cjs');
const {assertReader}=require('./metrics.cjs');
async function reconcileReader(call,input) {
  const users=await call('user.getAll');
  let user=users.find(x=>x.email===input.email);let changed=false;
  if(user && user.permission!=='none')throw new Error('Existing reader has unsafe permission');
  if(!user){user={id:await call('user.create',{email:input.email,password:input.password,permission:'none'})};changed=true;}
  const groupResult=await call('group.getAll');
  const groups=Array.isArray(groupResult)?groupResult:Object.values(groupResult);
  if(groups.some(x=>Array.isArray(x.users)?x.users.includes(user.id):Object.prototype.hasOwnProperty.call(x.users||{},user.id)))throw new Error('Reader group membership can widen permissions');
  const all=await call('acl.get');
  const acls=(Array.isArray(all)?all:Object.values(all)).filter(x=>x.subject===user.id);
  if(acls.some(x=>x.object!==input.pool_id||x.action!=='viewer'))throw new Error('Existing reader has wider ACL');
  if(!acls.some(x=>x.object===input.pool_id&&x.action==='viewer')) {
    await call('acl.add',{subject:user.id,object:input.pool_id,action:'viewer'});changed=true;
  }
  return {changed,user_id:user.id};
}
async function main() {
  process.umask(0o077);
  const input=JSON.parse(fs.readFileSync(0,'utf8'));
  if(!/^[^\s@]+@localhost$/.test(input.email||'')||typeof input.password!=='string'||input.password.length<32||!input.pool_id||!input.admin?.email||!input.admin?.password)throw new Error('invalid_setup_input');
  const client=await connect(input.admin,true);
  try {
    if(client.user.permission!=='admin')throw new Error('administrator_required');
    const result=await reconcileReader(client.call,input);
    const reader=await connect({email:input.email,password:input.password});
    try{assertReader(reader.user);}finally{reader.close();}
    console.log(JSON.stringify(result));
  }finally{client.close();}
}
if(require.main===module)main().catch(()=>{console.error('XOA reader setup failed; check private inputs and account/ACL ownership');process.exitCode=1;});
module.exports={reconcileReader};
