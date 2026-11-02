const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const root=path.resolve(__dirname,'../../../monitoring/xcp');
function impl(file){const p=path.join(root,file);assert.ok(fs.existsSync(p),file+' is not implemented');return require(p);}
test('reader setup is idempotent and grants only viewer on one pool',async()=>{
  const {reconcileReader}=impl('setup-reader.cjs');const users=[],acls=[],writes=[];
  const call=async(method,p)=>{
    if(method==='user.getAll')return users;
    if(method==='acl.get')return acls;
    if(method==='group.getAll')return [];
    writes.push([method,p]);
    if(method==='user.create'){users.push({id:'reader',email:p.email,permission:p.permission});return 'reader';}
    if(method==='acl.add')acls.push(p);
  };
  const input={email:'metrics@localhost',password:'fixture_password_long',pool_id:'pool'};
  assert.equal((await reconcileReader(call,input)).changed,true);
  assert.equal((await reconcileReader(call,input)).changed,false);
  assert.deepEqual(writes.map(x=>x[0]),['user.create','acl.add']);
  assert.equal(users[0].permission,'none');
  assert.deepEqual(acls,[{subject:'reader',object:'pool',action:'viewer'}]);
});
test('reader setup refuses an existing administrator or wider ACL',async()=>{
  const {reconcileReader}=impl('setup-reader.cjs');
  const input={email:'metrics@localhost',password:'fixture_password_long',pool_id:'pool'};
  await assert.rejects(()=>reconcileReader(async()=>[{id:'reader',email:input.email,permission:'admin'}],input),/permission/i);
  const call=async m=>m==='user.getAll'?[{id:'reader',email:input.email,permission:'none'}]:[{subject:'reader',object:'pool',action:'operator'}];
  await assert.rejects(()=>reconcileReader(call,input),/ACL/i);
});
test('reader setup refuses group membership that could widen its permissions',async()=>{
  const {reconcileReader}=impl('setup-reader.cjs');
  const call=async m=>m==='user.getAll'?[{id:'reader',email:'metrics@localhost',permission:'none'}]:m==='group.getAll'?[{users:['reader']}]:[];
  await assert.rejects(()=>reconcileReader(call,{email:'metrics@localhost',password:'fixture_password_long',pool_id:'pool'}),/group/i);
});
test('private config rejects world-readable files and symlinks',()=>{
  const {readPrivateConfig}=impl('collector.cjs');const dir=fs.mkdtempSync(path.join(os.tmpdir(),'xcp-private-'));
  try{
    fs.chmodSync(dir,0o700);const p=path.join(dir,'config.json');fs.writeFileSync(p,'{}',{mode:0o644});
    assert.throws(()=>readPrivateConfig(p),/private|permission/i);
    fs.chmodSync(p,0o600);assert.deepEqual(readPrivateConfig(p),{});
    const link=path.join(dir,'link');fs.symlinkSync(p,link);assert.throws(()=>readPrivateConfig(link),/regular|symlink/i);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('HTTPS redirects fail without forwarding credentials elsewhere',async()=>{
  const {pushMetrics}=impl('collector.cjs');const {EventEmitter}=require('node:events');let calls=0;
  const transport=(url,options,callback)=>{
    calls++;assert.equal(new URL(url).protocol,'https:');assert.equal(options.rejectUnauthorized,true);
    const req=new EventEmitter();req.setTimeout=()=>req;req.destroy=()=>{};req.end=()=>{
      const res=new EventEmitter();res.statusCode=302;res.resume=()=>{};callback(res);res.emit('end');
    };return req;
  };
  await assert.rejects(()=>pushMetrics({metrics_url:'https://prometheus-test.grafana.net/api/v1/push/influx/write',metrics_username:'1',metrics_token:'private'},'test',transport),/http_302/);
  assert.equal(calls,1);
});
