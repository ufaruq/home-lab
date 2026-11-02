const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const modulePath = path.resolve(__dirname, '../../../monitoring/xcp/metrics.cjs');
function implementation() {
  assert.ok(fs.existsSync(modulePath), 'XCP metric conversion is not implemented');
  return require(modulePath);
}
const now = 1800000000;
const config = {
  host_name: 'datacenter1', host_id: '11111111-1111-4111-8111-111111111111',
  pool_id: '22222222-2222-4222-8222-222222222222',
  storage_ids: ['33333333-3333-4333-8333-333333333333'],
  metrics_url: 'https://prometheus-prod-67-prod-us-west-0.grafana.net/api/v1/push/influx/write',
  metrics_username: '1234', metrics_token: 'glc_private_fixture',
  xoa_email: 'home-lab-xcp-metrics@localhost', xoa_password: 'private_fixture_password',
};
function source() {
  return {
    host: {id:config.host_id, name_label:'datacenter1', power_state:'Running', startTime:now-3600},
    objects: {sr:{id:config.storage_ids[0],type:'SR',size:1000,physical_usage:400}},
    envelope: {endTimestamp:now-5, interval:5, stats:{
      cpus:{0:[10,20],1:[30,40]}, memory:[1000,1000], memoryFree:[500,400],
      load:[1,2], pifs:{rx:{0:[10,20]},tx:{0:[30,40]}},
      ioThroughput:{r:{33333333:[1,2]},w:{33333333:[3,4]}},
    }},
  };
}
test('exports current host measurements and bounded stable device labels', () => {
  const {buildPoints}=implementation(); const result=buildPoints(config,source(),now);
  const host=result.find(x=>x.measurement==='homelab_xcp');
  assert.equal(host.fields.cpu_used_percent,30);
  assert.equal(host.fields.memory_used_bytes,600);
  assert.equal(host.fields.uptime_seconds,3600);
  assert.equal(host.tags.host,'datacenter1');
  assert.equal(host.timestamp,now-5);
  const net=result.find(x=>x.measurement==='homelab_xcp_network');
  assert.deepEqual(net.fields,{receive_bytes_per_second:20,transmit_bytes_per_second:40});
  assert.equal(net.tags.device,'eth0');
  const sr=result.find(x=>x.measurement==='homelab_xcp_storage');
  assert.equal(sr.fields.used_bytes,400);
  assert.equal(sr.fields.read_bytes_per_second,2);
  assert.ok(!JSON.stringify(result).includes('private_fixture'));
});
test('rejects stale and future statistics rather than relabeling them as fresh', () => {
  const {buildPoints}=implementation();
  for(const stamp of [now-181,now+31]) {
    const s=source();s.envelope.endTimestamp=stamp;
    assert.throws(()=>buildPoints(config,s,now),/fresh|stale|future/i);
  }
});
test('empty RRD data cannot report a successful collection',()=>{
  const {buildPoints}=implementation();const s=source();s.envelope.stats={};
  assert.throws(()=>buildPoints(config,s,now),/missing|empty|statistics/i);
});
test('private config refuses unrelated fields that could copy admin credentials',()=>{
  assert.throws(()=>implementation().validateConfig({...config,admin_password:'unrelated-secret'}),/field/i);
});
test('missing or nonnumeric last samples are omitted without fabricated zeroes', () => {
  const {buildPoints}=implementation();const s=source();
  s.envelope.stats.cpus={0:[20,null]};
  s.envelope.stats.memoryFree=[400,null];
  s.envelope.stats.load=[1,'bad'];
  const p=buildPoints(config,s,now).find(x=>x.measurement==='homelab_xcp');
  assert.ok(!('cpu_used_percent' in p.fields));
  assert.ok(!('memory_used_bytes' in p.fields));
  assert.ok(!('load' in p.fields));
});
test('rejects excess interfaces and invalid cloud destinations', () => {
  const {buildPoints,validateConfig}=implementation();const s=source();
  s.envelope.stats.pifs.rx=Object.fromEntries(Array.from({length:17},(_,i)=>[i,[1,2]]));
  assert.throws(()=>buildPoints(config,s,now),/limit|interface/i);
  for(const url of ['http://prometheus.grafana.net/api/v1/push/influx/write','https://evil.example/api/v1/push/influx/write','https://user:pass@prometheus.grafana.net/api/v1/push/influx/write','https://prometheus.grafana.net/api/v1/push/influx/write?token=secret']) {
    assert.throws(()=>validateConfig({...config,metrics_url:url}),/endpoint|HTTPS/i);
  }
});
test('Influx output contains only numeric fields and has strict payload/series bounds', () => {
  const {buildPoints,encodePoints}=implementation();const points=buildPoints(config,source(),now);
  const text=encodePoints(points);
  assert.match(text,/homelab_xcp,.*host=datacenter1.* cpu_used_percent=30/);
  assert.match(text,/1799999995000000000/);
  assert.throws(()=>encodePoints([{measurement:'bad',tags:{host:'x\ninjected'},fields:{a:1},timestamp:now}]),/label/i);
  assert.throws(()=>encodePoints(Array.from({length:129},(_,i)=>({measurement:'x',tags:{host:'x'},fields:{['f'+i]:1},timestamp:now})),{maxSeries:128}),/series/i);
});
test('scheduled collection refuses administrator credentials', () => {
  const {assertReader}=implementation();
  assert.throws(()=>assertReader({permission:'admin'}),/read|permission/i);
  assert.doesNotThrow(()=>assertReader({permission:'none'}));
});
