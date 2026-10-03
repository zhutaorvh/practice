const http2=require('http2'),crypto=require('crypto'),fs=require('fs');
const TGZ=fs.readFileSync('/tmp/grc/w.tar.gz');
const SUM=crypto.createHash('sha256').update(TGZ).digest('hex');
function v(x){x>>>=0;const b=[];while(x>127){b.push((x&127)|128);x>>>=7;}b.push(x&127);return Buffer.from(b);}
function f(n,d){return Buffer.concat([v((n<<3)|2),v(d.length),d]);}
function fv(n,x){return Buffer.concat([v((n<<3)|0),v(x)]);}
const kust=f(1,Buffer.from('x'));
const appsrc=Buffer.concat([f(2,Buffer.from('.')),f(8,kust)]);
const kopt=f(2,Buffer.from('./build'));
const req=Buffer.concat([f(2,Buffer.from('master')),fv(3,1),f(5,Buffer.from('d')),f(10,appsrc),f(13,kopt)]);
const w1=Buffer.concat([v(10),v(req.length),req]);
const md=Buffer.concat([f(1,Buffer.from(SUM)),fv(2,TGZ.length)]);
const w2=Buffer.concat([v(18),v(md.length),md]);
const ch=f(1,TGZ);
const w3=Buffer.concat([v(26),v(ch.length),ch]);
function gf(m){const h=Buffer.alloc(5);h.writeUInt32BE(m.length,1);return Buffer.concat([h,m]);}
const t0=Date.now();
const sess=http2.connect('https://172.20.135.138:8081',{rejectUnauthorized:false});
let done=false;
sess.on('error',e=>{if(!done){done=true;console.log('SES-ERR',e.message);process.exit(1);}});
const st=sess.request({':method':'POST',':scheme':'https',':authority':'172.20.135.138:8081',':path':'/repository.RepoServerService/GenerateManifestWithFiles','content-type':'application/grpc','te':'trailers'});
let data=Buffer.alloc(0),trailers={};
st.on('response',h=>console.log('HTTP',h[':status'],(Date.now()-t0)+'ms'));
st.on('data',d=>{data=Buffer.concat([data,d]);});
st.on('trailers',t=>{for(const k in t)trailers[k]=Buffer.from(t[k]).toString();});
const fin=()=>{if(done)return;done=true;sess.close();
  console.log('grpc-status='+trailers['grpc-status'],'t='+(Date.now()-t0)+'ms');
  if(trailers['grpc-message'])console.log('msg='+decodeURIComponent(trailers['grpc-message']));
  let pos=0,n=0;
  while(pos+5<=data.length){const len=data.readUInt32BE(pos+1);pos+=5;if(pos+len>data.length)break;const m=data.slice(pos,pos+len);pos+=len;n++;
    let p=0;while(p<m.length){const tag=m[p];p++;const fn=tag>>3,wt=tag&7;
      if(wt===2){let l=0,sh=0;while(true){const b=m[p];p++;l+=(b&127)*Math.pow(2,sh);sh+=7;if(!(b&128))break;}const val=m.slice(p,p+l);p+=l;
        if(fn===1)console.log('MANIFEST['+n+']:',val.toString('utf8').slice(0,500));
      }else if(wt===0){while(p<m.length&&(m[p]&128))p++;p++;}else break;}}
  console.log('frames='+n,'raw='+data.length+'B');
  process.exit(0);};
st.on('end',fin);st.on('close',fin);
st.write(gf(w1));st.write(gf(w2));st.write(gf(w3));st.end();
setTimeout(()=>{if(!done){done=true;console.log('TIMEOUT');process.exit(2);}},parseInt(process.env.T||'120000'));
