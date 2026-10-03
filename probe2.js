const http2=require('http2'),crypto=require('crypto'),fs=require('fs');
function v(x){x>>>=0;const b=[];while(x>127){b.push((x&127)|128);x>>>=7;}b.push(x&127);return Buffer.from(b);}
function f(n,d){return Buffer.concat([v((n<<3)|2),v(d.length),d]);}
function fv(n,x){return Buffer.concat([v((n<<3)|0),v(x)]);}
function gf(m){const h=Buffer.alloc(5);h.writeUInt32BE(m.length,1);return Buffer.concat([h,m]);}
function buildReq(){
  const kust=f(1,Buffer.from('x'));
  const appsrc=Buffer.concat([f(2,Buffer.from('.')),f(8,kust)]);
  const kopt=f(2,Buffer.from('./build'));
  return Buffer.concat([f(2,Buffer.from('master')),fv(3,1),f(5,Buffer.from('d')),f(10,appsrc),f(13,kopt)]);
}
function one(label,msgs,timeoutMs,next){
  const t0=Date.now();
  const sess=http2.connect('https://172.20.135.138:8081',{rejectUnauthorized:false});
  let out='';
  sess.on('error',e=>{out+=' SES-ERR:'+e.message;});
  sess.on('goaway',g=>{out+=' GOAWAY:'+g.code;});
  const s=sess.request({':method':'POST',':scheme':'https',':authority':'172.20.135.138:8081',':path':'/repository.RepoServerService/GenerateManifestWithFiles','content-type':'application/grpc','te':'trailers'});
  let data=Buffer.alloc(0),trailers={},done0=false,rH=null;
  const done=()=>{if(done0)return;done0=true;
    const src=trailers['grpc-status']!==undefined?trailers:(rH||{});
    out+=' rst='+s.rstCode+' bytes='+data.length+' gs='+src['grpc-status']+' gm='+decodeURIComponent(src['grpc-message']||'').slice(0,200);
    console.log('['+label+'] '+(Date.now()-t0)+'ms'+out);
    try{sess.close()}catch(e){}
    setTimeout(next,400);
  };
  s.on('response',h=>{rH=h;out+=' HTTP='+h[':status']+' gs='+h['grpc-status']+' gm='+decodeURIComponent(h['grpc-message']||'').slice(0,150);});
  s.on('data',d=>{data=Buffer.concat([data,d]);});
  s.on('trailers',t=>{for(const k in t)trailers[k]=Buffer.from(t[k]).toString();});
  s.on('error',e=>{out+=' ST-ERR:'+e.message;});
  s.on('close',done);
  let i=0;
  const send=()=>{if(i<msgs.length){s.write(gf(msgs[i]));i++;setTimeout(send,30);}else s.end();};
  send();
  setTimeout(()=>{try{s.close()}catch(e){}},timeoutMs);
}
const REQ=buildReq();
function V1(){
  const G=Buffer.from('GARBAGE-NOT-A-TAR-0123456789');
  const SUM=crypto.createHash('sha256').update(G).digest('hex');
  const md=Buffer.concat([f(1,Buffer.from(SUM)),fv(2,G.length)]);
  const ch=f(1,G);
  one('V1-garbage',[Buffer.concat([v(10),v(REQ.length),REQ]),Buffer.concat([v(18),v(md.length),md]),Buffer.concat([v(26),v(ch.length),ch])],60000,V2);
}
function V2(){
  const TGZ=fs.readFileSync('/tmp/grc/w.tar.gz');
  const SUM=crypto.createHash('sha256').update(TGZ).digest('hex');
  const md=Buffer.concat([f(1,Buffer.from(SUM)),fv(2,TGZ.length)]);
  const ch=f(1,TGZ);
  one('V2-realtar',[Buffer.concat([v(10),v(REQ.length),REQ]),Buffer.concat([v(18),v(md.length),md]),Buffer.concat([v(26),v(ch.length),ch])],90000,V3);
}
function V3(){
  const md=Buffer.concat([f(1,Buffer.from('ab')),fv(2,1)]);
  one('V3-nochunk',[Buffer.concat([v(10),v(REQ.length),REQ]),Buffer.concat([v(18),v(md.length),md])],30000,()=>process.exit(0));
}
console.log('REQ len',REQ.length);V1();
