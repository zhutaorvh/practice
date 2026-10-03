const http2=require('http2');
function v(x){x>>>=0;const b=[];while(x>127){b.push((x&127)|128);x>>>=7;}b.push(x&127);return Buffer.from(b);}
function f(n,d){return Buffer.concat([v((n<<3)|2),v(d.length),d]);}
function gf(m){const h=Buffer.alloc(5);h.writeUInt32BE(m.length,1);return Buffer.concat([h,m]);}
function call(path,payload,timeout,label,next){
  const t0=Date.now();
  const sess=http2.connect('https://172.20.135.138:8081',{rejectUnauthorized:false});
  let out='';
  sess.on('error',e=>{out+=' SES-ERR:'+e.message;});
  const s=sess.request({':method':'POST',':scheme':'https',':authority':'172.20.135.138:8081',':path':path,'content-type':'application/grpc','te':'trailers'});
  let data=Buffer.alloc(0),trailers={},done0=false;
  const done=()=>{if(done0)return;done0=true;
    out+=' rst='+s.rstCode+' bytes='+data.length;
    const gs=(trailers['grpc-status']||'').toString(),gm=(trailers['grpc-message']||'').toString();
    out+=' grpc-status='+gs+(gm?' msg='+decodeURIComponent(gm).slice(0,250):'');
    console.log('['+label+'] '+(Date.now()-t0)+'ms'+out);
    try{sess.close()}catch(e){}
    setTimeout(next,300);
  };
  s.on('response',h=>{out+=' HTTP='+h[':status'];});
  s.on('data',d=>{data=Buffer.concat([data,d]);});
  s.on('trailers',t=>{for(const k in t)trailers[k]=Buffer.from(t[k]).toString();});
  s.on('error',e=>{out+=' ST-ERR:'+e.message;});
  s.on('close',done);
  if(payload&&payload.length){s.write(gf(payload));s.end();}else{s.end();}
  setTimeout(()=>{try{s.close()}catch(e){}},timeout);
}
function A(){call('/repository.RepoServerService/TestRepository',f(1,f(1,Buffer.from('https://x.invalid/r.git'))),15000,'A-testrepo',B);}
function B(){call('/repository.RepoServerService/GenerateManifest',Buffer.alloc(0),15000,'B-emptyGM',C);}
function C(){call('/repository.RepoServerService/GenerateManifestWithFiles',f(2,Buffer.from('master')),15000,'C-withfiles-header-only',()=>process.exit(0));}
A();
