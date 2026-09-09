const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../web/bio-wallet.js'),'utf8');
const sandbox={window:{},console};vm.createContext(sandbox);vm.runInContext(source.replaceAll('export ',''),sandbox);
(async()=>{
  const calls=[];
  sandbox.window.unisat={requestAccounts:async()=>['owner'],signMessage:async(...args)=>{calls.push(args);return 'proof'}};
  assert.equal(await (await sandbox.connectProvider('unisat','owner'))('message'),'proof');
  assert.deepEqual(calls.pop(),['message','bip322-simple']);
  await assert.rejects(()=>sandbox.connectProvider('unisat','other'),/owns this Bitmap/);
  sandbox.window.okxwallet={bitcoin:{connect:async()=>({address:'owner'}),signMessage:async(...args)=>{calls.push(args);return 'okx-proof'}}};
  assert.equal(await (await sandbox.connectProvider('okx','owner'))('msg'),'okx-proof');
  assert.deepEqual(calls.pop(),['msg','bip322-simple']);
  sandbox.window.XverseProviders={BitcoinProvider:{request:async(method,params)=>{
    calls.push([method,params]);
    return {result:method==='wallet_connect'?{addresses:[{address:'owner',purpose:'ordinals'}]}:{signature:'xverse-proof'}};
  }}};
  assert.equal(await (await sandbox.connectProvider('xverse','owner'))('hello'),'xverse-proof');
  assert.equal(calls[0][0],'wallet_connect');assert.equal(calls[1][0],'signMessage');assert.equal(calls[1][1].protocol,'BIP322');assert.equal(calls[1][1].address,'owner');
  sandbox.window={};await assert.rejects(()=>sandbox.connectProvider('unisat','owner'),/not available/);
  const text=(origin,owner,bitmap,nonce)=>origin+' requests a Bitmap Lord Bio sign-in.\n\nAddress: '+owner
    +'\nBitmap: '+bitmap+'.bitmap\n\nThis signature only allows editing your public Bio and posting as Lord.'
    +'\nNo Bitcoin transfer. No transaction. No spending permission.\n\nURI: '+origin+'/'+bitmap
    +'\nNonce: '+nonce+'\nIssued at (Unix): 1788000000\nExpires at (Unix): 1788000300';
  const SITE='https://bitmap.bio';
  const good={nonce:'N1',address:'owner',message:text(SITE,'owner',7,'N1')};
  assert.equal(sandbox.assertChallenge(good,'owner',7,SITE),good.message);
  assert.equal(sandbox.assertChallenge(good,'owner','7',SITE),good.message);
  const rejects=/did not come from this site/;
  // A message the server did not scope to this origin, address, Bitmap or nonce
  // must never reach the wallet.
  assert.throws(()=>sandbox.assertChallenge(good,'owner',7,'https://evil.example'),rejects);
  assert.throws(()=>sandbox.assertChallenge(good,'other',7,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge(good,'owner',8,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge({...good,nonce:'N2'},'owner',7,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge({...good,address:'other'},'owner',7,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge({nonce:'N1',address:'owner',message:42},'owner',7,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge({nonce:'N1',address:'owner',message:'x'.repeat(2049)},'owner',7,SITE),rejects);
  assert.throws(()=>sandbox.assertChallenge(null,'owner',7,SITE),rejects);
  // A homograph prefix must not satisfy the origin check.
  assert.throws(()=>sandbox.assertChallenge({nonce:'N1',address:'owner',message:text('https://bitmap.bio.evil.test','owner',7,'N1')},'owner',7,SITE),rejects);
  assert(!source.includes('localStorage'));assert(!source.includes('signPsbt'));assert(!source.includes('sendBitcoin'));
  console.log('Wallet adapter and message-only safeguards: passed');
})().catch(error=>{console.error(error);process.exitCode=1});
