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
  assert(!source.includes('localStorage'));assert(!source.includes('signPsbt'));assert(!source.includes('sendBitcoin'));
  console.log('Wallet adapter and message-only safeguards: passed');
})().catch(error=>{console.error(error);process.exitCode=1});
