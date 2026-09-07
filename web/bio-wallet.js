// Lazy, SDK-free wallet adapters. Sessions live only in this tab's memory.
let session=null,current=null,dialog=null,busy=false;
const $=id=>document.getElementById(id);
export async function connectProvider(kind,owner){
  if(kind==='unisat'){
    const p=window.unisat;if(!p)throw new Error('UniSat is not available. Use its extension or open this page in the wallet browser.');
    const accounts=await p.requestAccounts();if(!accounts.includes(owner))throw new Error('Select the wallet address that owns this Bitmap.');
    return message=>p.signMessage(message,'bip322-simple');
  }
  if(kind==='okx'){
    const p=window.okxwallet?.bitcoin;if(!p)throw new Error('OKX Bitcoin wallet is not available. Use its extension or wallet browser.');
    const account=await p.connect();if(account.address!==owner)throw new Error('Select the wallet address that owns this Bitmap.');
    return message=>p.signMessage(message,'bip322-simple');
  }
  if(kind==='xverse'){
    const p=window.XverseProviders?.BitcoinProvider||window.BitcoinProvider;if(!p?.request)throw new Error('Xverse is not available. Use its extension or wallet browser.');
    const call=async(method,params)=>{const response=await p.request(method,params);if(response.error)throw new Error(response.error.message||'Wallet request cancelled.');if(!response.result)throw new Error('Please update Xverse and try again.');return response.result};
    const account=await call('wallet_connect',{addresses:['ordinals','payment'],message:'Connect to edit your Bitmap Lord Bio. No transactions.'});
    if(!account.addresses?.some(a=>a.address===owner))throw new Error('Select the wallet account that owns this Bitmap.');
    return async message=>(await call('signMessage',{address:owner,message,protocol:'BIP322'})).signature;
  }
  throw new Error('Choose a supported Bitcoin wallet.');
}
function status(message='',ok=false){const box=$('bio-editor-status');box.textContent=message;box.classList.toggle('is-ok',ok)}
async function api(action,payload,timeout=15000){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try{const response=await fetch(`/api/lord-bio/${current.bitmap}/${action}`,{method:'POST',credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json',...(session?{Authorization:'Bearer '+session.token}:{})},body:JSON.stringify(payload)});let body;try{body=await response.json()}catch{throw new Error('The server returned an invalid response. Please reload.')}if(!response.ok)throw new Error(body.error||'Please try again.');return body}catch(error){if(error.name==='AbortError')throw new Error('The request timed out. Please try again.');throw error}finally{clearTimeout(timer)}
}
function fill(profile){
  $('bio-editor-name').value=profile.name?.startsWith('Lord of ')?'':profile.name||'';
  $('bio-editor-bio').value=profile.bio==='This Lord has not written a bio yet.'?'':profile.bio||'';
  $('bio-editor-avatar').value=profile.avatar_number??'';
  for(const k of ['x','telegram','discord','website','tiktok','instagram','youtube','gmgn'])$('bio-editor-'+k).value=profile.social?.[k]||'';
  $('bio-editor-image').replaceChildren();
  if(/^\/storage\/ads\/offline\/[A-Za-z0-9_.-]+$/.test(profile.avatar_url||'')){const img=document.createElement('img');img.src=profile.avatar_url;img.alt='Current avatar';$('bio-editor-image').append(img)}
}
function init(){
  dialog=document.createElement('dialog');dialog.className='bio-editor';dialog.setAttribute('aria-labelledby','bio-editor-title');
  dialog.innerHTML=`<button type="button" id="bio-editor-close" class="bio-editor-close" aria-label="Close editor">×</button><h2 id="bio-editor-title">Your profile. Your keys.</h2><p class="bio-editor-safety">Only sign a message. We never ask for your seed phrase, private key, Bitcoin transfer or spending approval. Always check the website address in your wallet.</p><p id="bio-editor-owner" class="bio-editor-owner"></p><div id="bio-editor-connect"><p>Connect the address that owns this Bitmap. Ownership is checked against our cached registry.</p><div class="bio-wallet-choices"><button type="button" data-wallet="unisat">UniSat</button><button type="button" data-wallet="xverse">Xverse</button><button type="button" data-wallet="okx">OKX</button></div><p class="bio-editor-note">Beta supports native SegWit (bc1q) and Taproot (bc1p) single-key addresses. On mobile, open this page inside your wallet’s browser.</p><details><summary>Message to sign</summary><pre id="bio-editor-challenge">Choose your wallet to request a one-use message.</pre></details></div><form id="bio-editor-form" hidden><label>Display name<input id="bio-editor-name" maxlength="60" autocomplete="off"></label><label>Your Bio<textarea id="bio-editor-bio" maxlength="500" rows="3"></textarea></label><label>Avatar · Image inscription number<input id="bio-editor-avatar" inputmode="numeric" placeholder="e.g. 2" autocomplete="off"></label><div class="bio-avatar-row"><div id="bio-editor-image"></div><button type="button" id="bio-editor-preview">Preview avatar</button></div><p class="bio-editor-note">Same image rules as map ads: use an inscription number, never an external URL. Supported GIFs become a static local thumbnail. Non-image inscriptions are rejected. Leave blank for the Bitcoin avatar.</p><div class="bio-editor-links"><label>X<input id="bio-editor-x" type="url" maxlength="300" placeholder="https://x.com/yourname"></label><label>Telegram<input id="bio-editor-telegram" type="url" maxlength="300" placeholder="https://t.me/yourname"></label><label>Discord<input id="bio-editor-discord" type="url" maxlength="300" placeholder="https://discord.gg/…"></label><label>Website<input id="bio-editor-website" type="url" maxlength="300" placeholder="https://example.com"></label></div><button id="bio-editor-save" type="submit">Save my Bio</button></form><p id="bio-editor-status" role="status"></p>`;
  const linksBox=dialog.querySelector('.bio-editor-links');for(const [key,labelText,placeholder] of [['tiktok','TikTok','https://www.tiktok.com/@yourname'],['instagram','Instagram','https://www.instagram.com/yourname'],['youtube','YouTube','https://www.youtube.com/@yourname'],['gmgn','GMGN','https://gmgn.ai/...']]){const label=document.createElement('label'),input=document.createElement('input');label.append(document.createTextNode(labelText));input.id='bio-editor-'+key;input.type='url';input.maxLength=300;input.placeholder=placeholder;label.append(input);linksBox?.append(label)}
  document.body.append(dialog);$('bio-editor-close').addEventListener('click',()=>dialog.close());dialog.addEventListener('cancel',()=>{if(busy)status('You may reopen the editor to check the result.')});
  dialog.querySelectorAll('[data-wallet]').forEach(button=>button.addEventListener('click',async()=>{
    if(busy)return;busy=true;dialog.querySelectorAll('[data-wallet]').forEach(b=>b.disabled=true);status('Waiting for wallet…');
    try{const sign=await connectProvider(button.dataset.wallet,current.lord);const challenge=await api('challenge',{address:current.lord});$('bio-editor-challenge').textContent=challenge.message;status('Check the message in your wallet, then sign to verify ownership.');const signature=await sign(challenge.message);status('Verifying your signature…');const result=await api('verify',{nonce:challenge.nonce,signature});session=result;current.onAuthenticated(result.token);$('bio-editor-connect').hidden=true;$('bio-editor-form').hidden=false;status('Ownership verified. You can now edit your Bio.',true)}catch(error){status(error.message||'Wallet request cancelled.')}finally{busy=false;dialog.querySelectorAll('[data-wallet]').forEach(b=>b.disabled=false)}
  }));
  $('bio-editor-preview').addEventListener('click',async()=>{
    if(busy)return;const number=$('bio-editor-avatar').value.trim();if(!/^-?\d{1,12}$/.test(number)){status('Enter an image inscription number.');return}busy=true;const button=$('bio-editor-preview');button.disabled=true;$('bio-editor-image').replaceChildren();$('bio-editor-image').classList.add('is-loading');status('Looking up the inscription and preparing its static thumbnail…');
    try{const {asset}=await api('avatar',{avatar_number:number},60000);if($('bio-editor-avatar').value.trim()===number){const img=document.createElement('img');img.src=asset.asset_url;img.alt='Avatar preview · #'+number;$('bio-editor-image').append(img);status('Avatar preview ready. Click Save my Bio to publish it.',true)}}catch(error){status(error.message)}finally{busy=false;button.disabled=false;$('bio-editor-image').classList.remove('is-loading')}
  });
  $('bio-editor-form').addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;busy=true;const button=$('bio-editor-save');button.disabled=true;status('Saving your Bio…');
    try{const social={};for(const k of ['x','telegram','discord','website','tiktok','instagram','youtube','gmgn'])social[k]=$('bio-editor-'+k).value.trim();const result=await api('save',{name:$('bio-editor-name').value,bio:$('bio-editor-bio').value,avatar_number:$('bio-editor-avatar').value.trim(),social},60000);current.profile=result.profile;current.onSaved(result.profile);status('Your Bio is saved. Close this panel to share it.',true)}catch(error){status(error.message)}finally{busy=false;button.disabled=false}
  });
}
export function openEditor(options){
  if(!dialog)init();if(busy){if(!dialog.open)dialog.showModal();return}current=options;
  const valid=session&&session.lord===options.lord&&Number(session.bitmap)===Number(options.bitmap)&&session.expires_at>Date.now()/1000;
  if(!valid)session=null;else current.onAuthenticated(session.token);
  $('bio-editor-owner').textContent=options.lord;$('bio-editor-connect').hidden=Boolean(valid);$('bio-editor-form').hidden=!valid;fill(options.profile||{});status();if(!dialog.open)dialog.showModal();
}
