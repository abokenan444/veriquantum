
// Minimal WebAuthn helpers: base64url <-> ArrayBuffer
function b64uToBytes(b64u){
  const pad = '='.repeat((4 - b64u.length % 4) % 4);
  const b64 = (b64u.replace(/-/g, '+').replace(/_/g, '/')) + pad;
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i=0; i<bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bytesToB64u(buf){
  const bytes = new Uint8Array(buf);
  let bin='';
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// Register (create) a passkey for current user
async function vqRegisterPasskey(){
  const res = await fetch('/webauthn/reg/options', {method:'POST'});
  const opts = await res.json();
  // Decode challenge and user.id
  opts.publicKey.challenge = b64uToBytes(opts.publicKey.challenge);
  opts.publicKey.user.id = b64uToBytes(opts.publicKey.user.id);
  if (opts.publicKey.excludeCredentials){
    for (const cred of opts.publicKey.excludeCredentials){
      cred.id = b64uToBytes(cred.id);
    }
  }
  const cred = await navigator.credentials.create({publicKey: opts.publicKey});
  const attestationObject = bytesToB64u(cred.response.attestationObject);
  const clientDataJSON = bytesToB64u(cred.response.clientDataJSON);
  const rawId = bytesToB64u(cred.rawId);
  const data = {id: cred.id, rawId, type: cred.type, response: {attestationObject, clientDataJSON}};
  const verify = await fetch('/webauthn/reg/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const out = await verify.json();
  alert(out.ok ? 'Passkey registered.' : ('Failed: ' + (out.error || '')));
  location.reload();
}

// Authenticate (assert) for current user OR for a biometric session (via ?session_id=)
async function vqAuthenticatePasskey(sessionId){
  const url = sessionId ? `/webauthn/auth/options?session_id=${encodeURIComponent(sessionId)}` : '/webauthn/auth/options';
  const res = await fetch(url, {method:'POST'});
  const opts = await res.json();
  opts.publicKey.challenge = b64uToBytes(opts.publicKey.challenge);
  if (opts.publicKey.allowCredentials){
    for (const cred of opts.publicKey.allowCredentials){
      cred.id = b64uToBytes(cred.id);
    }
  }
  const assertion = await navigator.credentials.get({publicKey: opts.publicKey});
  const authData = bytesToB64u(assertion.response.authenticatorData);
  const clientDataJSON = bytesToB64u(assertion.response.clientDataJSON);
  const signature = bytesToB64u(assertion.response.signature);
  const userHandle = assertion.response.userHandle ? bytesToB64u(assertion.response.userHandle) : null;
  const rawId = bytesToB64u(assertion.rawId);
  const payload = {id: assertion.id, rawId, type: assertion.type, response:{authenticatorData:authData, clientDataJSON, signature, userHandle}};
  const vurl = sessionId ? `/webauthn/auth/verify?session_id=${encodeURIComponent(sessionId)}` : '/webauthn/auth/verify';
  const verify = await fetch(vurl, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const out = await verify.json();
  if (out.ok){
    alert(sessionId ? 'Biometric session verified.' : 'Authenticated.');
    if (out.redirect){ location.href = out.redirect; }
  }else{
    alert('Verification failed: ' + (out.error || ''));
  }
}
