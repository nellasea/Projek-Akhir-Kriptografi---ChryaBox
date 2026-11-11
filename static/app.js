/* CHRYA BOX responsive web interface. All confidential operations enforce server authorization. */
const $=(id)=>document.getElementById(id);
const state={me:null,csrf:'',view:'dashboard',flow:null,stage:'login',contacts:[],stats:null,reply:null,usbState:null,biometricMode:'verify',hasFace:false,hasPasskey:false,face:null,contactQuery:'',contactFilter:'all',msgBox:'inbox',msgQuery:'',fileQuery:'',fileCategory:'',noteQuery:'',noteCategory:'',editingNote:null,notifUnreadOnly:false,openMessage:null,refreshing:false};
const escapeHtml=(x)=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=(s,n=110)=>String(s||'').length>n?String(s).slice(0,n)+'…':String(s||'');
const dateFmt=(s)=>s?new Date(s).toLocaleString('id-ID',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}):'';
const tag=(val)=>`<span class="tag ${val==='unread'||val==='pending'?'warn':val==='blocked'||val==='failed'||val==='revoked'||val==='lost'?'danger':'muted'}">${escapeHtml(val)}</span>`;
let toastTimer;
function toast(message,error=false){const t=$('toast');if(!t)return;t.textContent=String(message);t.className='toast visible'+(error?' error':'');clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.className='toast',4500)}
async function api(path,{method='GET',body=null,download=false}={}){
  const opt={method,credentials:'same-origin',headers:{}};
  if(method!=='GET'&&method!=='HEAD'&&state.csrf)opt.headers['X-CSRF-Token']=state.csrf;
  if(body!==null){if(body instanceof FormData) opt.body=body;else{opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body)}}
  let res;
  try{res=await fetch(path,opt)}catch(e){throw Error('Server tidak terhubung. Pastikan CHRYA BOX aktif.')}
  if(res.status===423){showLocked('USB Vault Key tidak ditemukan. Pasang kembali flashdisk pada server.');throw Error('Aplikasi terkunci: USB dicabut.')}
  if(download){
    if(!res.ok){
      const err=await res.json().catch(()=>({error:'Gagal mengunduh data.'}));
      throw Error(err.error||'Gagal mengunduh data.');
    }
    return {blob:await res.blob(),filename:res.headers.get('Content-Disposition')||''};
  }
  const data=await res.json().catch(()=>({error:'Respons server tidak valid.'}));
  if(!res.ok||!data.ok)throw Error(data.error||'Operasi gagal');
  return data;
}
function showLocked(reason){if($('locked-screen'))return;const wrap=document.createElement('div');wrap.id='locked-screen';wrap.className='lock-overlay';wrap.innerHTML=`<div class="lock-card"><div class="lock-glyph">⌑</div><h2>Vault Terkunci</h2><p>${escapeHtml(reason)}</p><button class="btn btn-primary" id="retry-dongle">Periksa ulang USB Key</button><p class="small-note">Permintaan ke server ditolak sampai flashdisk terdaftar terdeteksi kembali.</p></div>`;document.body.append(wrap);$('retry-dongle').onclick=async()=>{const result=await fetch('/api/status').then(r=>r.json()).catch(()=>({authorized:false}));if(result.authorized){wrap.remove();state.me=null;state.csrf='';$('workspace').classList.add('hidden');$('public').classList.remove('hidden');toast('Flashdisk terdeteksi. Silakan login kembali.');}else toast(result.reason||'Flashdisk belum terdeteksi.',true)}}
function authOpen(tab='login'){$('auth-layer').classList.remove('hidden');setAuthTab(tab)}
function authClose(){stopFaceCamera();$('auth-layer').classList.add('hidden')}
function setAuthTab(tab){
  stopFaceCamera();state.stage=tab;state.enrollRequested=false;
  $('auth-forms').classList.remove('hidden');$('usb-step').classList.add('hidden');
  $('passkey-step').classList.add('hidden');$('face-camera-step').classList.add('hidden');
  $('registration-done-step').classList.add('hidden');
  $('auth-tabs').classList.toggle('hidden',tab==='recover');
  $('login-form').classList.toggle('hidden',tab!=='login');
  $('register-form').classList.toggle('hidden',tab!=='register');
  if($('recover-form'))$('recover-form').classList.toggle('hidden',tab!=='recover');
  document.querySelectorAll('[data-auth-tab]').forEach(x=>x.classList.toggle('active',x.dataset.authTab===tab));
  $('auth-title').textContent=tab==='login'?'Welcome back':(tab==='register'?'Buat brankas pribadi':'Pemulihan Akun Darurat');
  $('auth-hint').textContent=tab==='login'?'Buka vault dengan 3 lapisan verifikasi.':(tab==='register'?'Bergabung dalam komunikasi terenkripsi.':'Gunakan Recovery Code sekali pakai untuk memulihkan akses.');
  if(tab==='register')scheduleUsernameCheck(0);
}
function authStep(stage){
 state.stage=stage;
 $('auth-forms').classList.add('hidden');$('auth-tabs').classList.add('hidden');
 $('usb-step').classList.toggle('hidden',stage!=='usb');
 $('passkey-step').classList.toggle('hidden',stage!=='passkey');
 $('registration-done-step').classList.add('hidden');
 $('face-camera-step').classList.add('hidden');
 const registering=state.biometricMode==='register';
 $('auth-title').textContent=stage==='usb'?(registering?'Daftar: keamanan USB':'Login: keamanan USB'):(registering?'Daftarkan wajah saat Register':'Login dengan Face Unlock');
 $('auth-hint').textContent=stage==='usb'?'Tahap 2/3 — verifikasi flashdisk sebelum menggunakan kamera':(registering?'Tahap 3/3 — rekam wajah terlebih dahulu untuk menyelesaikan pendaftaran':'Tahap 3/3 — cocokkan wajah yang sudah didaftarkan saat Register');
 if(stage==='passkey'){
   $('passkey-action-label').textContent=registering?'◉ REGISTER • Daftarkan wajah pertama':'◉ LOGIN • Verifikasi wajah terdaftar';
   $('face-open-btn').textContent=registering?'📷 Buka Kamera & Daftarkan Wajah':'📷 Buka Kamera untuk Login';
   $('passkey-verify-btn').classList.toggle('hidden',registering||!state.hasPasskey);
   $('face-open-btn').classList.toggle('hidden',!registering&&!state.hasFace);
   $('passkey-description').textContent=registering?'Kamera akan meminta izin dari browser. Posisikan wajah menghadap depan, lalu pindai satu kali untuk menyelesaikan pendaftaran. Belum dapat masuk sebelum wajah berhasil tersimpan.':(state.hasFace?'Arahkan wajah ke kamera untuk mencocokkannya dengan data wajah saat pendaftaran.':'Akun lama ini memakai Windows Hello/Passkey. Setelah login, daftarkan kamera wajah di Security Center.');
 }
}
function registrationComplete(message){
 stopFaceCamera();state.flow=null;state.biometricMode='verify';state.hasFace=true;
 $('auth-layer').classList.remove('hidden');$('auth-forms').classList.add('hidden');
 $('auth-tabs').classList.add('hidden');$('usb-step').classList.add('hidden');
 $('passkey-step').classList.add('hidden');$('face-camera-step').classList.add('hidden');
 $('registration-done-step').classList.remove('hidden');
 $('auth-title').textContent='Pendaftaran Selesai';
 $('auth-hint').textContent=message||'Face Unlock kamu sudah siap digunakan saat login.';
}
const b64uToBytes=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const bytesToB64u=(b)=>{let binary='';for(const c of new Uint8Array(b))binary+=String.fromCharCode(c);return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const hex=(buffer)=>Array.from(new Uint8Array(buffer)).map(x=>x.toString(16).padStart(2,'0')).join('');
function credJSON(c){const data={id:c.id,rawId:bytesToB64u(c.rawId),type:c.type,clientExtensionResults:typeof c.getClientExtensionResults==='function'?c.getClientExtensionResults():{},authenticatorAttachment:c.authenticatorAttachment||null,response:{clientDataJSON:bytesToB64u(c.response.clientDataJSON)}};
 if(c.response.attestationObject)data.response.attestationObject=bytesToB64u(c.response.attestationObject);
 if(c.response.authenticatorData)data.response.authenticatorData=bytesToB64u(c.response.authenticatorData);
 if(c.response.signature)data.response.signature=bytesToB64u(c.response.signature);
 if(c.response.userHandle)data.response.userHandle=bytesToB64u(c.response.userHandle);
 if(typeof c.response.getTransports==='function')data.response.transports=c.response.getTransports();
 return data;}
async function createOrGetCredential(data){if(!window.PublicKeyCredential||!navigator.credentials){throw Error('Perangkat/browser ini belum mendukung WebAuthn. Gunakan Chrome, Edge atau Safari terbaru pada HTTPS/localhost.');}
 const opts=data.publicKey;
 opts.challenge=b64uToBytes(opts.challenge);
 if(data.kind==='register'){opts.user.id=b64uToBytes(opts.user.id);for(const c of opts.excludeCredentials||[])c.id=b64uToBytes(c.id);}else for(const c of opts.allowCredentials||[])c.id=b64uToBytes(c.id);
 let credential;
 try{credential=data.kind==='register'?await navigator.credentials.create({publicKey:opts}):await navigator.credentials.get({publicKey:opts});}
 catch(e){throw Error('Verifikasi perangkat gagal/dibatalkan: '+String(e.message||e.name))}
 return credJSON(credential);}
async function biometricVerify(){
 const data=await api('/api/auth/webauthn/options',{method:'POST',body:{flow:state.flow}});
 const credential=await createOrGetCredential(data);
 const done=await api('/api/auth/webauthn/verify',{method:'POST',body:{flow:state.flow,credential}});
 state.me=done.user;state.csrf=done.csrf;state.flow=null;authClose();await openWorkspace();toast('Brankas dibuka. Selamat datang, '+state.me.full_name+'!');}
function stopFaceCamera(){
 if(state.face?.stream){for(const track of state.face.stream.getTracks())track.stop();}
 const video=$('face-video');if(video){video.pause();video.srcObject=null;}
 state.face=null;
}
function cameraSnapshot(){
 const video=$('face-video');if(!video.videoWidth||!video.videoHeight)throw Error('Kamera belum siap. Tunggu tampilan video muncul.');
 const canvas=document.createElement('canvas');const ratio=video.videoWidth/video.videoHeight;
 canvas.width=640;canvas.height=Math.max(240,Math.round(640/ratio));
 const ctx=canvas.getContext('2d');ctx.translate(canvas.width,0);ctx.scale(-1,1);
 ctx.drawImage(video,0,0,canvas.width,canvas.height);
 return canvas.toDataURL('image/jpeg',0.78);
}
async function openFaceCamera(context='auth',passwordConfirm=''){
 if(!navigator.mediaDevices?.getUserMedia)throw Error('Kamera memerlukan halaman HTTPS atau http://localhost:8765.');
 stopFaceCamera();
 let stream;
 try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'user',width:{ideal:640},height:{ideal:480}},audio:false});}
 catch(e){const reason=e.name==='NotAllowedError'?'Izin kamera ditolak. Klik ikon kamera di address bar Chrome/Edge untuk mengizinkan akses.':e.name==='NotFoundError'?'Kamera laptop tidak terdeteksi.':'Tidak dapat membuka kamera: '+(e.message||e.name);throw Error(reason)}
 state.face={stream,context,flow:state.flow,frames:[],options:null,password:passwordConfirm};
 try{
  const options=context==='security'
    ?await api('/api/security/face/options',{method:'POST',body:{password:passwordConfirm}})
    :await api('/api/auth/face/options',{method:'POST',body:{flow:state.flow}});
  state.face.options=options;state.face.flow=options.flow||state.flow;
  $('auth-layer').classList.remove('hidden');$('auth-forms').classList.add('hidden');
  $('auth-tabs').classList.add('hidden');$('usb-step').classList.add('hidden');
  $('passkey-step').classList.add('hidden');$('face-camera-step').classList.remove('hidden');
  $('auth-title').textContent=options.kind==='register'?'Pendaftaran Kamera Wajah':'Verifikasi Wajah';
  $('auth-hint').textContent='Browser menggunakan kamera setelah kamu mengizinkannya.';
  $('face-camera-title').textContent=options.kind==='register'?'Register: Rekam Wajah':'Login: Verifikasi Wajah Terdaftar';
  $('face-capture-one').textContent=options.kind==='register'?'📸 Pindai Sekali & Daftarkan Wajah':'📸 Pindai Sekali & Login';
  $('face-camera-hint').textContent='Hadapkan wajah ke kamera. Pastikan hanya satu wajah terlihat jelas dan pencahayaan cukup.';
  $('face-direction-guide').textContent='Posisikan wajah di tengah bingkai, lalu tekan Pindai Wajah sekali. Tidak perlu menoleh.';
  $('face-camera-status').textContent='Kamera aktif — siap mengambil satu foto wajah';
  $('face-capture-one').classList.remove('hidden');
  $('face-capture-one').disabled=false;
  const video=$('face-video');video.srcObject=stream;await video.play();
 }catch(error){stopFaceCamera();throw error}
}
async function captureFaceOnce(){
 if(!state.face||!state.face.options)throw Error('Kamera belum aktif.');
 const current=state.face;
 const captureButton=$('face-capture-one');
 captureButton.disabled=true;
 $('face-camera-status').textContent='Memeriksa kecocokan wajah (SFace 128-D)...';
 try{
  // Only ONE camera snapshot is sent; no left/right head movement required.
  const frames=[cameraSnapshot()];
  const endpoint=current.context==='security'?'/api/security/face/verify':'/api/auth/face/verify';
  const result=await api(endpoint,{method:'POST',body:{flow:current.flow,frames,password:current.password}});
  if(current.context==='security'){
   stopFaceCamera();authClose();await showSecurity();toast(result.message||'Wajah kamera berhasil disimpan.');
  }else if(result.registered){
   registrationComplete(result.message);
   toast('Wajah tersimpan. Silakan login menggunakan Face Unlock.');
  }else{
   stopFaceCamera();authClose();state.me=result.user;state.csrf=result.csrf;state.flow=null;
   await openWorkspace();toast('Face Unlock berhasil. Selamat datang, '+state.me.full_name+'!');
  }
 }catch(error){
  $('face-camera-status').textContent='Pemindaian gagal: '+error.message;
  $('face-direction-guide').textContent='Tetap hadap kamera. Sesuaikan posisi dan pencahayaan, lalu coba pindai sekali lagi.';
  throw error;
 }finally{captureButton.disabled=false;}
}
function cancelFaceCamera(){
 const context=state.face?.context;
 stopFaceCamera();$('face-camera-step').classList.add('hidden');
 if(context==='security')authClose();
 else authStep('passkey');
}
async function verifyUSB(){const input=$('usb-key-file');if(!input.files.length)throw Error('Pilih file chrya_usb.key di flashdisk yang terdaftar.');const file=input.files[0];if(file.name!=='chrya_usb.key')throw Error('Nama file harus chrya_usb.key');const raw=await file.arrayBuffer();if(raw.byteLength!==32)throw Error('Isi USB Key harus berupa 32 byte.');
 const challenge=await api('/api/auth/usb/challenge',{method:'POST',body:{flow:state.flow}});
 const hmacKey=await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const response=hex(await crypto.subtle.sign('HMAC',hmacKey,b64uToBytes(challenge.challenge)));
 await api('/api/auth/usb/verify',{method:'POST',body:{flow:state.flow,response}});
 authStep('passkey');toast('Kunci USB tervalidasi. Lanjutkan biometrik.');}
let usernameTimer=null,usernameRequestSerial=0;
function usernameFeedback(message,kind=''){
  const hint=$('username-status'),field=$('register-username'),submit=$('register-submit');
  if(!hint||!field||!submit)return;
  hint.textContent=message;
  hint.className='username-availability'+(kind?' '+kind:'');
  field.setAttribute('aria-invalid',kind==='unavailable'?'true':'false');
  submit.disabled=kind==='unavailable'||kind==='checking';
}
function scheduleUsernameCheck(delay=350){
  clearTimeout(usernameTimer);
  const serial=++usernameRequestSerial;
  const field=$('register-username');if(!field)return;
  const name=field.value.trim().toLowerCase();
  if(!name){usernameFeedback('Username harus unik. Masukkan 3–32 karakter untuk memeriksa.');return}
  if(!/^[a-z0-9_.]{3,32}$/.test(name)){
    usernameFeedback('Gunakan 3–32 karakter: huruf, angka, titik, atau underscore.','unavailable');return;
  }
  usernameFeedback('Memeriksa username di database server…','checking');
  usernameTimer=setTimeout(async()=>{
    try{
      const result=await api('/api/auth/username-availability?username='+encodeURIComponent(name));
      if(serial!==usernameRequestSerial||field.value.trim().toLowerCase()!==name)return;
      usernameFeedback(result.message,result.available?'available':'unavailable');
    }catch(e){
      if(serial!==usernameRequestSerial)return;
      usernameFeedback('Tidak bisa memeriksa sekarang. Pendaftaran tetap dicek oleh server.');
    }
  },delay);
}
async function formRegister(e){
 e.preventDefault();const b=Object.fromEntries(new FormData(e.target));
 b.username=String(b.username||'').trim().toLowerCase();
 if(b.password!==b.confirm)throw Error('Konfirmasi password tidak cocok.');
 delete b.confirm;
 let data;
 try{data=await api('/api/auth/register',{method:'POST',body:b})}
 catch(err){if(/username sudah terdaftar/i.test(err.message)){usernameFeedback('Username sudah terdaftar. Silakan ganti username.','unavailable')}throw err}
 state.flow=data.flow;state.biometricMode='register';state.hasFace=false;state.hasPasskey=false;authStep('usb');
}
async function formLogin(e){e.preventDefault();const form=$('login-form');if(!form.reportValidity())return;const b=Object.fromEntries(new FormData(form));const data=await api('/api/auth/start',{method:'POST',body:b});state.flow=data.flow;state.biometricMode=data.setup?'register':'verify';state.hasFace=!!data.face_enrolled;state.hasPasskey=!!data.passkey_enrolled;if(data.setup)toast('Pendaftaran wajah akun belum selesai. Lengkapi dahulu, lalu login kembali.');authStep('usb');}
async function formRecover(e){
 e.preventDefault();const b=Object.fromEntries(new FormData(e.target));
 const payload={identity:b.identity,recovery_code:b.recovery_code,new_password:b.new_password||null,reset_face:!!b.reset_face,revoke_usb:!!b.revoke_usb};
 const data=await api('/api/auth/recover',{method:'POST',body:payload});
 state.flow=data.flow;state.biometricMode=data.setup?'register':'verify';state.hasFace=!data.setup;state.hasPasskey=false;
 toast(data.message);authStep('usb');
}
function safeRun(fn){return async(...args)=>{try{await fn(...args)}catch(e){toast(e.message||String(e),true)}}}
const pageHead=(name,sub,action='')=>`<div class="page-head"><div><div class="eyebrow-sm">CHRYA BOX / PRIVATE WORKSPACE</div><h1>${escapeHtml(name)}</h1><p>${escapeHtml(sub)}</p></div>${action}</div>`;
const empty=(msg,details='')=>`<div class="empty"><div class="empty-icon">▣</div><strong>${escapeHtml(msg)}</strong><p>${escapeHtml(details)}</p></div>`;
function rowMessage(m){return `<div class="data-row" data-open-message="${m.id}"><div class="row-icon">${m.pinned?'★':'✉'}</div><div class="row-content"><strong>${m.pinned?'[Pin] ':''}${escapeHtml(short(m.subject,70))}</strong><small>${escapeHtml(m.person.full_name)} · @${escapeHtml(m.person.username)} · ${escapeHtml(m.delivery_indicator||'')}</small></div><div class="row-right"><div>${dateFmt(m.created_at)}</div><div style="margin-top:5px">${tag(m.status)}</div></div></div>`}
async function openWorkspace(){
  $('public').classList.add('hidden');
  $('workspace').classList.remove('hidden');
  $('user-bubble').textContent=(state.me.full_name||'U')[0].toUpperCase();
  $('side-security').textContent='3 factors enabled';
  if(window.Notification && Notification.permission==='default'){
    Notification.requestPermission().catch(()=>{});
  }
  await navigate('dashboard');
}
function setNav(view){state.view=view;const names={dashboard:'Dashboard',inbox:'Inbox',sent:'Sent Messages',compose:'Compose',contacts:'Contacts',vault:'My Vault',files:'File Vault',stego:'Steganography',ledger:'Blockchain Ledger',notifications:'Notifications',security:'Security Center'};$('current-view').textContent=names[view]||view;document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('selected',b.dataset.view===view));$('sidebar').classList.remove('open');$('mobile-scrim').classList.add('hidden')}
async function navigate(view){state.openMessage=null;setNav(view);$('view').innerHTML='<div class="empty">Memuat data...</div>';try{
 if(view==='dashboard')await showDashboard();else if(view==='inbox'||view==='sent')await showMessages(view);else if(view==='compose')await showCompose();else if(view==='contacts')await showContacts();else if(view==='vault')await showVault();else if(view==='files')await showFiles();else if(view==='stego')await showStego();else if(view==='ledger')await showLedger();else if(view==='notifications')await showNotifications();else if(view==='security')await showSecurity();
 }catch(e){$('view').innerHTML=empty('Tidak dapat memuat konten',e.message);toast(e.message,true)}}

async function showDashboard(){const [s,m]=await Promise.all([api('/api/stats'),api('/api/messages?box=inbox')]);state.stats=s;syncActivityBadges(s);
 $('view').innerHTML=`${pageHead('Dashboard','Ringkasan aktivitas di ruang privat Anda.',`<button class="btn btn-primary btn-small" data-view="compose">＋ New message</button>`)}
 <div class="welcome-banner"><div><div class="eyebrow-sm">YOUR PRIVATE SPACE</div><h2>Welcome back, ${escapeHtml(state.me.full_name.split(' ')[0])}.</h2><p>Pesan dan file rahasia siap dikelola dalam satu brankas yang terlindungi. Kirim dan baca saat Anda siap.</p><span class="tag">◉ Protected by CHRYA BOX</span></div><span class="welcome-symbol">▣</span></div>
 <div class="stat-grid"><div class="stat-card"><div class="stat-head">Secret messages <span class="stat-ico">✉</span></div><div class="stat-number">${s.inbox}</div><div class="stat-trend">${s.unread} belum dibaca</div></div><div class="stat-card"><div class="stat-head">Sent messages <span class="stat-ico">↗</span></div><div class="stat-number">${s.sent}</div><div class="stat-trend">Tersimpan terenkripsi</div></div><div class="stat-card"><div class="stat-head">Trusted contacts <span class="stat-ico">♧</span></div><div class="stat-number">${s.contacts}</div><div class="stat-trend">Koneksi disetujui</div></div><div class="stat-card"><div class="stat-head">Encrypted files <span class="stat-ico">▤</span></div><div class="stat-number">${s.files}</div><div class="stat-trend">ChaCha20-Poly1305</div></div></div>
 <div class="dashboard-grid"><section class="card"><div class="card-title"><h2>Recent messages</h2><button class="link-button" data-view="inbox">View inbox →</button></div>${m.items.length?m.items.slice(0,5).map(rowMessage).join(''):empty('Belum ada pesan masuk','Hubungkan kontak lalu kirim pesan rahasia.')}</section><section class="card"><div class="card-title"><h2>Security overview</h2><button class="link-button" data-view="security">Details →</button></div><div class="data-row"><div class="row-icon">⌑</div><div class="row-content"><strong>Multi-factor authentication</strong><small>Argon2id + USB HMAC + Face Unlock SFace 128-D</small></div><span class="tag">Active</span></div><div class="data-row"><div class="row-icon">◈</div><div class="row-content"><strong>Message encryption</strong><small>Vigenère + AES-256-GCM (HKDF domain key)</small></div><span class="tag">Active</span></div><div class="data-row"><div class="row-icon">▤</div><div class="row-content"><strong>Secure file storage</strong><small>ChaCha20-Poly1305 + Wrapped File Key</small></div><span class="tag">Active</span></div><div class="data-row"><div class="row-icon">◎</div><div class="row-content"><strong>Audit ledger</strong><small>SHA-256 chain + Ed25519 Checkpoints</small></div><span class="tag">Available</span></div></section></div>`;}

async function showMessages(box=state.msgBox||'inbox',q=state.msgQuery||''){
 state.msgBox=box;state.msgQuery=q;
 const result=await api('/api/messages?box='+encodeURIComponent(box)+'&q='+encodeURIComponent(q));
 const titleMap={inbox:'Inbox',sent:'Sent messages',archive:'Archived messages',pinned:'Pinned messages'};
 $('view').innerHTML=`${pageHead(titleMap[box]||'Messages',box==='inbox'?'Surat digital terenkripsi yang dititipkan ke brankas Anda.':'Kelola riwayat pesan terenkripsi, arsip, dan pesan favorit Anda.',`<div class="inline-buttons"><button class="btn ${box==='inbox'?'btn-primary':'btn-muted'} btn-small" data-msg-box="inbox">Inbox</button><button class="btn ${box==='sent'?'btn-primary':'btn-muted'} btn-small" data-msg-box="sent">Sent</button><button class="btn ${box==='archive'?'btn-primary':'btn-muted'} btn-small" data-msg-box="archive">Arsip</button><button class="btn ${box==='pinned'?'btn-primary':'btn-muted'} btn-small" data-msg-box="pinned">★ Pin</button><button class="btn btn-primary btn-small" data-view="compose">✎ Compose</button></div>`)}
 <section class="card">
   <div class="card-title" style="flex-wrap:wrap;gap:10px">
     <h2>${escapeHtml(titleMap[box]||'Pesan')} <span class="tag muted">${result.items.length}</span></h2>
     <form id="message-search-form" class="inline-buttons" style="flex:1;max-width:420px"><input name="q" value="${escapeHtml(q)}" placeholder="Cari subjek, isi, atau pengirim..." style="flex:1;min-height:36px;padding:6px 12px;border-radius:9px;background:#0b1729;border:1px solid #30425b;color:#e5effb"><button class="btn btn-muted btn-small" type="submit">Cari</button>${q?`<button class="btn btn-ghost btn-small" type="button" data-clear-msg-search>Reset</button>`:''}</form>
   </div>
   ${result.items.length?result.items.map(rowMessage).join(''):empty('Tidak ada pesan ditemukan','Pesan terenkripsi yang sesuai akan muncul di sini.')}
 </section>`;
}

async function openMessage(id){
 state.openMessage=id;const data=await api('/api/messages/'+id);const m=data.message;const amReceiver=m.receiver_id===state.me.id;
 state.reply={recipient:m.person.username,reply_to:m.id,subject:m.subject.startsWith('Re:')?m.subject:'Re: '+m.subject};
 $('view').innerHTML=`${pageHead('Secret message','Pesan dibuka melalui sesi terverifikasi.',`<button class="btn btn-muted btn-small" data-msg-box="${state.msgBox||'inbox'}">← Kembali</button>`)}
 <div class="card form-card">
   <div class="inline-buttons" style="justify-content:space-between">
     <span class="tag">◈ AES-256-GCM Verified · ${escapeHtml(m.delivery_indicator||'')}</span>
     <span class="small-note">Dikirim: ${dateFmt(m.created_at)}${m.read_at?' · Dibaca: '+dateFmt(m.read_at):''}</span>
   </div>
   <h2 style="font-size:23px;margin:20px 0 6px">${m.pinned?'★ ':''}${escapeHtml(m.subject)}</h2>
   <div class="small-note">${amReceiver?'Dari':'Kepada'}: <b>${escapeHtml(m.person.full_name)}</b> (@${escapeHtml(m.person.username)})</div>
   <div class="response-view"><h3>Isi pesan</h3><p>${escapeHtml(m.body)}</p></div>
   <div class="panel-actions" style="margin-top:18px">
     <button class="btn btn-primary" id="reply-btn">↶ Balas pesan</button>
     <button class="btn btn-muted" data-pin-msg="${m.id}">${m.pinned?'☆ Lepas Pin':'★ Pin / Favorit'}</button>
     ${amReceiver?(m.archived?`<button class="btn btn-muted" data-unarchive="${m.id}">▤ Batal Arsip (Unarchive)</button>`:`<button class="btn btn-muted" data-archive="${m.id}">▤ Arsipkan</button>`):''}
     <button class="btn btn-danger" data-delete-msg="${m.id}">✕ Hapus Pesan</button>
     <button class="btn btn-danger" data-delete-conv="${escapeHtml(m.person.username)}">✕ Hapus Percakapan</button>
   </div>
 </div>`;
 $('reply-btn').onclick=safeRun(()=>navigate('compose'));
}

async function showCompose(){const contacts=await api('/api/contacts');const accepted=contacts.items.filter(x=>x.status==='accepted'&&x.connected);const unique=[...new Map(accepted.map(x=>[x.person.id,x.person])).values()];state.contacts=unique;
 const reply=state.reply;
 $('view').innerHTML=`${pageHead('Compose secret message','Tulis pesan, lalu sistem mengenkripsi sebelum menyimpan.',`<span class="tag">◈ Vigenère + AES-GCM</span>`)}<section class="card form-card"><h2>New encrypted message</h2><div class="stepper"><span class="step-active">1 · Compose</span><span>→</span><span>2 · Encrypt</span><span>→</span><span>3 · Deliver to vault</span></div><form id="compose-form"><label class="field">Recipient<select name="recipient" required><option value="">Pilih kontak yang sudah disetujui</option>${unique.map(p=>`<option value="${escapeHtml(p.username)}" ${reply?.recipient===p.username?'selected':''}>${escapeHtml(p.full_name)} (@${escapeHtml(p.username)})</option>`).join('')}</select></label><label class="field">Subject<input name="subject" required maxlength="150" value="${escapeHtml(reply?.subject||'')}" placeholder="Subjek pesan rahasia"></label><label class="field">Message<textarea name="body" required maxlength="12000" placeholder="Tulis informasi yang ingin disampaikan secara privat..."></textarea></label><div class="soft-warning">Pesan disimpan sebagai ciphertext di database. Email penerima hanya berisi pemberitahuan, bukan isi pesan. Sistem ini menggunakan Server-Side Encryption dengan pemisahan kunci domain HKDF.</div><div class="panel-actions" style="margin-top:18px"><button type="submit" class="btn btn-primary" ${unique.length?'':'disabled'}>Send encrypted message ↗</button><button type="button" class="btn btn-muted" data-view="contacts">Manage contacts</button></div></form>${unique.length?'':'<p class="small-note">Anda harus memiliki kontak berstatus Accepted sebelum mengirim pesan.</p>'}</section>`;}

function renderUserSearchResults(users,q){
 if(q.trim().length<1)return empty('Cari username atau nama lengkap','Ketik username atau nama lengkap pengguna pada server yang sama.');
 if(!users.length)return empty('Pengguna tidak ditemukan','Tidak ada akun dengan username atau nama lengkap "'+q+'". Periksa ejaan atau pastikan terdaftar di server yang sama.');
 return users.map(u=>{
   let button='';
   if(u.relation==='accepted')button=`<button class="btn btn-primary btn-small" data-compose-to="${escapeHtml(u.username)}">Kirim pesan ↗</button>`;
   else if(u.relation==='pending_outgoing')button='<span class="tag warn">Menunggu persetujuan</span>';
   else if(u.relation==='pending_incoming')button='<span class="tag warn">Undangan masuk ↓</span>';
   else if(u.relation==='blocked')button=`<button class="btn btn-muted btn-small" data-unblock="${u.id}">Buka Blokir</button>`;
   else button=`<button class="btn btn-primary btn-small" data-invite="${escapeHtml(u.username)}">＋ Tambah kontak</button>`;
   return `<div class="data-row contact-result-row"><div class="row-icon">${escapeHtml((u.full_name||u.username).slice(0,1).toUpperCase())}</div><div class="row-content"><strong>${escapeHtml(u.full_name)}</strong><small>@${escapeHtml(u.username)}</small></div><div class="contact-action">${button}</div></div>`;
 }).join('');
}
async function liveSearchContacts(term){
 if(state.view!=='contacts')return;
 const input=$('contact-search-input'), results=$('contact-search-results');
 if(!input||!results)return;
 const q=term.trim();state.contactQuery=q;
 if(q.length<1){results.innerHTML=renderUserSearchResults([],q);return}
 const current=Symbol();state.contactRequest=current;
 const result=await api('/api/contacts?q='+encodeURIComponent(q)+'&status_filter='+encodeURIComponent(state.contactFilter||'all'));
 if(state.contactRequest!==current||input.value.trim()!==q)return;
 results.innerHTML=renderUserSearchResults(result.search,q);
}
async function showContacts(q=state.contactQuery||'',statusFilter=state.contactFilter||'all'){
 const query=String(q||'').trim();state.contactQuery=query;state.contactFilter=statusFilter;
 const result=await api('/api/contacts?q='+encodeURIComponent(query)+'&status_filter='+encodeURIComponent(statusFilter));
 const inbox=result.items.filter(x=>x.direction==='incoming'&&x.status==='pending');
 const others=[...new Map(result.items.filter(x=>x.status==='accepted'&&x.connected).map(x=>[x.person.id,x])).values()];
 const outgoing=result.items.filter(x=>x.direction==='outgoing'&&x.status==='pending');
 const blocked=result.blocked||[];
 $('view').innerHTML=`${pageHead('Kontak antarperangkat','Cari akun CHRYA BOX berdasarkan username atau nama lengkap, kelola undangan, blokir, dan filter status.',`<div class="inline-buttons"><select id="contact-status-filter" style="min-height:36px;padding:6px 10px"><option value="all" ${statusFilter==='all'?'selected':''}>Semua Status</option><option value="accepted" ${statusFilter==='accepted'?'selected':''}>Accepted</option><option value="pending" ${statusFilter==='pending'?'selected':''}>Pending</option><option value="rejected" ${statusFilter==='rejected'?'selected':''}>Rejected</option><option value="blocked" ${statusFilter==='blocked'?'selected':''}>Blocked</option></select><button class="btn btn-muted btn-small" data-refresh-contacts>↻ Refresh</button></div>`)}
 <div class="contact-steps"><span><b>1</b> Cari username/nama</span><span>→</span><span><b>2</b> Kirim undangan</span><span>→</span><span><b>3</b> Disetujui</span><span>→</span><span><b>4</b> Kirim pesan</span></div>
 <div class="dashboard-grid contacts-grid"><section class="card"><div class="card-title"><h2>Temukan pengguna</h2><span class="tag">Satu database</span></div>
 <form id="contact-search" class="form-stack contact-find" style="margin:13px 0"><label>Username atau nama lengkap<input id="contact-search-input" name="q" autocomplete="off" placeholder="Contoh: @temanku atau Nama Lengkap" value="${escapeHtml(query)}" aria-label="Cari username kontak"></label><button class="btn btn-primary" type="submit">Cari pengguna →</button></form>
 <div id="contact-search-results" aria-live="polite">${renderUserSearchResults(result.search,query)}</div>
 <p class="small-note">Pencarian langsung berdasarkan username maupun nama lengkap pada satu server CHRYA BOX.</p>
 </section><section class="card"><div class="card-title"><h2>Undangan masuk</h2><span class="tag ${inbox.length?'warn':''}">${inbox.length} pending</span></div>
 ${inbox.length?inbox.map(x=>`<div class="data-row"><div class="row-content"><strong>${escapeHtml(x.person.full_name)}</strong><small>@${escapeHtml(x.person.username)}</small></div><div class="inline-buttons"><button class="btn btn-primary btn-small" data-respond="accept:${x.id}">Terima</button><button class="btn btn-muted btn-small" data-respond="reject:${x.id}">Tolak</button><button class="btn btn-danger btn-small" data-respond="block:${x.id}">Blokir</button></div></div>`).join(''):empty('Belum ada undangan masuk','Minta temanmu mencari username-mu dan mengirim undangan.')}
 ${outgoing.length?`<h2 style="margin-top:24px">Undangan keluar (${outgoing.length})</h2>${outgoing.map(x=>`<div class="data-row"><div class="row-content"><strong>${escapeHtml(x.person.full_name)} (@${escapeHtml(x.person.username)})</strong><small>Menunggu persetujuan</small></div><div class="inline-buttons">${tag('pending')}<button class="btn btn-danger btn-small" data-cancel-invite="${x.id}">Batalkan</button></div></div>`).join('')}`:''}
 </section></div>
 <section class="card" style="margin-top:15px"><div class="card-title"><h2>Kontak terhubung</h2><span class="tag">${others.length} connected</span></div>
 ${others.length?others.map(x=>`<div class="data-row"><div class="row-icon">♧</div><div class="row-content"><strong>${escapeHtml(x.person.full_name)}</strong><small>@${escapeHtml(x.person.username)}</small></div><div class="panel-actions"><button class="btn btn-primary btn-small" data-compose-to="${escapeHtml(x.person.username)}">✉ Kirim pesan</button><button class="btn btn-muted btn-small" data-remove-contact="${x.person.id}">Hapus Kontak</button><button class="btn btn-danger btn-small" data-block="${x.person.id}">Blokir</button></div></div>`).join(''):empty('Belum ada kontak terhubung','Cari username teman lalu kirim permintaan kontak. Setelah diterima, kamu dapat mengirim pesan.')}</section>
 ${blocked.length?`<section class="card" style="margin-top:15px"><div class="card-title"><h2>Pengguna diblokir</h2><span class="tag danger">${blocked.length} blocked</span></div>${blocked.map(b=>`<div class="data-row"><div class="row-content"><strong>${escapeHtml(b.person.full_name)}</strong><small>@${escapeHtml(b.person.username)}</small></div><button class="btn btn-muted btn-small" data-unblock="${b.user_id}">Buka Blokir (Unblock)</button></div>`).join('')}</section>`:''}`;
 const filterEl=$('contact-status-filter');
 if(filterEl)filterEl.onchange=safeRun(()=>showContacts(state.contactQuery,filterEl.value));
}

async function showVault(){
 const res=await api('/api/notes?q='+encodeURIComponent(state.noteQuery||'')+'&category='+encodeURIComponent(state.noteCategory||''));
 const edit=state.editingNote;
 const categories=['Umum','Pribadi','Kredensial','Pekerjaan','Akademik'];
 $('view').innerHTML=`${pageHead('My private vault','Catatan pribadi terenkripsi (Vigenère + AES-256-GCM) yang hanya dapat diakses pemilik akun.')}
 <div class="dashboard-grid">
   <section class="card">
     <h2>${edit?'Edit secret note':'Add secret note'}</h2>
     <form id="note-form" class="form-stack" style="margin-top:17px">
       <input type="hidden" name="note_id" value="${edit?edit.id:''}">
       <label>Judul<input name="title" required maxlength="100" value="${escapeHtml(edit?edit.title:'')}" placeholder="Judul catatan"></label>
       <label>Kategori<select name="category">${categories.map(c=>`<option value="${c}" ${(edit?.category||'Umum')===c?'selected':''}>${c}</option>`).join('')}</select></label>
       <label>Isi catatan<textarea name="body" required rows="5" placeholder="Catatan rahasia...">${escapeHtml(edit?edit.body:'')}</textarea></label>
       <div class="inline-buttons">
         <button type="submit" class="btn btn-primary">${edit?'Perbarui catatan ▣':'Simpan di brankas ▣'}</button>
         ${edit?`<button type="button" class="btn btn-muted" data-cancel-edit-note>Batal Edit</button>`:''}
       </div>
     </form>
   </section>
   <section class="card">
     <div class="card-title" style="flex-wrap:wrap;gap:8px">
       <h2>Your encrypted notes <span class="tag">${res.items.length}</span></h2>
       <form id="note-search-form" class="inline-buttons">
         <input name="q" value="${escapeHtml(state.noteQuery||'')}" placeholder="Cari catatan..." style="min-height:34px;padding:5px 10px;width:150px">
         <select name="category" style="min-height:34px;padding:5px 8px;width:120px"><option value="">Semua Kategori</option>${categories.map(c=>`<option value="${c}" ${state.noteCategory===c?'selected':''}>${c}</option>`).join('')}</select>
         <button class="btn btn-muted btn-small" type="submit">Filter</button>
       </form>
     </div>
     <div class="activity-list">${res.items.length?res.items.map(n=>`<div class="note-card" style="margin-bottom:10px"><div class="control-line"><b>${escapeHtml(n.title)}</b><span class="tag muted">${escapeHtml(n.category||'Umum')}</span></div><p>${escapeHtml(n.body)}</p><div class="control-line"><small class="small-note">${dateFmt(n.updated_at||n.created_at)}</small><div class="inline-buttons"><button class="link-button" data-edit-note="${n.id}" data-note-title="${escapeHtml(n.title)}" data-note-body="${escapeHtml(n.body)}" data-note-cat="${escapeHtml(n.category||'Umum')}">Edit</button><button class="link-button" style="color:#ff9da5" data-delete-note="${n.id}">Hapus</button></div></div></div>`).join(''):empty('Belum ada catatan pribadi')}</div>
   </section>
 </div>`;
}

async function showFiles(){
 const [res,contacts]=await Promise.all([
   api('/api/files?q='+encodeURIComponent(state.fileQuery||'')+'&category='+encodeURIComponent(state.fileCategory||'')),
   api('/api/contacts')
 ]);
 const unique=[...new Map(contacts.items.filter(x=>x.status==='accepted'&&x.connected).map(x=>[x.person.id,x.person])).values()];
 const fileCats=['Dokumen','Gambar','Spreadsheet','Arsip','Rahasia'];
 $('view').innerHTML=`${pageHead('Secure file vault','Enkripsi dokumen menggunakan ChaCha20-Poly1305 dengan kunci file unik yang dibungkus AES-256-GCM.')}
 <div class="dashboard-grid">
   <section class="card">
     <h2>Upload encrypted file</h2>
     <form id="file-form" class="form-stack" style="margin-top:17px">
       <label>Dokumen (PDF, DOCX, XLSX, PNG, JPG, ZIP, TXT, CSV, PPTX — maks. 6 MB)<input type="file" name="file" required></label>
       <label>Kategori file<select name="category"><option value="">Otomatis sesuai tipe</option>${fileCats.map(c=>`<option value="${c}">${c}</option>`).join('')}</select></label>
       <label>Bagikan ke kontak (opsional)<select name="recipient"><option value="">Simpan di brankas saya saja</option>${unique.map(x=>`<option value="${escapeHtml(x.username)}">${escapeHtml(x.full_name)} (@${escapeHtml(x.username)})</option>`).join('')}</select></label>
       <button type="submit" class="btn btn-primary">Enkripsi & simpan ▤</button>
     </form>
     <p class="small-note">Server hanya menyimpan ciphertext di folder instance/storage. Anda dapat melakukan preview, membagikan ulang, mencabut akses penerima, atau menghapus file kapan saja.</p>
   </section>
   <section class="card">
     <div class="card-title" style="flex-wrap:wrap;gap:8px">
       <h2>Stored files <span class="tag">${res.items.length}</span></h2>
       <form id="file-search-form" class="inline-buttons">
         <input name="q" value="${escapeHtml(state.fileQuery||'')}" placeholder="Cari nama file..." style="min-height:34px;padding:5px 10px;width:150px">
         <select name="category" style="min-height:34px;padding:5px 8px;width:130px"><option value="">Semua Kategori</option>${fileCats.map(c=>`<option value="${c}" ${state.fileCategory===c?'selected':''}>${c}</option>`).join('')}</select>
         <button class="btn btn-muted btn-small" type="submit">Cari</button>
       </form>
     </div>
     ${res.items.length?res.items.map(f=>{
       const isOwner=f.owner_id===state.me.id;
       const shareInfo=f.receiver_id?`Dibagikan ke @${escapeHtml(f.receiver_username)}`:'Pribadi';
       return `<div class="data-row" style="flex-wrap:wrap"><div class="row-icon">▤</div><div class="row-content"><strong>${escapeHtml(f.filename)}</strong><small>${escapeHtml(f.category||'Dokumen')} · ${(f.size_bytes/1024).toFixed(1)} KB · ${shareInfo} · ${dateFmt(f.created_at)}</small></div><div class="inline-buttons"><button class="btn btn-muted btn-small" data-preview-file="${f.id}">Preview</button><button class="btn btn-primary btn-small" data-download="${f.id}">Download</button>${isOwner&&f.receiver_id?`<button class="btn btn-muted btn-small" data-revoke-file="${f.id}">Cabut Akses</button>`:''}${isOwner&&unique.length?`<button class="btn btn-muted btn-small" data-share-file="${f.id}">Bagikan</button>`:''}${isOwner?`<button class="btn btn-danger btn-small" data-delete-file="${f.id}">Hapus</button>`:''}</div></div>`;
     }).join(''):empty('Belum ada file rahasia')}
     <div id="file-preview-box" class="response-view hidden" style="margin-top:16px"></div>
   </section>
 </div>`;
}

async function showStego(){$('view').innerHTML=`${pageHead('Image steganography','Sembunyikan ciphertext ke kanal piksel gambar menggunakan Least Significant Bit (LSB).')}<div class="dashboard-grid"><section class="card"><h2>Hide secret inside an image</h2><form id="stego-embed-form" class="form-stack" style="margin-top:16px"><label>Gambar sumber<input type="file" name="image" accept="image/*" required></label><label>Pesan rahasia<textarea name="secret" rows="4" minlength="1" maxlength="1000" required placeholder="Tulis pesan yang akan disembunyikan"></textarea></label><button class="btn btn-primary" type="submit">Embed & download PNG →</button></form></section><section class="card"><h2>Extract secret from image</h2><form id="stego-extract-form" class="form-stack" style="margin-top:16px"><label>Gambar stego PNG<input type="file" name="image" accept="image/png" required></label><button type="submit" class="btn btn-muted">Extract secret ↗</button></form><div class="response-view hidden" id="stego-result"></div></section></div><div class="card" style="margin-top:16px"><h2>How it works</h2><p class="small-note">Plaintext → Vigenère + AES-GCM (HKDF STEGO key) → ciphertext → LSB RGB → file PNG. Dekripsi dilakukan setelah ekstraksi. Jangan mengompres file stego menjadi JPEG karena pesan tersembunyi dapat rusak.</p></div>`}

async function showLedger(){
 const res=await api('/api/ledger');
 const cps=res.checkpoints||[];
 $('view').innerHTML=`${pageHead('Audit Hash Chain Ledger','Buku besar audit keamanan berbasis rantai hash SHA-256, pohon Merkle, dan tanda tangan digital Ed25519 untuk mendeteksi manipulasi data.',`<div class="inline-buttons"><span class="tag ${res.valid?'':'danger'}">${res.valid?'✓ Integrity verified':'✕ Tampering detected'}</span><button class="btn btn-primary btn-small" data-create-checkpoint>✍ Sign Checkpoint & Anchor</button><button class="btn btn-muted btn-small" data-export-ledger>⬇ Backup Audit Log</button></div>`)}
 <section class="card" style="margin-bottom:15px">
   <h2>Apa Fungsi Audit Hash Chain Ledger Ini?</h2>
   <p class="small-note" style="margin-top:6px;line-height:1.6">
     Fitur ini adalah <b>buku catatan keamanan anti-manipulasi (tamper-evident audit log)</b> yang merekam setiap kejadian penting di CHRYA BOX (registrasi akun, login, kirim pesan, enkripsi/dekripsi file, steganografi, dan rotasi kunci):<br>
     • <b>1. Rantai Hash Berantai (Previous Hash → Current Hash):</b> Setiap aktivitas (Blok #0, #1, #2, dst.) mengunci hash dari blok sebelumnya. Jika seseorang mengedit atau menghapus 1 baris saja langsung di database SQLite/MySQL, nilai hash blok tersebut berubah dan memutus rantai blok setelahnya sehingga status langsung berubah menjadi <b style="color:#ff9da5">TAMPERED / RUSAK</b>.<br>
     • <b>2. SHA-256 Merkle Root:</b> Ringkasan kriptografi tunggal yang mewakili seluruh blok dari #0 sampai blok terakhir.<br>
     • <b>3. Sign Checkpoint (Ed25519) &amp; External Anchor:</b> Saat tombol <b>Sign Checkpoint &amp; Anchor</b> ditekan, server menandatangani Merkle Root dengan kunci privat <b>Ed25519</b> dan menyimpan file bukti eksternal di <code>instance/anchors/</code>. Dengan begitu, penyerang yang mengubah database tidak bisa menghitung ulang rantai hash palsu tanpa terdeteksi.
   </p>
 </section>
 <div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">
   <div class="stat-card"><div class="stat-head">Status Integritas Rantai</div><div class="stat-number" style="font-size:20px;color:${res.valid?'#5ee7c7':'#ff9da5'}">${res.valid?'VALID (UTUH)':'TAMPERED / RUSAK'}</div><div class="stat-trend">${escapeHtml(res.reason||'')}</div></div>
   <div class="stat-card"><div class="stat-head">SHA-256 Merkle Root</div><div class="mono" style="margin-top:12px">${escapeHtml(res.merkle_root||'0')}</div><div class="stat-trend">${res.total} total blok tercatat</div></div>
   <div class="stat-card"><div class="stat-head">Signed Checkpoints (Ed25519)</div><div class="stat-number">${cps.length}</div><div class="stat-trend">External anchor di instance/anchors/</div></div>
 </div>
 ${cps.length?`<section class="card" style="margin-bottom:15px"><div class="card-title"><h2>Checkpoints Tertandatangani (Ed25519) & External Anchors</h2></div><div class="table-wrap"><table><thead><tr><th>Blok</th><th>Merkle Root</th><th>Signature (Ed25519)</th><th>Anchor File</th><th>Status</th></tr></thead><tbody>${cps.map(c=>`<tr><td>#0..#${c.up_to_index}</td><td class="mono">${escapeHtml(c.merkle_root.slice(0,20))}…</td><td class="mono">${escapeHtml(c.signature.slice(0,24))}…</td><td>${escapeHtml(c.anchor_path)}</td><td><span class="tag ${c.valid?'':'danger'}">${c.valid?'✓ Valid':'✕ Invalid'}</span></td></tr>`).join('')}</tbody></table></div></section>`:''}
 <section class="card"><div class="card-title"><h2>Immutable-style audit trail</h2><span class="tag muted">${res.total} blocks</span></div><div class="table-wrap"><table><thead><tr><th>Block</th><th>Timestamp</th><th>Actor</th><th>Action</th><th>Resource</th><th>Previous Hash</th><th>Current Hash</th></tr></thead><tbody>${res.items.map(x=>`<tr><td>#${x.index}</td><td>${escapeHtml(x.ts)}</td><td>User #${x.actor}</td><td>${escapeHtml(x.action)}</td><td>${escapeHtml(x.resource)}</td><td class="mono">${escapeHtml(x.previous_hash.slice(0,16))}...</td><td class="mono">${escapeHtml(x.hash.slice(0,20))}...</td></tr>`).join('')}</tbody></table></div>${res.items.length?'':empty('Belum ada aktivitas')}</section>`;
}

async function showNotifications(){
 const res=await api('/api/notifications?unread_only='+(state.notifUnreadOnly?'true':'false'));
 $('view').innerHTML=`${pageHead('Notifications','Pemberitahuan undangan kontak, pesan baru, file masuk, dan pengiriman email SMTP.',`<div class="inline-buttons"><button class="btn ${state.notifUnreadOnly?'btn-primary':'btn-muted'} btn-small" data-toggle-unread-notif>${state.notifUnreadOnly?'Menampilkan: Belum Dibaca':'Filter: Belum Dibaca ('+(res.unread_count||0)+')'}</button><button class="btn btn-muted btn-small" data-read-all-notif>✓ Tandai Semua Dibaca</button></div>`)}
 <div class="dashboard-grid">
   <section class="card"><div class="card-title"><h2>In-app notifications</h2><span class="tag ${res.unread_count?'warn':''}">${res.unread_count||0} unread</span></div>
   ${res.items.length?res.items.map(x=>`<div class="data-row"><div class="row-icon">${x.category==='message'?'✉':x.category==='file'?'▤':x.category==='contact'?'♧':'♢'}</div><div class="row-content"><strong>${x.read?'':'● '}${escapeHtml(x.text)}</strong><small>${escapeHtml(x.category)} · ${dateFmt(x.created_at)}</small></div><div class="inline-buttons">${x.message_id?`<button class="btn btn-primary btn-small" data-open-message="${x.message_id}">Buka</button>`:''}${!x.read?`<button class="btn btn-muted btn-small" data-read-notif="${x.id}">Dibaca</button>`:''}<button class="btn btn-danger btn-small" data-delete-notif="${x.id}">✕</button></div></div>`).join(''):empty('Tidak ada notifikasi')}
   </section>
   <section class="card"><h2>SMTP email log</h2>${res.email_logs.length?res.email_logs.map(x=>`<div class="data-row"><div class="row-content"><strong>${escapeHtml(x.recipient)}</strong><small>Attempts: ${x.attempts}${x.error?' · '+escapeHtml(x.error):''}</small></div><div class="inline-buttons">${tag(x.status)}${x.status!=='sent'&&x.attempts<3?`<button class="link-button" data-retry-email="${x.id}">Retry</button>`:''}</div></div>`).join(''):empty('Belum ada email keluar','Konfigurasi SMTP di .env diperlukan untuk mengirim email sungguhan.')}</section>
 </div>`;
}

async function showSecurity(){
 const [status,me,overview]=await Promise.all([api('/api/status'),api('/api/me'),api('/api/security/overview')]);
 $('view').innerHTML=`${pageHead('Security center','Pusat kendali autentikasi 3 lapis (Password, USB Key, Face Unlock SFace 128-D), perangkat aktif, rotasi kunci, dan pemulihan akun.')}
 <div class="dashboard-grid">
   <section class="card">
     <h2>Authentication factors &amp; Key Separation</h2>
     <div class="data-row"><div class="row-icon">⌑</div><div class="row-content"><strong>Password hashing</strong><small>Argon2id — memory-hard</small></div><span class="tag">Enabled</span></div>
     <div class="data-row"><div class="row-icon">▣</div><div class="row-content"><strong>USB flashdisk key</strong><small>HMAC-SHA256 + Volume Serial (${escapeHtml(status.volume_serial||'Host')})</small></div><span class="tag ${status.authorized?'':'danger'}">${status.authorized?'Connected':'Missing'}</span></div>
     <div class="data-row"><div class="row-icon">📷</div><div class="row-content"><strong>Face Embedding (YuNet + SFace 128-D)</strong><small>1 Wajah 1 Akun · Anti-spoofing + AES-256-GCM template</small></div><span class="tag">${me.face_enrolled?'Terdaftar ('+escapeHtml(me.face_model||'SFace')+')':'Belum terdaftar'}</span></div>
     <div class="data-row"><div class="row-icon">🔑</div><div class="row-content"><strong>HKDF Domain Key Separation</strong><small>Versi Kunci Aktif: v${overview.key_management.current_kid} (${overview.key_management.domains.length} domain terpisah)</small></div><span class="tag">Active</span></div>

     <h2 style="margin-top:22px">Ganti Password</h2>
     <form id="change-password-form" class="form-stack" style="margin-top:10px">
       <label>Password saat ini<input type="password" name="current_password" required></label>
       <label>Password baru (minimal 12 karakter)<input type="password" name="new_password" required minlength="12"></label>
       <button type="submit" class="btn btn-primary btn-small">Simpan Password Baru</button>
     </form>

     <h2 style="margin-top:22px">Pemulihan Akun &amp; Backup Kriptografi</h2>
     <p class="small-note">Recovery code tersisa: <b>${overview.recovery_codes_remaining}</b> kode. Gunakan jika USB hilang/rusak atau wajah gagal dikenali.</p>
     <div class="inline-buttons" style="margin-top:8px">
       <button class="btn btn-muted btn-small" data-generate-recovery>Buat 6 Recovery Code Baru</button>
       <button class="btn btn-muted btn-small" data-rotate-key>↻ Rotasi Encryption Key</button>
       <button class="btn btn-muted btn-small" data-backup-db>⬇ Backup Database</button>
     </div>
     <div id="recovery-codes-display" class="response-view hidden" style="margin-top:10px"></div>
     <form id="backup-master-form" class="inline-buttons" style="margin-top:10px">
       <input type="password" name="passphrase" required minlength="10" placeholder="Passphrase backup master key (min 10 kar)" style="flex:1;min-height:36px;padding:6px 10px">
       <button type="submit" class="btn btn-outline btn-small">⬇ Backup Master Key</button>
     </form>
   </section>

   <section class="card">
     <h2>Biometrik Wajah &amp; USB Key Management</h2>
     <p class="small-note">Akun: <b>${escapeHtml(state.me.username)}</b> (${escapeHtml(state.me.email)}) · Origin: <b>${escapeHtml(status.origin)}</b></p>
     <div class="biometric-manage">
       <strong>Pengaturan Ulang Biometrik Wajah (SFace 128-D · 1 Wajah 1 Akun)</strong>
       <p>Anda dapat memperbarui atau menghapus template wajah terenkripsi Anda kapan saja.</p>
       <div class="inline-buttons">
         <button class="btn btn-primary btn-small" data-enroll-camera>📷 Daftarkan / Perbarui Wajah Kamera</button>
         ${me.face_enrolled?`<button class="btn btn-danger btn-small" data-delete-face>✕ Hapus Template Wajah</button>`:''}
       </div>
     </div>
     <div class="biometric-manage">
       <strong>USB Vault Key Management (Registrasi Ulang &amp; Pencabutan USB Lama)</strong>
       <p>Buat kunci USB baru atau cabut USB lama yang hilang/rusak. Token USB lama yang dicabut akan ditolak server.</p>
       <div class="inline-buttons">
         <button class="btn btn-primary btn-small" data-issue-usb>＋ Registrasi Ulang / Buat USB Key Baru</button>
         <button class="btn btn-muted btn-small" data-rotate-host-usb>↻ Rotasi USB Dongle Server</button>
       </div>
       ${overview.usb_keys.map(uk=>`<div class="data-row" style="padding:8px 0"><div class="row-content"><strong>${escapeHtml(uk.label)} (${escapeHtml(uk.key_id)})</strong><small>Serial: ${escapeHtml(uk.volume_serial||'N/A')} · ${dateFmt(uk.created_at)}</small></div><div class="inline-buttons">${tag(uk.status)}${uk.status==='active'?`<button class="btn btn-danger btn-small" data-revoke-usb="${uk.id}:revoked">Cabut</button><button class="btn btn-danger btn-small" data-revoke-usb="${uk.id}:lost">Hilang</button>`:''}</div></div>`).join('')}
     </div>
   </section>
 </div>
 <div class="dashboard-grid" style="margin-top:15px">
   <section class="card">
     <div class="card-title"><h2>Perangkat yang Sedang Login (${overview.active_sessions.length})</h2><button class="btn btn-danger btn-small" data-logout-all-devices>Logout Semua Perangkat</button></div>
     ${overview.active_sessions.map(s=>`<div class="data-row"><div class="row-icon">💻</div><div class="row-content"><strong>${escapeHtml(s.device_name)} ${s.is_current?'(Perangkat Ini)':''}</strong><small>IP: ${escapeHtml(s.ip_address)} · Aktif: ${dateFmt(s.last_active)}</small></div>${!s.is_current?`<button class="btn btn-danger btn-small" data-revoke-session="${escapeHtml(s.session_id)}">Putuskan</button>`:`<span class="tag">Current</span>`}</div>`).join('')}
   </section>
   <section class="card">
     <div class="card-title"><h2>Riwayat Aktivitas Login &amp; Deteksi Mencurigakan</h2></div>
     <div class="activity-list" style="max-height:300px">
       ${overview.login_history.length?overview.login_history.map(h=>`<div class="data-row"><div class="row-content"><strong>${escapeHtml(h.device_name||'Browser')} · ${escapeHtml(h.method)}</strong><small>IP: ${escapeHtml(h.ip_address)} · ${dateFmt(h.created_at)}${h.reason?' · '+escapeHtml(h.reason):''}</small></div><div class="inline-buttons">${h.suspicious?'<span class="tag danger">⚠ Mencurigakan</span>':''}${tag(h.status)}</div></div>`).join(''):empty('Belum ada riwayat login')}
     </div>
   </section>
 </div>`;
}

async function enrollExtraBiometric(){
 if(!window.PublicKeyCredential||!navigator.credentials)throw Error('Browser belum mendukung WebAuthn. Gunakan HTTPS atau localhost.');
 const data=await api('/api/security/passkey/options',{method:'POST',body:{}});
 const credential=await createOrGetCredential(data);
 const result=await api('/api/security/passkey/verify',{method:'POST',body:{flow:data.flow,credential}});
 toast(result.message||'Biometrik berhasil didaftarkan.');
 await showSecurity();
}
function downloadBlob(blob,name){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000)}

async function installEvents(){
 $('open-login').onclick=()=>authOpen('login');$('open-register').onclick=()=>authOpen('register');$('learn-btn').onclick=()=>$('features').scrollIntoView({behavior:'smooth'});$('auth-close').onclick=authClose;$('auth-shade').onclick=authClose;
 document.querySelectorAll('[data-auth-tab]').forEach(x=>x.onclick=()=>setAuthTab(x.dataset.authTab));
 $('login-form').addEventListener('submit',safeRun(formLogin));
 $('register-form').addEventListener('submit',safeRun(formRegister));
 if($('recover-form'))$('recover-form').addEventListener('submit',safeRun(formRecover));
 if($('go-recover-account'))$('go-recover-account').onclick=()=>setAuthTab('recover');
 if($('cancel-recover'))$('cancel-recover').onclick=()=>setAuthTab('login');
 $('register-username').addEventListener('input',()=>scheduleUsernameCheck());$('register-username').addEventListener('blur',()=>scheduleUsernameCheck(0));$('go-register-face').onclick=()=>setAuthTab('register');$('go-login-after-face').onclick=()=>setAuthTab('login');
 $('usb-verify-btn').onclick=safeRun(verifyUSB);$('passkey-verify-btn').onclick=safeRun(biometricVerify);
 $('face-open-btn').onclick=safeRun(()=>openFaceCamera('auth'));
 $('face-capture-one').onclick=safeRun(captureFaceOnce);
 $('face-cancel').onclick=cancelFaceCamera;
 $('menu-toggle').onclick=()=>{$('sidebar').classList.toggle('open');$('mobile-scrim').classList.toggle('hidden')};$('mobile-scrim').onclick=()=>{$('sidebar').classList.remove('open');$('mobile-scrim').classList.add('hidden')};$('more-mobile').onclick=$('menu-toggle').onclick;
 $('notif-shortcut').onclick=safeRun(()=>navigate('notifications'));
 $('logout').onclick=safeRun(async()=>{await api('/api/auth/logout',{method:'POST',body:{}});state.me=null;state.csrf='';$('workspace').classList.add('hidden');$('public').classList.remove('hidden');toast('Anda berhasil keluar.');});

 document.body.addEventListener('click',safeRun(async(e)=>{
    const a=e.target.closest('button,[data-open-message]');if(!a)return;
    if(a.hasAttribute('data-enroll-passkey')){await enrollExtraBiometric();return}
    if(a.hasAttribute('data-enroll-camera')){const pw=prompt('Konfirmasi password akun Anda (opsional jika baru saja login):')||'';await openFaceCamera('security',pw);return}
    if(a.hasAttribute('data-delete-face')){const pw=prompt('Konfirmasi password untuk menghapus template wajah:')||'';await api('/api/security/face',{method:'DELETE',body:{password:pw}});toast('Template wajah dihapus.');await showSecurity();return}
    if(a.hasAttribute('data-refresh-contacts')){await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.view){if(a.dataset.view==='compose')state.reply=null;await navigate(a.dataset.view);return}
    if(a.dataset.msgBox){await showMessages(a.dataset.msgBox,state.msgQuery);return}
    if(a.hasAttribute('data-clear-msg-search')){await showMessages(state.msgBox,'');return}
    if(a.dataset.openMessage){await openMessage(Number(a.dataset.openMessage));return}
    if(a.dataset.invite){await api('/api/contacts/request',{method:'POST',body:{username:a.dataset.invite}});toast('Undangan dikirim. Tunggu temanmu menyetujuinya.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.respond){const [action,id]=a.dataset.respond.split(':');await api('/api/contacts/respond',{method:'POST',body:{action,id:Number(id)}});toast('Undangan diperbarui.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.cancelInvite){await api('/api/contacts/cancel',{method:'POST',body:{id:Number(a.dataset.cancelInvite)}});toast('Undangan dibatalkan.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.removeContact){if(!confirm('Hapus kontak ini dari daftar koneksi?'))return;await api('/api/contacts/'+a.dataset.removeContact,{method:'DELETE'});toast('Kontak dihapus.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.block){if(!confirm('Blokir kontak? Komunikasi tidak akan diizinkan.'))return;await api('/api/contacts/block',{method:'POST',body:{user_id:Number(a.dataset.block)}});toast('Kontak diblokir.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.unblock){await api('/api/contacts/unblock',{method:'POST',body:{user_id:Number(a.dataset.unblock)}});toast('Blokir pengguna dibuka.');await showContacts(state.contactQuery,state.contactFilter);return}
    if(a.dataset.composeTo){state.reply={recipient:a.dataset.composeTo};await navigate('compose');return}
    if(a.dataset.editNote){state.editingNote={id:Number(a.dataset.editNote),title:a.dataset.noteTitle,body:a.dataset.noteBody,category:a.dataset.noteCat};await showVault();return}
    if(a.hasAttribute('data-cancel-edit-note')){state.editingNote=null;await showVault();return}
    if(a.dataset.deleteNote){if(!confirm('Hapus catatan?'))return;await api('/api/notes/'+a.dataset.deleteNote,{method:'DELETE'});state.editingNote=null;toast('Catatan dihapus.');await showVault();return}
    if(a.dataset.archive){await api('/api/messages/'+a.dataset.archive+'/archive',{method:'POST',body:{}});toast('Pesan diarsipkan.');await showMessages('inbox');return}
    if(a.dataset.unarchive){await api('/api/messages/'+a.dataset.unarchive+'/unarchive',{method:'POST',body:{}});toast('Pesan dikembalikan ke Inbox.');await showMessages('inbox');return}
    if(a.dataset.pinMsg){const r=await api('/api/messages/'+a.dataset.pinMsg+'/pin',{method:'POST',body:{}});toast(r.pinned?'Pesan di-pin.':'Pin dilepas.');await openMessage(Number(a.dataset.pinMsg));return}
    if(a.dataset.deleteMsg){if(!confirm('Hapus pesan ini?'))return;await api('/api/messages/'+a.dataset.deleteMsg,{method:'DELETE'});toast('Pesan dihapus.');await showMessages(state.msgBox);return}
    if(a.dataset.deleteConv){if(!confirm('Hapus seluruh percakapan dengan @'+a.dataset.deleteConv+'?'))return;await api('/api/conversations/'+encodeURIComponent(a.dataset.deleteConv),{method:'DELETE'});toast('Percakapan dihapus.');await showMessages(state.msgBox);return}
    if(a.dataset.download){const id=a.dataset.download;const response=await api('/api/files/'+id+'/download',{download:true});let name='chrya_file';const m=response.filename.match(/filename\*=UTF-8''([^;]+)/);if(m)name=decodeURIComponent(m[1]);downloadBlob(response.blob,name);toast('File didekripsi dan diunduh.');return}
    if(a.dataset.previewFile){
      const fid=a.dataset.previewFile;
      const p=await api('/api/files/'+fid+'/preview');
      const box=$('file-preview-box');if(!box)return;box.classList.remove('hidden');
      const inlineUrl=p.inline_url||('/api/files/'+fid+'/inline');
      const headerHtml=`<div class="control-line" style="margin-bottom:10px;flex-wrap:wrap;gap:8px"><h3>Preview: ${escapeHtml(p.filename)}</h3><div class="inline-buttons"><a class="btn btn-primary btn-small" href="${escapeHtml(inlineUrl)}" target="_blank" rel="noopener">↗ Buka Layar Penuh</a><button class="btn btn-muted btn-small" type="button" data-close-preview>✕ Tutup</button></div></div>`;
      if(p.kind==='image')box.innerHTML=headerHtml+`<img src="${p.data_uri||inlineUrl}" alt="${escapeHtml(p.filename)}" style="max-width:100%;max-height:420px;border-radius:10px;margin-top:4px">`;
      else if(p.kind==='pdf')box.innerHTML=headerHtml+`<iframe src="${escapeHtml(inlineUrl)}" style="width:100%;height:500px;border:1px solid #30425b;border-radius:10px;background:#fff" title="${escapeHtml(p.filename)}"></iframe>`;
      else box.innerHTML=headerHtml+`<pre style="white-space:pre-wrap;word-break:break-word;max-height:380px;overflow:auto;background:#091324;padding:14px;border-radius:10px;border:1px solid #263852;color:#dbeafe;font-size:13px;line-height:1.55">${escapeHtml(p.content||'')}</pre>`;
      box.scrollIntoView({behavior:'smooth',block:'nearest'});
      return;
    }
    if(a.hasAttribute('data-close-preview')){const box=$('file-preview-box');if(box){box.classList.add('hidden');box.innerHTML='';}return}
    if(a.dataset.shareFile){const rec=prompt('Masukkan username kontak tujuan berbagi file:');if(!rec)return;const r=await api('/api/files/'+a.dataset.shareFile+'/share',{method:'POST',body:{recipient:rec}});toast(r.message);await showFiles();return}
    if(a.dataset.revokeFile){await api('/api/files/'+a.dataset.revokeFile+'/revoke',{method:'POST',body:{}});toast('Akses file telah dicabut.');await showFiles();return}
    if(a.dataset.deleteFile){if(!confirm('Hapus file terenkripsi ini secara permanen?'))return;await api('/api/files/'+a.dataset.deleteFile,{method:'DELETE'});toast('File dihapus.');await showFiles();return}
    if(a.hasAttribute('data-toggle-unread-notif')){state.notifUnreadOnly=!state.notifUnreadOnly;await showNotifications();return}
    if(a.hasAttribute('data-read-all-notif')){await api('/api/notifications/read-all',{method:'POST',body:{}});toast('Semua notifikasi ditandai telah dibaca.');await showNotifications();return}
    if(a.dataset.readNotif){await api('/api/notifications/'+a.dataset.readNotif+'/read',{method:'POST',body:{}});await showNotifications();return}
    if(a.dataset.deleteNotif){await api('/api/notifications/'+a.dataset.deleteNotif,{method:'DELETE'});toast('Notifikasi dihapus.');await showNotifications();return}
    if(a.dataset.retryEmail){await api('/api/notifications/email/'+a.dataset.retryEmail+'/retry',{method:'POST',body:{}});toast('Pengiriman ulang email dimulai.');await showNotifications();return}
    if(a.hasAttribute('data-create-checkpoint')){const r=await api('/api/ledger/checkpoint',{method:'POST',body:{}});toast(r.message);await showLedger();return}
    if(a.hasAttribute('data-export-ledger')){const r=await api('/api/ledger/export',{download:true});downloadBlob(r.blob,'chrya_ledger_backup.json');toast('Backup audit log diunduh.');return}
    if(a.hasAttribute('data-logout-all-devices')){if(!confirm('Keluar dari seluruh perangkat yang sedang login?'))return;await api('/api/security/sessions/logout-all',{method:'POST',body:{}});state.me=null;state.csrf='';$('workspace').classList.add('hidden');$('public').classList.remove('hidden');toast('Seluruh perangkat telah dikeluarkan.');return}
    if(a.dataset.revokeSession){await api('/api/security/sessions/'+encodeURIComponent(a.dataset.revokeSession),{method:'DELETE'});toast('Sesi perangkat dihentikan.');await showSecurity();return}
    if(a.dataset.deletePasskey){if(!confirm('Hapus passkey ini?'))return;await api('/api/security/passkey/'+a.dataset.deletePasskey,{method:'DELETE'});toast('Passkey dihapus.');await showSecurity();return}
    if(a.hasAttribute('data-issue-usb')){
      const pw=prompt('Konfirmasi password akun Anda (opsional jika baru saja login):')||'';
      const r=await api('/api/security/usb/issue',{method:'POST',body:{label:'Personal USB Key',revoke_old:true,password:pw}});
      const rawBytes=b64uToBytes(r.key_b64);
      downloadBlob(new Blob([rawBytes],{type:'application/octet-stream'}),'chrya_usb.key');
      toast(r.message);await showSecurity();return;
    }
    if(a.hasAttribute('data-rotate-host-usb')){
      const pw=prompt('Konfirmasi password untuk merotasi USB Dongle host:')||'';
      const r=await api('/api/security/usb/rotate-host',{method:'POST',body:{password:pw}});
      toast(r.message);await showSecurity();return;
    }
    if(a.dataset.revokeUsb){
      const [id,reason]=a.dataset.revokeUsb.split(':');
      const r=await api('/api/security/usb/'+id+'/revoke',{method:'POST',body:{reason}});
      toast(r.message);await showSecurity();return;
    }
    if(a.hasAttribute('data-generate-recovery')){
      const pw=prompt('Konfirmasi password akun Anda:')||'';
      const r=await api('/api/security/recovery/generate',{method:'POST',body:{password:pw}});
      const box=$('recovery-codes-display');
      if(box){box.classList.remove('hidden');box.innerHTML=`<h3>Simpan Kode Pemulihan Darurat</h3><p class="mono">${r.codes.map(escapeHtml).join('<br>')}</p>`;}
      toast(r.message);return;
    }
    if(a.hasAttribute('data-rotate-key')){
      const pw=prompt('Konfirmasi password untuk rotasi kunci enkripsi:')||'';
      const r=await api('/api/security/keys/rotate',{method:'POST',body:{password:pw}});
      toast(r.message);await showSecurity();return;
    }
    if(a.hasAttribute('data-backup-db')){
      const pw=prompt('Konfirmasi password untuk membuat backup database:')||'';
      const r=await api('/api/security/database/backup',{method:'POST',body:{password:pw}});
      toast(r.message);return;
    }
 }));

 document.body.addEventListener('submit',safeRun(async e=>{
   const validForms=['compose-form','note-form','note-search-form','contact-search','file-form','file-search-form','message-search-form','stego-embed-form','stego-extract-form','change-password-form','backup-master-form'];
   if(!validForms.includes(e.target.id))return;
   e.preventDefault();
   const form=e.target;const data=new FormData(form);
   if(form.id==='contact-search'){await showContacts(data.get('q'),state.contactFilter);return}
   if(form.id==='message-search-form'){await showMessages(state.msgBox,data.get('q'));return}
   if(form.id==='compose-form'){const payload=Object.fromEntries(data);if(state.reply?.reply_to)payload.reply_to=state.reply.reply_to;const result=await api('/api/messages',{method:'POST',body:payload});state.reply=null;toast(result.notice);await navigate('sent');return}
   if(form.id==='note-form'){
     const obj=Object.fromEntries(data);const nid=obj.note_id;delete obj.note_id;
     if(nid){await api('/api/notes/'+nid,{method:'PUT',body:obj});state.editingNote=null;toast('Catatan diperbarui.');}
     else{await api('/api/notes',{method:'POST',body:obj});toast('Catatan tersimpan terenkripsi.');}
     await showVault();return;
   }
   if(form.id==='note-search-form'){state.noteQuery=data.get('q')||'';state.noteCategory=data.get('category')||'';await showVault();return}
   if(form.id==='file-form'){await api('/api/files',{method:'POST',body:data});toast('File terenkripsi disimpan.');await showFiles();return}
   if(form.id==='file-search-form'){state.fileQuery=data.get('q')||'';state.fileCategory=data.get('category')||'';await showFiles();return}
   if(form.id==='stego-embed-form'){const result=await api('/api/stego/embed',{method:'POST',body:data,download:true});downloadBlob(result.blob,'chrya_stego.png');toast('Gambar stego PNG berhasil dibuat.');return}
   if(form.id==='stego-extract-form'){const result=await api('/api/stego/extract',{method:'POST',body:data});$('stego-result').classList.remove('hidden');$('stego-result').innerHTML='<h3>Secret recovered</h3><p>'+escapeHtml(result.message)+'</p>';toast('Pesan tersembunyi berhasil diekstraksi.');return}
   if(form.id==='change-password-form'){const r=await api('/api/security/password',{method:'POST',body:Object.fromEntries(data)});form.reset();toast(r.message);await showSecurity();return}
   if(form.id==='backup-master-form'){const r=await api('/api/security/keys/backup',{method:'POST',body:Object.fromEntries(data),download:true});downloadBlob(r.blob,'chrya_master_key_backup.enc.json');form.reset();toast('Backup master key terenkripsi berhasil diunduh.');return}
 }));
}

// Web Audio API notification chime (no external audio files needed, works offline)
function playChime(){
  try{
    const AudioCtx=window.AudioContext||window.webkitAudioContext;
    if(!AudioCtx)return;
    const ctx=new AudioCtx();
    const t=ctx.currentTime;
    const osc1=ctx.createOscillator(),g1=ctx.createGain();
    osc1.type='sine';osc1.frequency.setValueAtTime(587.33,t);
    g1.gain.setValueAtTime(0.14,t);g1.gain.exponentialRampToValueAtTime(0.001,t+0.32);
    osc1.connect(g1);g1.connect(ctx.destination);
    osc1.start(t);osc1.stop(t+0.32);
    const osc2=ctx.createOscillator(),g2=ctx.createGain();
    osc2.type='sine';osc2.frequency.setValueAtTime(880,t+0.1);
    g2.gain.setValueAtTime(0.16,t+0.1);g2.gain.exponentialRampToValueAtTime(0.001,t+0.5);
    osc2.connect(g2);g2.connect(ctx.destination);
    osc2.start(t+0.1);osc2.stop(t+0.5);
  }catch(e){}
}

function syncActivityBadges(s){
  const unreadMsg = Number(s.unread || 0);
  const unreadNotif = Number(s.unread_notifications || 0);
  const pendingInvites = Number(s.pending_invites || 0);

  // 1. Sidebar count badges
  if($('nav-unread'))$('nav-unread').textContent=String(unreadMsg);
  if($('nav-invites')){$('nav-invites').textContent=String(pendingInvites);$('nav-invites').classList.toggle('hidden',!pendingInvites);}
  if($('nav-notifs')){$('nav-notifs').textContent=String(unreadNotif);$('nav-notifs').classList.toggle('hidden',!unreadNotif);}

  // 2. Top header notification icon badge
  const headerBadge = $('header-notif-badge');
  if(headerBadge){
    const totalAlerts = unreadNotif + unreadMsg + pendingInvites;
    headerBadge.textContent = totalAlerts > 99 ? '99+' : String(totalAlerts);
    headerBadge.classList.toggle('hidden', totalAlerts <= 0);
  }

  // 3. Mobile bottom bar Inbox badge
  const mobileBadge = $('mobile-unread-badge');
  if(mobileBadge){
    mobileBadge.textContent = String(unreadMsg);
    mobileBadge.classList.toggle('hidden', unreadMsg <= 0);
  }

  // 4. Update browser tab title with unread indicator (e.g. "(1) CHRYA BOX")
  const totalUnread = unreadMsg + pendingInvites;
  document.title = (totalUnread > 0 ? `(${totalUnread}) ` : '') + 'CHRYA BOX — Private Messaging & Digital Vault';
}

async function refreshCrossDeviceActivity(forced=false){
  if(!state.me || state.refreshing) return;
  state.refreshing = true;
  try{
    const latest = await api('/api/stats');
    const previous = state.stats;
    syncActivityBadges(latest);
    state.stats = latest;

    // Detect if a new incoming message, contact invite, or notification arrived
    const hasNewMsg = previous && (
      (latest.unread > (previous.unread || 0)) ||
      (latest.inbox > (previous.inbox || 0))
    );
    const hasNewInvite = previous && (latest.pending_invites > (previous.pending_invites || 0));
    const hasNewNotif = previous && (
      (latest.unread_notifications > (previous.unread_notifications || 0)) ||
      (latest.latest_notification && state.lastNotifId && latest.latest_notification.id > state.lastNotifId)
    );

    if(latest.latest_notification){
      state.lastNotifId = Math.max(state.lastNotifId || 0, latest.latest_notification.id);
    }

    if(hasNewMsg){
      playChime();
      const txt = (latest.latest_notification && latest.latest_notification.category === 'message')
        ? latest.latest_notification.text
        : '✉️ Ada pesan rahasia baru di Inbox!';
      toast(txt);
      if(window.Notification && Notification.permission === 'granted'){
        try { new Notification('CHRYA BOX', { body: txt, icon: '/favicon.ico' }); } catch(e){}
      }
    } else if(hasNewInvite){
      playChime();
      const txt = (latest.latest_notification && latest.latest_notification.category === 'contact')
        ? latest.latest_notification.text
        : '♧ Ada permintaan kontak baru!';
      toast(txt);
      if(window.Notification && Notification.permission === 'granted'){
        try { new Notification('CHRYA BOX', { body: txt, icon: '/favicon.ico' }); } catch(e){}
      }
    } else if(hasNewNotif){
      playChime();
      const txt = latest.latest_notification?.text || '♢ Anda memiliki pemberitahuan baru.';
      toast(txt);
    }

    // Real-time live view update without requiring manual page reload
    if(state.view === 'inbox' && !state.openMessage && hasNewMsg){
      await showMessages('inbox', state.msgQuery);
    } else if(state.view === 'contacts' && hasNewInvite && !$('contact-search-input')?.matches(':focus')){
      await showContacts(state.contactQuery, state.contactFilter);
    } else if(state.view === 'notifications' && (hasNewNotif || hasNewMsg)){
      await showNotifications();
    } else if(state.view === 'dashboard' && previous && (
      hasNewMsg || hasNewInvite || latest.contacts !== previous.contacts || latest.files !== previous.files
    )){
      await showDashboard();
    }
  }catch(error){
    if(error.message?.includes('sesi') || error.message?.includes('Terkunci')) return;
  }finally{
    state.refreshing = false;
  }
}
let contactSearchTimer=null;
document.body.addEventListener('input', e=>{
 if(e.target.id!=='contact-search-input')return;
 const value=e.target.value;
 clearTimeout(contactSearchTimer);
 contactSearchTimer=setTimeout(()=>liveSearchContacts(value).catch(err=>toast(err.message,true)),250);
});
async function init(){
  installEvents();
  try{
    const status=await api('/api/status');
    state.usbState=status;
    if(!status.authorized){toast(status.reason+' — daftarkan flashdisk sebelum menggunakan aplikasi.',true);return}
    const user=await api('/api/me');
    if(user.authenticated){state.me=user.user;state.csrf=user.csrf;await openWorkspace()}
  }catch(e){toast('Gagal memeriksa koneksi ke server.',true)}

  // USB Dongle watchdog: checks every 4.5s
  setInterval(async()=>{
    if(!state.me)return;
    try{
      const s=await fetch('/api/status').then(r=>r.json());
      if(!s.authorized)showLocked('USB Vault Key dicabut. Akses server telah dikunci.')
    }catch(e){}
  },4500);

  // Fast real-time polling every 2.5 seconds (was 12s)
  setInterval(() => refreshCrossDeviceActivity(), 2500);

  // Instant refresh as soon as user returns to or focuses the tab
  document.addEventListener('visibilitychange', () => {
    if(!document.hidden) refreshCrossDeviceActivity(true);
  });
  window.addEventListener('focus', () => {
    refreshCrossDeviceActivity(true);
  });
}
document.addEventListener('DOMContentLoaded',init);
