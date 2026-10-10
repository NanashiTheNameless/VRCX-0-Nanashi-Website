import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, ArrowUpRight, Database, Globe, KeyRound, LogOut, Shield, ShieldCheck, Users, Waves } from 'lucide-react'
import { createPasskeyEnvelope, createPassphraseEnvelope, createPrfCredential, generatePassphrase, generateWordPassphrase, normalizeSyncKey, openPasskeyEnvelope, openPassphraseEnvelope, type Envelope } from './envelopes'
import { configPromise, getToken, request, tokenKey } from './api'
import { HistoryBrowser } from './history'
import { RelayPage } from './relay'
import { ChosenPassphrase, Clients, Collections, DeviceTransfer, KeyUnlock, Pairing, RecoveryCodes, Tokens, YourData } from './account'
import { ImagesToggle, useImagesEnabled } from './images'
import { Licenses, Themes } from './publicPages'
import { forgetProtocolWorker, unlockProtocolWorker } from './protocol'
import './styles/fonts-0xproto.css'
import './styles/app.css'

type Me = { accountId: string; email: string; state: string; role: string; twofaMethod: string | null; recoveryCodesLeft: number; usageBytes: number; quotaBytes: number | null; syncAllowed: boolean; collectorAllowed: boolean; adminAvailable: boolean }
type Challenge = { challenge: string; next: string; methods?: string[] }
function LandingPage() {
  return <main className="landing-shell">
    <header className="landing-nav">
      <a className="landing-brand" href="/"><img className="landing-mark" src="/vrcx-0-nanashi.png" alt="" /><span>VRCX-0-NANASHI</span></a>
      <nav aria-label="Main navigation">
        <a href="/privacy">Privacy</a>
        <a href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi" target="_blank" rel="noreferrer">Source <ArrowUpRight size={14}/></a>
      </nav>
    </header>
    <section className="landing-hero">
      <div className="landing-copy">
        <h1>VRCX-0-Nanashi</h1>
        <p>A personal fork of VRCX-0 for VRChat.</p>
        <div className="landing-actions">
          <a className="landing-button primary" href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi/releases/tag/Nightly-Rolling" target="_blank" rel="noreferrer">Download <ArrowUpRight size={16}/></a>
          <a className="landing-button secondary" href="/privacy">Privacy</a>
        </div>
      </div>
      <img className="landing-logo" src="/vrcx-0-nanashi.png" alt="VRCX-0-Nanashi app icon" />
    </section>
    <footer className="landing-footer">
      <a className="landing-brand" href="/"><img className="landing-mark" src="/vrcx-0-nanashi.png" alt="" /> VRCX-0-NANASHI</a>
      <a href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi" target="_blank" rel="noreferrer">Source</a>
      <a href="/privacy">Privacy</a>
    </footer>
  </main>
}

function PrivacyPage() {
  return <main className="landing-shell privacy-page">
    <header className="landing-nav">
      <a className="landing-brand" href="/"><img className="landing-mark" src="/vrcx-0-nanashi.png" alt="" /><span>VRCX-0-NANASHI</span></a>
      <nav aria-label="Main navigation"><a href="/">Home</a></nav>
      <a className="landing-nav-cta" href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi/releases/tag/Nightly-Rolling" target="_blank" rel="noreferrer">Download <ArrowUpRight size={15}/></a>
    </header>
    <article className="privacy-content">
      <h1>Privacy</h1>
      <p>VRCX-0-Nanashi is open source. Read the source code to see how the desktop app and RemoteSync service handle information.</p>
      <ul>
        <li><a href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi" target="_blank" rel="noreferrer">Desktop app source code</a></li>
        <li><a href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi-Website" target="_blank" rel="noreferrer">RemoteSync website and server source code</a></li>
      </ul>
      <p>Source code describes the software. A self-hosted RemoteSync server's operator controls its hosting and configuration.</p>
      <a className="landing-button secondary" href="/">Back to home</a>
    </article>
    <footer className="landing-footer"><a className="landing-brand" href="/"><img className="landing-mark" src="/vrcx-0-nanashi.png" alt="" /> VRCX-0-NANASHI</a><a href="/privacy">Privacy</a></footer>
  </main>
}

function App() {
  const [token, setToken] = useState(getToken())
  const [me, setMe] = useState<Me | null>(null)
  const [page, setPage] = useState(location.pathname.startsWith('/pair') ? 'pair' : 'home')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [keep, setKeep] = useState(false)
  const [busy, setBusy] = useState(false)
  const [browserKeyUnlocked,setBrowserKeyUnlocked]=useState(false)
  const [buildInfo, setBuildInfo] = useState<{version:string,manifestSha256:string}|null>(null)

  useEffect(() => { if (token) request<Me>('/me').then(setMe).catch(e => { setError(e.message); sessionStorage.removeItem(tokenKey); localStorage.removeItem(tokenKey); setToken(null); setBrowserKeyUnlocked(false); void forgetProtocolWorker() }) }, [token])
  useEffect(() => { fetch('/build.json').then(r=>r.json()).then(setBuildInfo).catch(()=>{}) }, [])
  const act = async (work: () => Promise<void>) => { setBusy(true); setError(''); setNotice(''); try { await work() } catch (e) { setError((e as Error).message) } finally { setBusy(false) } }
  const signOut = () => act(async () => { try { await request('/session', { method: 'DELETE' }) } finally { sessionStorage.removeItem(tokenKey); localStorage.removeItem(tokenKey); setToken(null); setMe(null); setBrowserKeyUnlocked(false); await forgetProtocolWorker() } })
  const unlockBrowserKey = async (key:string) => { await unlockProtocolWorker(key); setBrowserKeyUnlocked(true) }
  const forgetBrowserKey = async () => { await forgetProtocolWorker(); setBrowserKeyUnlocked(false) }
  const authenticated = (session: string, codes?: string[]) => {
    ;(keep ? localStorage : sessionStorage).setItem(tokenKey, session)
    setToken(session)
    if (codes?.length) setCodes(codes)
  }

  if (location.pathname === '/privacy') return <PrivacyPage/>
  if (location.pathname === '/') return <LandingPage/>
  if (location.pathname.startsWith('/open/')) return <RelayPage/>
  if (location.pathname === '/themes') return <Themes/>
  if (location.pathname === '/licenses') return <Licenses/>
  if (location.pathname.startsWith('/c/')) return <PublicCollection code={location.pathname.split('/')[2] ?? ''}/>
  if (location.pathname === '/collections') return <PublicDirectory/>

  if (!token || !me) return <main className="auth-shell"><div className="brand"><Waves size={22}/><span>RemoteSync</span></div><AuthForm busy={busy} error={error} notice={notice} onAuthenticated={authenticated}/><label className="check-label keep-signed-in"><input type="checkbox" checked={keep} onChange={e=>setKeep(e.target.checked)}/>Keep me signed in on this browser</label><BuildFooter build={buildInfo}/></main>

  return <div className="layout"><aside className="sidebar"><a className="brand" href="#home"><Waves size={22}/> RemoteSync</a><nav>{[['home',Activity,'Overview'],['devices',Users,'Devices'],['data',Database,'Your data'],['collections',Globe,'Collections'],['security',KeyRound,'Security'],...(['admin','owner'].includes(me.role) ? [['admin',Shield,'Administration'] as const] : [])].map(([id,Icon,label]) => <button key={id as string} className={page===id?'selected':''} onClick={()=>setPage(id as string)}><Icon size={17}/>{label as string}</button>)}</nav><div className="profile"><span className="avatar">{me.email[0].toUpperCase()}</span><span className="ellipsis">{me.email}</span><button title="Sign out" onClick={signOut}><LogOut size={17}/></button></div></aside><main className="content"><header><div><div className="eyebrow">ACCOUNT</div><h1>{page === 'home' ? 'Overview' : page === 'admin' ? 'Administration' : page === 'data' ? 'Your data' : page[0].toUpperCase()+page.slice(1)}</h1></div><span className={`pill ${me.state}`}>{me.state}</span></header>{error&&<div className="alert error">{error}</div>}{notice&&<div className="alert">{notice}</div>}{codes&&<RecoveryCodes codes={codes} onDone={()=>setCodes(null)}/>}{!codes&&page==='home'&&<Overview me={me} keyUnlocked={browserKeyUnlocked} onForget={forgetBrowserKey}/ >}{!codes&&page==='devices'&&<><Clients act={act} twofaMethod={me.twofaMethod}/><Tokens act={act} twofaMethod={me.twofaMethod}/></>}{!codes&&page==='data'&&<YourData act={act} usageBytes={me.usageBytes} quotaBytes={me.quotaBytes} email={me.email} twofaMethod={me.twofaMethod} unlocked={browserKeyUnlocked} onDeleted={()=>{sessionStorage.removeItem(tokenKey);localStorage.removeItem(tokenKey);setToken(null);setMe(null)}}/>}{!codes&&page==='collections'&&<Collections act={act}/>}{!codes&&page==='security'&&<><KeyUnlock act={act} unlocked={browserKeyUnlocked} onUnlock={unlockBrowserKey} onForget={forgetBrowserKey}/><DeviceTransfer act={act} accountId={me.accountId} unlocked={browserKeyUnlocked} twofaMethod={me.twofaMethod} onReceived={()=>setBrowserKeyUnlocked(true)}/><ChosenPassphrase act={act} accountId={me.accountId} twofaMethod={me.twofaMethod} onSaved={()=>setNotice('Envelope saved. Remember this passphrase; it cannot be recovered.')}/><Security me={me} act={act} setNotice={setNotice} showCodes={setCodes} onUnlock={unlockBrowserKey} onForget={forgetBrowserKey}/ ></>}{!codes&&page==='admin'&&<Admin act={act} available={me.adminAvailable} actorRole={me.role}/ >}{!codes&&page==='pair'&&<Pairing act={act} twofaMethod={me.twofaMethod}/>}<BuildFooter build={buildInfo}/></main></div>
}

function AuthForm({busy,error,notice,onAuthenticated}:{busy:boolean,error:string,notice:string,onAuthenticated:(session:string,codes?:string[])=>void}) {
  const [mode,setMode]=useState<'login'|'signup'>('login')
  const [step,setStep]=useState<'credentials'|'verify'|'enroll'|'totp-confirm'|'reset-password'|'reset-verify'>('credentials')
  const [email,setEmail]=useState(''); const [password,setPassword]=useState(''); const [newPassword,setNewPassword]=useState(''); const [code,setCode]=useState('')
  const [method,setMethod]=useState('totp'); const [challenge,setChallenge]=useState(''); const [totpSecret,setTotpSecret]=useState('')
  const [methods,setMethods]=useState<string[]>(['totp','email','recovery'])
  const [emailQueued,setEmailQueued]=useState(false)
  useEffect(()=>{
    const hash=location.hash.slice(1)
    if(location.pathname==='/reset'&&hash){setStep('reset-password');return}
    if(location.pathname==='/verify'&&hash){
      request<Challenge>('/auth/verify',{method:'POST',body:JSON.stringify({token:hash})}).then(result=>{setChallenge(result.challenge);setStep('enroll');history.replaceState(null,'','/verify')}).catch(()=>{})
    }
  },[])
  const submit=async(e:React.FormEvent)=>{
    e.preventDefault()
    if(step==='reset-password'){
      const result=await request<Challenge>('/auth/reset/finish',{method:'POST',body:JSON.stringify({token:location.hash.slice(1),password:newPassword})})
      setChallenge(result.challenge);setMethods(result.methods??['totp','email','recovery']);setMethod(result.methods?.[0]??'totp');setStep('reset-verify');history.replaceState(null,'',location.pathname);return
    }
    if(step==='reset-verify'){
      const result=await request<{session:string}>('/auth/login/2fa',{method:'POST',body:JSON.stringify({challenge,method,code})})
      onAuthenticated(result.session);return
    }
    if(step==='credentials'){
      if(mode==='signup'){
        const invite=location.pathname==='/invite'?location.hash.slice(1):undefined
        const result=await request<Challenge|undefined>('/auth/signup',{method:'POST',body:JSON.stringify({email,password,message:'',...(invite?{inviteToken:invite}:{})})})
        if(result?.challenge){setChallenge(result.challenge);setStep('enroll')}
        else setEmailQueued(true)
        return
      }
      const result=await request<Challenge>('/auth/login',{method:'POST',body:JSON.stringify({email,password})})
      setChallenge(result.challenge);setMethods(result.methods??['totp','email']);setMethod(result.methods?.[0]??'totp');setStep(result.next==='enroll'?'enroll':'verify');return
    }
    if(step==='verify'){
      const result=await request<{session:string}>('/auth/login/2fa',{method:'POST',body:JSON.stringify({challenge,method,code})})
      onAuthenticated(result.session);return
    }
    if(step==='enroll'){
      if(method==='email') {await request('/auth/enroll/email',{method:'POST',body:JSON.stringify({challenge})});setStep('totp-confirm');setEmailQueued(true);return}
      const setup=await request<{secret:string,uri:string}>('/auth/enroll/totp',{method:'POST',body:JSON.stringify({challenge})})
      setTotpSecret(`${setup.secret}\n${setup.uri}`);setStep('totp-confirm');return
    }
    if(method==='email'){
      const result=await request<{session:string,recoveryCodes:string[]}>('/auth/enroll/email/confirm',{method:'POST',body:JSON.stringify({challenge,code})})
      onAuthenticated(result.session,result.recoveryCodes);return
    }
    const result=await request<{session:string,recoveryCodes:string[]}>('/auth/enroll/totp/confirm',{method:'POST',body:JSON.stringify({challenge,code})})
    onAuthenticated(result.session,result.recoveryCodes)
  }
  const title=step==='verify'||step==='reset-verify'?'Two-factor verification':step==='enroll'?'Set up two-factor authentication':step==='totp-confirm'?'Confirm your authenticator':step==='reset-password'?'Choose a new password':mode==='login'?'Sign in':'Create account'
  return <section className="auth-card"><div className="eyebrow">ACCOUNT ACCESS</div><h1>{title}</h1><p className="muted">Your RemoteSync account is separate from your VRChat account.</p>{error&&<div className="alert error">{error}</div>}{notice&&<div className="alert">{notice}</div>}{emailQueued&&<div className="alert">Check your email for the next step. If you are setting up email 2FA, enter the code we sent.</div>}{step==='totp-confirm'&&totpSecret&&<div className="secret-box"><b>Authenticator setup key</b><pre>{totpSecret}</pre><small>Add this key to your authenticator app, then enter its current 6-digit code.</small></div>}<form onSubmit={submit}>{step==='credentials'&&<><label>Email<input autoComplete="email" type="email" required value={email} onChange={e=>setEmail(e.target.value)}/></label><label>Password<input autoComplete={mode==='login'?'current-password':'new-password'} type="password" minLength={12} required value={password} onChange={e=>setPassword(e.target.value)}/></label></>}{step==='reset-password'&&<label>New password<input autoComplete="new-password" type="password" minLength={12} required value={newPassword} onChange={e=>setNewPassword(e.target.value)}/></label>}{(step==='verify'||step==='enroll'||step==='reset-verify')&&<label>{step==='enroll'?'Choose a two-factor method':'Verification method'}<select value={method} onChange={e=>setMethod(e.target.value)}>{(step==='enroll'?['totp','email']:methods).map(m=><option key={m} value={m}>{m==='totp'?'Authenticator app':m==='email'?'Email code':'Recovery code'}</option>)}</select></label>}{(step==='verify'||step==='reset-verify'||step==='totp-confirm')&&<label>{method==='recovery'?'Recovery code':method==='email'?'Email code':'6-digit authenticator code'}<input autoFocus required value={code} onChange={e=>setCode(e.target.value)}/></label>}{(step==='verify'||step==='reset-verify')&&method==='email'&&<button type="button" onClick={async()=>{await request('/auth/login/email-code',{method:'POST',body:JSON.stringify({challenge})});setEmailQueued(true)}}>Send code to email</button>}<button className="primary" disabled={busy}>{busy?'Please wait…':step==='credentials'?(mode==='login'?'Continue':'Create account'):step==='verify'||step==='reset-verify'?'Verify and sign in':step==='enroll'?'Continue':step==='reset-password'?'Set new password':'Confirm setup'}</button></form>{step==='credentials'&&<>{mode==='login'&&<button className="link" onClick={()=>{request('/auth/reset',{method:'POST',body:JSON.stringify({email})}).then(()=>setEmailQueued(true)).catch(()=>setEmailQueued(true))}}>Forgot password?</button>}<button className="link" onClick={()=>{setMode(mode==='login'?'signup':'login');setEmailQueued(false)}}>{mode==='login'?'Need an account? Sign up':'Already have an account? Sign in'}</button></>}{step!=='credentials'&&<button className="link" onClick={()=>{setStep('credentials');setCode('');setEmailQueued(false)}}>Back</button>}</section>
}

function Overview({me,keyUnlocked,onForget}:{me:Me,keyUnlocked:boolean,onForget:()=>Promise<void>}) { const usage=me.usageBytes;const pct=me.quotaBytes?Math.min(100,usage/me.quotaBytes*100):0;return <>{me.recoveryCodesLeft<=2&&<div className="alert error">Only {me.recoveryCodesLeft} recovery codes remain. Generate a fresh set in Security.</div>}<div className="hero"><div><div className="eyebrow">REMOTE VIEWING</div><h2>Your account is ready</h2><p>RemoteSync keeps encrypted VRCX history available to your devices.</p></div><Activity size={48}/></div><div className="cards"><article className="card"><div className="card-title">Storage usage</div><strong>{formatBytes(usage)}</strong><div className="progress"><i style={{width:`${pct}%`}}/></div><small>{me.quotaBytes?`of ${formatBytes(me.quotaBytes)} limit`:'No storage limit'}</small></article><article className="card"><div className="card-title">RemoteSync access</div><strong>{me.syncAllowed?'Enabled':'Disabled'}</strong><small>{me.collectorAllowed?'Collector access is allowed':'Collector access is disabled'}</small></article><article className="card"><div className="card-title">Security</div><strong>{me.twofaMethod==='totp'?'Authenticator enabled':'2FA enabled'}</strong><small>{me.recoveryCodesLeft} recovery codes remaining</small></article></div>{keyUnlocked&&<div className="key-status">Sync key is unlocked in this tab's protocol Worker. <button onClick={()=>void onForget()}>Forget key</button></div>}<HistoryBrowser unlocked={keyUnlocked} accountId={me.accountId}/></>}


function Security({me,act,setNotice,showCodes,onUnlock,onForget}:{me:Me,act:(f:()=>Promise<void>)=>Promise<void>,setNotice:(s:string)=>void,showCodes:(codes:string[])=>void,onUnlock:(key:string)=>Promise<void>,onForget:()=>Promise<void>}) {
  const [code,setCode]=useState(''); const [reauthMethod,setReauthMethod]=useState(me.twofaMethod==='email'?'email':'totp'); const [emailCodeSent,setEmailCodeSent]=useState(false); const [envelopes,setEnvelopes]=useState<any[]|null>(null)
  const [syncKey,setSyncKey]=useState(''); const [label,setLabel]=useState('Browser recovery'); const [newPassphrase,setNewPassphrase]=useState(''); const [unlockId,setUnlockId]=useState(''); const [unlockEnvelope,setUnlockEnvelope]=useState<Envelope|null>(null); const [unlockPassphrase,setUnlockPassphrase]=useState(''); const [keyUnlocked,setKeyUnlocked]=useState(false)
  const reauth=async()=>request('/reauth',{method:'POST',body:JSON.stringify({method:reauthMethod,code})})
  const refreshEnvelopes=async()=>{await reauth();setEnvelopes(await request<any[]>('/envelopes'))}
  return <div className="security-grid"><article className="card"><h2>Recovery codes</h2><p>You have {me.recoveryCodesLeft} recovery codes remaining.</p><label>Verification method<select value={reauthMethod} onChange={e=>{setReauthMethod(e.target.value);setCode('');setEmailCodeSent(false)}}><option value="totp">Authenticator app</option><option value="email">Email code</option><option value="recovery">Recovery code</option></select></label>{reauthMethod==='email'&&<button onClick={()=>act(async()=>{await request('/reauth/email-code',{method:'POST'});setEmailCodeSent(true)})}>{emailCodeSent?'Send another email code':'Send email code'}</button>}<label>{reauthMethod==='totp'?'Authenticator code':reauthMethod==='email'?'Email verification code':'Recovery code'}<input autoComplete={reauthMethod==='totp'?'one-time-code':'off'} value={code} onChange={e=>setCode(e.target.value)}/></label><button className="primary" onClick={()=>act(async()=>{await reauth();const data=await request<{recoveryCodes:string[]}>('/recovery-codes',{method:'POST'});showCodes(data.recoveryCodes);setCode('')})}>Generate new codes</button></article>
    <article className="card"><h2>Stored key envelopes</h2><p className="muted">Create an encrypted browser recovery envelope from your 64-character sync key. The passphrase is generated on this device and never sent to the server. Save both the passphrase and key somewhere safe.</p>
      <label>Sync key (64 hex characters or rss1 recovery string)<input type="password" autoComplete="off" value={syncKey} onChange={e=>setSyncKey(e.target.value)}/></label>
      <label>Envelope label<input maxLength={64} value={label} onChange={e=>setLabel(e.target.value)}/></label>
      <div className="actions"><button onClick={()=>setNewPassphrase(generatePassphrase())}>Generate passphrase</button><button onClick={()=>void generateWordPassphrase().then(setNewPassphrase)}>Generate 7 words</button>{newPassphrase&&<code className="secret-code">{newPassphrase}</code>}</div>
      {newPassphrase&&<button className="primary" onClick={()=>act(async()=>{const normalizedKey=normalizeSyncKey(syncKey);await reauth();const envelope=await createPassphraseEnvelope(me.accountId,normalizedKey,label,newPassphrase);await request('/envelopes',{method:'POST',body:JSON.stringify(envelope)});await onUnlock(normalizedKey);setKeyUnlocked(true);setSyncKey('');setEnvelopes(await request<any[]>('/envelopes'));setNotice(`Envelope saved. Store this generated passphrase now; it cannot be recovered: ${newPassphrase}`);setNewPassphrase('');setCode('')})}>Encrypt and save envelope</button>}
      <button onClick={()=>act(async()=>{const normalizedKey=normalizeSyncKey(syncKey);if(!label.trim()||label.length>64)throw new Error('Give this key envelope a label of 1 to 64 characters.');const prf=await createPrfCredential(me.email);await reauth();const envelope=await createPasskeyEnvelope(me.accountId,normalizedKey,label,prf.credentialId,prf.prfSalt,prf.prfOutput);await request('/envelopes',{method:'POST',body:JSON.stringify(envelope)});await onUnlock(normalizedKey);setKeyUnlocked(true);setSyncKey('');setEnvelopes(await request<any[]>('/envelopes'));setNotice('Passkey envelope saved. The passkey is required to unlock this sync key.');setCode('')})}>Create passkey envelope</button>
      <p className="muted">Passphrase envelopes use Argon2id (256 MiB, 3 passes) and XChaCha20-Poly1305. A wrong passphrase or modified envelope fails to decrypt.</p>
      <button onClick={()=>act(refreshEnvelopes)}>Verify and load envelopes</button>{envelopes&&<div className="envelope-list">{envelopes.length===0?<p className="muted">No stored envelopes.</p>:envelopes.map((item:any)=><div className="envelope-row" key={item.envelopeId}><span><b>{item.label||'Unnamed envelope'}</b><small>{item.kind} · Added {date(item.createdAtMs)}</small></span><div className="actions">{item.kind==='passphrase'&&<button onClick={()=>{setUnlockId(item.envelopeId);setUnlockEnvelope(null)}}>Unlock</button>}{item.kind==='passkey-prf'&&<button onClick={()=>act(async()=>{await reauth();setUnlockEnvelope(await request<Envelope>(`/envelopes/${encodeURIComponent(item.envelopeId)}`));setUnlockId(item.envelopeId);setCode('')})}>Unlock with passkey</button>}<button className="danger" onClick={()=>{if(confirm(`Delete “${item.label||'this envelope'}”?`))act(async()=>{await reauth();await request(`/envelopes/${encodeURIComponent(item.envelopeId)}`,{method:'DELETE'});setEnvelopes(await request<any[]>('/envelopes'));setCode('')})}}>Delete</button></div></div>)}</div>}
      {unlockId&&!unlockEnvelope&&<div className="unlock-box"><label>Generated passphrase<input autoComplete="off" value={unlockPassphrase} onChange={e=>setUnlockPassphrase(e.target.value)}/></label><button className="primary" onClick={()=>act(async()=>{await reauth();const envelope=await request<Envelope>(`/envelopes/${encodeURIComponent(unlockId)}`);const key=await openPassphraseEnvelope(me.accountId,envelope,unlockPassphrase);await onUnlock(key);setKeyUnlocked(true);setUnlockPassphrase('');setCode('')})}>Decrypt sync key</button></div>}
      {unlockEnvelope&&<div className="unlock-box"><p>Use the passkey created for “{unlockEnvelope.label}”.</p><button className="primary" onClick={()=>act(async()=>{const key=await openPasskeyEnvelope(me.accountId,unlockEnvelope);await onUnlock(key);setKeyUnlocked(true);setUnlockEnvelope(null)})}>Use passkey</button></div>}
      {keyUnlocked&&<div className="alert">Sync key is unlocked in the protocol Worker. The page does not retain the decrypted key. <button onClick={()=>void onForget().then(()=>setKeyUnlocked(false))}>Forget key</button></div>}
      {envelopes&&envelopes.length>0&&<button className="danger" onClick={()=>{if(confirm('Delete every stored key envelope?'))act(async()=>{await reauth();await request('/envelopes',{method:'DELETE'});setEnvelopes([]);setCode('')})}}>Delete all envelopes</button>}</article>
    <article className="card"><h2>Delete account</h2><p className="muted">Permanently removes the account and its encrypted data.</p><button className="danger" onClick={()=>{if(confirm('Permanently delete this account and its data?'))act(async()=>{await reauth();await request('/account',{method:'DELETE'});sessionStorage.clear();localStorage.removeItem(tokenKey);location.reload()})}}>Delete account</button></article></div>
}

function Admin({act,available,actorRole}:{act:(f:()=>Promise<void>)=>Promise<void>,available:boolean,actorRole:string}) {
  const [accounts,setAccounts]=useState<any[]>([]); const [code,setCode]=useState(''); const [unlocked,setUnlocked]=useState(false)
  const [settings,setSettings]=useState<any>(null); const [audit,setAudit]=useState<any[]>([]); const [inviteEmail,setInviteEmail]=useState('')
  const refresh=async()=>{const [a,s,l]=await Promise.all([request<any[]>('/admin/accounts'),request<any>('/admin/settings'),request<any[]>('/admin/audit')]);setAccounts(a);setSettings({...s,defaultQuota:s.defaultQuota==null?'unlimited':String(s.defaultQuota)});setAudit(l)}
  const saveSettings=()=>act(async()=>{await request('/admin/settings',{method:'PUT',body:JSON.stringify(settings)});await refresh()})
  const updateAccount=(a:any,path:string,body:any)=>act(async()=>{await request(`/admin/accounts/${a.accountId}/${path}`,{method:'PUT',body:JSON.stringify(body)});await refresh()})
  return <>
    <section className="card wide"><div className="section-heading"><div><h2>Administration</h2><p className="muted">Actions require an enrolled authenticator and recent TOTP verification.</p></div>{unlocked&&<button onClick={()=>act(refresh)}>Refresh</button>}</div>
      {!available?<div className="alert">Set up an authenticator app for this account before using the admin area. Email codes and recovery codes cannot unlock admin privileges.</div>:!unlocked?<div className="reauth"><label>Authenticator code<input autoComplete="one-time-code" value={code} onChange={e=>setCode(e.target.value)}/></label><button className="primary" onClick={()=>act(async()=>{await request('/reauth',{method:'POST',body:JSON.stringify({method:'totp',code})});setCode('');setUnlocked(true);await refresh()})}>Unlock administration</button></div>:<>
      <div className="cards admin-cards">
        <article className="card"><h2>Registration and defaults</h2>{settings&&<><label>Registration<select value={settings.registration} onChange={e=>setSettings({...settings,registration:e.target.value})}><option value="request">Request approval</option><option value="closed">Closed</option></select></label><label>Default quota (for example 5 GiB)<input value={String(settings.defaultQuota)} placeholder="unlimited" onChange={e=>setSettings({...settings,defaultQuota:e.target.value||'unlimited'})}/></label><label className="check-label"><input type="checkbox" checked={settings.collectorDefaultAllowed} onChange={e=>setSettings({...settings,collectorDefaultAllowed:e.target.checked})}/> Allow collector by default</label><button className="primary" onClick={saveSettings}>Save settings</button></>}</article>
        <article className="card"><h2>Invite an account</h2><p className="muted">Sends a one time sign-up link to this email address.</p><label>Email<input type="email" value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)}/></label><button className="primary" disabled={!inviteEmail} onClick={()=>act(async()=>{await request('/admin/invites',{method:'POST',body:JSON.stringify({email:inviteEmail})});setInviteEmail('');await refresh()})}>Send invitation</button></article>
      </div>
      {settings&&<p className="muted admin-meta">API {settings.apiOrigin} · Website origins: {(settings.websiteOrigins||[]).join(', ')} · Commit {settings.commit||'unknown'}</p>}
      <h2 className="admin-subhead">Accounts</h2><div className="admin-account-list">{accounts.map((a:any)=><AdminAccount key={a.accountId} account={a} actorRole={actorRole} update={updateAccount} act={act} refresh={refresh}/>)}</div>
      <section className="card wide"><div className="section-heading"><div><h2>Audit log</h2><p className="muted">Recent administrative actions.</p></div></div>{audit.length===0?<div className="empty-state">No audit entries.</div>:<div className="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target account</th></tr></thead><tbody>{audit.map((entry:any,i:number)=><tr key={`${entry.atMs}-${i}`}><td>{date(entry.atMs)}</td><td>{entry.actor}</td><td>{entry.action}</td><td>{entry.targetAccount||'—'}</td></tr>)}</tbody></table></div>}</section>
      </>}</section>
  </>
}

function AdminAccount({account:a,actorRole,update,act,refresh}:{account:any,actorRole:string,update:(a:any,path:string,body:any)=>Promise<void>,act:(f:()=>Promise<void>)=>Promise<void>,refresh:()=>Promise<void>}) {
  const [quota,setQuota]=useState(a.quotaBytes==null?'':String(a.quotaBytes)); const [vaults,setVaults]=useState(String(a.maxVaults)); const [confirmEmail,setConfirmEmail]=useState('')
  const protectedOwner=a.role==='owner'; const canManage=!protectedOwner&&(a.role!=='admin'||actorRole==='owner')
  return <article className="card admin-account"><div className="section-heading"><div><b>{a.email}</b><div className="muted">{a.state} · {a.role} · {formatBytes(a.usageBytes)} / {a.quotaBytes?formatBytes(a.quotaBytes):'unlimited'} · {a.maxVaults} vaults</div></div><div className="actions">{a.state==='pending'&&<><button onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/approve`,{method:'POST'});await refresh()})}>Approve</button><button className="danger" onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/deny`,{method:'POST'});await refresh()})}>Deny</button></>}{canManage&&a.state!=='pending'&&<button onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/${a.state==='suspended'?'resume':'suspend'}`,{method:'POST'});await refresh()})}>{a.state==='suspended'?'Resume':'Suspend'}</button>}</div></div>
    {canManage&&<div className="admin-controls"><label>Quota bytes<input inputMode="numeric" value={quota} onChange={e=>setQuota(e.target.value)} placeholder="unlimited"/></label><label>Maximum vaults<input type="number" min="1" max="1000" value={vaults} onChange={e=>setVaults(e.target.value)}/></label><button onClick={()=>update(a,'limits',{quota:quota?`${quota} B`:'unlimited',maxVaults:Number(vaults)})}>Save limits</button><button onClick={()=>update(a,'collector',{allowed:!a.collectorAllowed})}>{a.collectorAllowed?'Disable':'Enable'} collector</button>{actorRole==='owner'&&<button onClick={()=>update(a,'role',{role:a.role==='admin'?'user':'admin'})}>{a.role==='admin'?'Remove admin':'Make admin'}</button>}<button onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/reset-2fa`,{method:'POST'});await refresh()})}>Reset 2FA</button><button className="danger" onClick={()=>{if(confirm(`Permanently delete ${a.email} and all of its data?`))act(async()=>{await request(`/admin/accounts/${a.accountId}`,{method:'DELETE'});await refresh()})}}>Delete account</button></div>}
    {canManage&&a.syncAllowed&&<div className="sync-disable"><p className="muted">Disabling sync permanently deletes this account’s encrypted server data.</p><label>Type {a.email} to confirm<input value={confirmEmail} onChange={e=>setConfirmEmail(e.target.value)}/></label><button className="danger" disabled={confirmEmail!==a.email} onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/sync`,{method:'PUT',body:JSON.stringify({allowed:false,confirmEmail})});setConfirmEmail('');await refresh()})}>Disable sync and delete data</button></div>}
    {canManage&&!a.syncAllowed&&<button onClick={()=>update(a,'sync',{allowed:true})}>Restore sync access</button>}
  </article>
}


async function publicGet(path:string) {
  const config=await configPromise
  const response=await fetch(`${config.apiOrigin}/public/v1${path}`)
  if(!response.ok) throw new Error(response.status===404?'This page was not found.':`Could not load page (${response.status})`)
  return response.json()
}

function PublicCollection({code}:{code:string}) {
  const images=useImagesEnabled()
  const [collection,setCollection]=useState<any>(null);const [error,setError]=useState('')
  useEffect(()=>{publicGet(`/collections/${encodeURIComponent(code)}`).then(setCollection).catch(e=>setError(e.message))},[code])
  return <main className="public-shell"><a className="brand" href="/"> <Waves size={22}/> RemoteSync</a>{error?<article className="card"><h1>Collection unavailable</h1><p>{error}</p></article>:!collection?<article className="card">Loading collection…</article>:<><header className="public-header"><div className="eyebrow">SHARED WORLD COLLECTION</div><h1>{collection.title}</h1><p className="muted">By {collection.author_name}{collection.category?` · ${collection.category}`:''}</p>{collection.note&&<p>{collection.note}</p>}<ImagesToggle/> <a className="button primary" href={`vrcx-0-nanashi://collection/import?id=${encodeURIComponent(code)}`}>Import into VRCX-0-Nanashi</a></header><div className="world-grid">{collection.worlds.map((world:any)=><article className="card world" key={world.world_id}>{images&&world.image_url&&<img src={world.image_url} alt=""/>}<div className="eyebrow">{world.world_id}</div><h2>{world.name}</h2><p className="muted">By {world.author_name}</p>{world.description&&<p>{world.description}</p>}{world.comment&&<div className="world-comment">{world.comment}</div>}</article>)}</div><small>Updated {new Date(collection.updated_at*1000).toLocaleDateString()}</small></>}</main>
}

function PublicDirectory() {
  const [items,setItems]=useState<any[]>([]);const [query,setQuery]=useState('');const [error,setError]=useState('')
  useEffect(()=>{publicGet(`/collections${query?`?q=${encodeURIComponent(query)}`:''}`).then(setItems).catch(e=>setError(e.message))},[query])
  return <main className="public-shell"><a className="brand" href="/"> <Waves size={22}/> RemoteSync</a><header className="public-header"><div className="eyebrow">COMMUNITY</div><h1>World collections</h1><p className="muted">Collections shared publicly by RemoteSync users.</p><input type="search" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search collections"/></header>{error&&<div className="alert error">{error}</div>}<div className="world-grid">{items.map((item:any)=><a className="card collection-card" href={`/c/${item.id}`} key={item.id}><div className="eyebrow">{item.category||'COLLECTION'}</div><h2>{item.title}</h2><p className="muted">Updated {new Date(item.updated_at*1000).toLocaleDateString()}</p></a>)}</div>{!items.length&&!error&&<div className="empty-state">No listed collections found.</div>}</main>
}

function formatBytes(n:number){if(n<1024)return `${n} B`;const units=['KiB','MiB','GiB','TiB'];let i=-1;do{n/=1024;i++}while(n>=1024&&i<units.length-1);return `${n.toFixed(1)} ${units[i]}`}
function date(value:number){return value?new Date(value).toLocaleString():'—'}
function BuildFooter({build}:{build:{version:string,manifestSha256:string}|null}) {return <footer className="site-footer">{build?<>Build {build.version} · Manifest SHA-256 {build.manifestSha256.slice(0,16)}</>:'RemoteSync'} · <a href="/themes">Themes</a> · <a href="/collections">Collections</a> · <a href="/licenses">Licenses</a></footer>}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
