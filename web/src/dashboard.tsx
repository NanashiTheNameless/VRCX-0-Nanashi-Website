import React, { useEffect, useState } from 'react'
import 'altcha/external'
import 'altcha/altcha.css'
import type {} from 'altcha/types/react'
import { Activity, Database, Globe, KeyRound, Link2, LogOut, Radio, Shield, Users } from 'lucide-react'
import { createPassphraseEnvelope, generatePassphrase, generateWordPassphrase, normalizeSyncKey, openPassphraseEnvelope } from './envelopes'
import { ApiError, configPromise, getToken, request, tokenKey } from './api'
import { HistoryBrowser } from './history'
import { CollectorPage } from './collector'
import { AccountSecurity, ChosenPassphrase, Clients, Collections, DeviceTransfer, KeyUnlock, Pairing, RecoveryCodes, Tokens, TotpSetup, YourData } from './account'
import { forgetProtocolWorker, unlockProtocolWorker } from './protocol'
import { forgetVerification, noteReauthFailure, useReauth } from './reauth'
import { formatBytes, useTitle } from './site'
import { startPbkdf2Worker } from './workers'

$altcha.defaults.set('hideFooter', true)
for (const algorithm of ['PBKDF2/SHA-256', 'PBKDF2/SHA-384', 'PBKDF2/SHA-512']) $altcha.algorithms.set(algorithm, startPbkdf2Worker)

type Me = { accountId: string; email: string; state: string; role: string; twofaMethod: string | null; recoveryCodesLeft: number; usageBytes: number; quotaBytes: number | null; syncAllowed: boolean; collectorAllowed: boolean; adminAvailable: boolean }
type Challenge = { challenge: string; next: string; methods?: string[] }
type Build = { version: string; manifestSha256: string }
type Step = 'credentials' | 'waiting' | 'verify' | 'enroll' | 'totp-confirm' | 'reset-password' | 'reset-verify'

const PAGES = [
  ['home', Activity, 'Overview'],
  ['devices', Users, 'Devices'],
  ['pair', Link2, 'Pair device'],
  ['data', Database, 'Your data'],
  ['collections', Globe, 'Collections'],
  ['security', KeyRound, 'Security'],
  ['collector', Radio, 'Collector'],
  ['admin', Shield, 'Administration'],
] as const
type PageId = typeof PAGES[number][0]

function pageFromLocation(): PageId {
  const pathPage = location.pathname.startsWith('/dashboard/')
    ? location.pathname.slice('/dashboard/'.length).split('/')[0]
    : ''
  const hash = location.hash.slice(1)
  const known = PAGES.find(([id]) => id === pathPage) ?? PAGES.find(([id]) => id === hash)
  if (known) return known[0]
  return location.pathname === '/pair' ? 'pair' : 'home'
}

function clearSession() {
  sessionStorage.removeItem(tokenKey)
  localStorage.removeItem(tokenKey)
  forgetVerification()
}

function AuthShell({ build, children }: { build: Build | null; children: React.ReactNode }) {
  return (
    <main className="auth-shell">
      <a className="brand" href="/"><img className="brand-mark" src="/vrcx-0-nanashi.png" alt="" /><span>RemoteSync</span></a>
      <div className="auth-body">{children}</div>
      <BuildFooter build={build} />
    </main>
  )
}

export default function Dashboard() {
  const [token, setToken] = useState(getToken())
  const [me, setMe] = useState<Me | null>(null)
  const [page, setPage] = useState<PageId>(pageFromLocation)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loadError, setLoadError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [keep, setKeep] = useState(false)
  const [busy, setBusy] = useState(false)
  const [browserKeyUnlocked, setBrowserKeyUnlocked] = useState(false)
  const [buildInfo, setBuildInfo] = useState<Build | null>(null)
  const [envelopes, setEnvelopes] = useState<any[] | null>(null)

  const dropSession = () => {
    clearSession()
    setToken(null)
    setMe(null)
    setBrowserKeyUnlocked(false)
    setEnvelopes(null)
    void forgetProtocolWorker()
  }

  useEffect(() => {
    if (!token) return
    let active = true
    setLoadError('')
    request<Me>('/me').then(result => { if (active) setMe(result) }).catch(cause => {
      if (!active) return
      if (cause instanceof ApiError && cause.status === 401) {
        dropSession()
        setError('Your session has ended. Sign in again.')
      } else setLoadError((cause as Error).message)
    })
    return () => { active = false }
  }, [token, attempt])
  useEffect(() => {
    if (me?.state !== 'pending') return
    const timer = window.setInterval(() => request<Me>('/me').then(setMe).catch(() => {}), 30_000)
    return () => window.clearInterval(timer)
  }, [me?.state])
  useEffect(() => { fetch('/build.json').then(r => r.json()).then(setBuildInfo).catch(() => {}) }, [])
  useEffect(() => {
    const update = () => { setPage(pageFromLocation()); setError(''); setNotice('') }
    window.addEventListener('hashchange', update)
    window.addEventListener('popstate', update)
    return () => {
      window.removeEventListener('hashchange', update)
      window.removeEventListener('popstate', update)
    }
  }, [])

  const isAdmin = me ? ['admin', 'owner'].includes(me.role) : false
  const pages = PAGES.filter(([id]) => id !== 'admin' ? id !== 'collector' || Boolean(me?.collectorAllowed) : isAdmin)
  const current = pages.find(([id]) => id === page) ?? pages[0]
  const signedIn = Boolean(token && me)
  useTitle(!signedIn ? 'Sign in' : me!.state === 'active' ? current[2] : 'Account')

  const act = async (work: () => Promise<void>) => {
    setBusy(true); setError(''); setNotice('')
    try { await work() } catch (cause) {
      noteReauthFailure(cause)
      if (cause instanceof ApiError && cause.status === 401) { dropSession(); setError('Your session has ended. Sign in again.') }
      else setError((cause as Error).message)
    } finally { setBusy(false) }
  }
  const signOut = async () => {
    setBusy(true)
    try { await request('/session', { method: 'DELETE' }) } catch {} finally { dropSession(); setError(''); setNotice(''); setBusy(false) }
  }
  const unlockBrowserKey = async (key: string) => { await unlockProtocolWorker(key); setBrowserKeyUnlocked(true) }
  const forgetBrowserKey = async () => { await forgetProtocolWorker(); setBrowserKeyUnlocked(false) }
  const authenticated = (session: string, recoveryCodes?: string[]) => {
    const storage = keep ? localStorage : sessionStorage
    const otherStorage = keep ? sessionStorage : localStorage
    otherStorage.removeItem(tokenKey)
    storage.setItem(tokenKey, session)
    if (!location.pathname.startsWith('/dashboard') && location.pathname !== '/pair') history.replaceState(null, '', '/dashboard')
    setError(''); setNotice(''); setPage(pageFromLocation())
    setEnvelopes(null)
    setToken(session)
    if (recoveryCodes?.length) setCodes(recoveryCodes)
  }

  if (!token) return <AuthShell build={buildInfo}><AuthForm error={error} keep={keep} setKeep={setKeep} onAuthenticated={authenticated} /></AuthShell>
  if (!me) {
    return (
      <AuthShell build={buildInfo}>
        <section className="auth-card" aria-live="polite">
          <div className="eyebrow">ACCOUNT ACCESS</div>
          {loadError ? (
            <>
              <h1>Could not load your account</h1>
              <p className="muted">{loadError}</p>
              <p className="muted">You are still signed in. Check your connection and try again.</p>
              <button className="primary" onClick={() => setAttempt(value => value + 1)}>Try again</button>
              <button className="link" onClick={() => void signOut()}>Sign out</button>
            </>
          ) : <><h1>Loading your account</h1><p className="muted">One moment...</p></>}
        </section>
      </AuthShell>
    )
  }
  if (me.state !== 'active') {
    const pending = me.state === 'pending'
    return (
      <AuthShell build={buildInfo}>
        <section className="auth-card">
          <div className="eyebrow">ACCOUNT ACCESS</div>
          <h1>{pending ? 'Awaiting approval' : me.state === 'suspended' ? 'Account suspended' : 'Account unavailable'}</h1>
          <p className="muted">{pending ? 'Your email and two-factor setup are complete. An administrator must approve this account before its data or sync services are available.' : 'This account cannot be used right now. Account data and sync services are unavailable.'}</p>
          <p className="muted">{me.email}</p>
          {pending && <p className="muted">This page checks for approval automatically.</p>}
          {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}
          <button className="primary" disabled={busy} onClick={() => void signOut()}>Sign out</button>
        </section>
      </AuthShell>
    )
  }

  const id = current[0]
  return (
    <div className="layout">
      <aside className="sidebar">
        <a className="brand" href="/dashboard"><img className="brand-mark" src="/vrcx-0-nanashi.png" alt="" /><span>RemoteSync</span></a>
        <nav aria-label="Dashboard">
          {pages.map(([pageId, Icon, label]) => <a key={pageId} href={pageId === 'home' ? '/dashboard' : `/dashboard/${pageId}`} aria-current={id === pageId ? 'page' : undefined}><Icon size={17} aria-hidden="true" /><span>{label}</span></a>)}
        </nav>
        <div className="profile">
          <span className="ellipsis" title={me.email}>{me.email}</span>
          <button title="Sign out" aria-label="Sign out" disabled={busy} onClick={() => void signOut()}><LogOut size={17} aria-hidden="true" /></button>
        </div>
      </aside>
      <main className="content">
        <header>
          <div><div className="eyebrow">ACCOUNT</div><h1>{current[2]}</h1></div>
          <span className={`pill ${me.state}`}>{me.state}</span>
        </header>
        <div aria-live="polite">
          {error && <div className="alert error">{error}</div>}
          {notice && <div className="alert">{notice}</div>}
        </div>
        {codes ? <RecoveryCodes codes={codes} onDone={() => setCodes(null)} /> : (
          <>
            {id === 'home' && <Overview me={me} keyUnlocked={browserKeyUnlocked} onForget={forgetBrowserKey} />}
            {id === 'devices' && <><Clients act={act} twofaMethod={me.twofaMethod} /><Tokens act={act} twofaMethod={me.twofaMethod} /></>}
            {id === 'pair' && <Pairing act={act} twofaMethod={me.twofaMethod} />}
            {id === 'data' && <YourData act={act} usageBytes={me.usageBytes} quotaBytes={me.quotaBytes} email={me.email} twofaMethod={me.twofaMethod} unlocked={browserKeyUnlocked} onDeleted={dropSession} />}
            {id === 'collections' && <Collections act={act} />}
            {id === 'security' && (
              <>
                <AccountSecurity email={me.email} twofaMethod={me.twofaMethod} act={act} onUpdated={async () => setMe(await request<Me>('/me'))} />
                <div className="security-grid">
                  <DeviceTransfer act={act} accountId={me.accountId} unlocked={browserKeyUnlocked} twofaMethod={me.twofaMethod} onReceived={() => setBrowserKeyUnlocked(true)} />
                  <Security me={me} act={act} setNotice={setNotice} showCodes={setCodes} onUnlock={unlockBrowserKey} onForget={forgetBrowserKey} envelopes={envelopes} setEnvelopes={setEnvelopes} />
                </div>
                <details className="card wide">
                  <summary className="advanced-summary">Advanced key recovery options</summary>
                  <p className="muted">Use these options if you cannot transfer your key from another signed-in device or unlock a saved envelope.</p>
                  <div className="security-grid">
                    <KeyUnlock act={act} unlocked={browserKeyUnlocked} onUnlock={unlockBrowserKey} onForget={forgetBrowserKey} />
                    <ChosenPassphrase act={act} accountId={me.accountId} twofaMethod={me.twofaMethod} onSaved={() => setNotice('Envelope saved. Remember this passphrase; it cannot be recovered.')} />
                  </div>
                </details>
              </>
            )}
            {id === 'collector' && <CollectorPage accountId={me.accountId} allowed={me.collectorAllowed} unlocked={browserKeyUnlocked} act={act} />}
            {id === 'admin' && <Admin act={act} available={me.adminAvailable} actorRole={me.role} actorId={me.accountId} />}
          </>
        )}
        <BuildFooter build={buildInfo} />
      </main>
    </div>
  )
}

const METHOD_LABELS: Record<string, string> = { totp: 'Authenticator app', email: 'Email code', recovery: 'Recovery code' }

function AuthForm({ error, keep, setKeep, onAuthenticated }: { error: string; keep: boolean; setKeep: (value: boolean) => void; onAuthenticated: (session: string, codes?: string[]) => void }) {
  const invited = location.pathname === '/invite' && location.hash.length > 1
  const [mode, setMode] = useState<'login' | 'signup'>(invited ? 'signup' : 'login')
  const [step, setStep] = useState<Step>(location.pathname === '/reset' && location.hash.length > 1 ? 'reset-password' : 'credentials')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [code, setCode] = useState('')
  const [method, setMethod] = useState('totp')
  const [challenge, setChallenge] = useState('')
  const [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null)
  const [methods, setMethods] = useState<string[]>(['totp', 'email', 'recovery'])
  const [info, setInfo] = useState('')
  const [formError, setFormError] = useState('')
  const [verifyCooldown, setVerifyCooldown] = useState(0)
  const [codeCooldown, setCodeCooldown] = useState(0)
  const [sending, setSending] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [captchaKey, setCaptchaKey] = useState(0)
  const [apiOrigin, setApiOrigin] = useState('')

  useEffect(() => {
    configPromise.then(config => setApiOrigin(config.apiOrigin)).catch(() => setFormError('The site configuration could not be loaded. Reload the page to try again.'))
    const hash = location.hash.slice(1)
    if (location.pathname !== '/verify' || !hash) return
    request<Challenge>('/auth/verify', { method: 'POST', body: JSON.stringify({ token: hash }) })
      .then(result => { setChallenge(result.challenge); setStep('enroll'); setInfo('Email confirmed. Set up two-factor authentication to finish.'); history.replaceState(null, '', '/verify') })
      .catch(() => setFormError('This confirmation link is invalid or has expired. Sign in to request a new one.'))
  }, [])
  useEffect(() => {
    if (verifyCooldown === 0 && codeCooldown === 0) return
    const timer = window.setTimeout(() => { setVerifyCooldown(value => Math.max(0, value - 1)); setCodeCooldown(value => Math.max(0, value - 1)) }, 1000)
    return () => window.clearTimeout(timer)
  }, [verifyCooldown, codeCooldown])

  const goTo = (next: Step) => { setStep(next); setCode(''); setInfo(''); setFormError('') }
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting) return
    setFormError('')
    setSubmitting(true)
    try {
      if (step === 'reset-password') {
        if (password !== repeat) throw new Error('The passwords do not match.')
        const result = await request<Challenge>('/auth/reset/finish', { method: 'POST', body: JSON.stringify({ token: location.hash.slice(1), password }) })
        setChallenge(result.challenge); setMethods(result.methods ?? ['totp', 'email', 'recovery']); setMethod(result.methods?.[0] ?? 'totp')
        setPassword(''); setRepeat(''); goTo('reset-verify'); history.replaceState(null, '', location.pathname)
        return
      }
      if (step === 'credentials') {
        if (mode === 'signup' && password !== repeat) throw new Error('The passwords do not match.')
        const altcha = String(new FormData(event.currentTarget).get('altcha') ?? '')
        if (!altcha) throw new Error('Complete the bot check before continuing.')
        setCaptchaKey(value => value + 1)
        if (mode === 'signup') {
          const result = await request<Challenge | undefined>('/auth/signup', { method: 'POST', body: JSON.stringify({ email, password, message: '', altcha, ...(invited ? { inviteToken: location.hash.slice(1) } : {}) }) })
          setPassword(''); setRepeat('')
          if (result?.challenge) { setChallenge(result.challenge); goTo('enroll') }
          else setInfo(`If ${email} can be used for a new account, a confirmation link is on its way. Open it to continue.`)
          return
        }
        const result = await request<Challenge>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password, altcha }) })
        setChallenge(result.challenge); setPassword('')
        if (result.next === 'verify-email') { goTo('waiting'); setVerifyCooldown(30); return }
        setMethods(result.methods ?? ['totp', 'email']); setMethod(result.methods?.[0] ?? 'totp')
        goTo(result.next === 'enroll' ? 'enroll' : 'verify')
        return
      }
      if (step === 'verify' || step === 'reset-verify') {
        const result = await request<{ session: string }>('/auth/login/2fa', { method: 'POST', body: JSON.stringify({ challenge, method, code: code.trim() }) })
        onAuthenticated(result.session)
        return
      }
      if (step === 'enroll') {
        if (method === 'email') {
          await request('/auth/enroll/email', { method: 'POST', body: JSON.stringify({ challenge }) })
          goTo('totp-confirm'); setInfo('We sent a code to your email address. Enter it below.')
          return
        }
        setTotp(await request<{ secret: string; uri: string }>('/auth/enroll/totp', { method: 'POST', body: JSON.stringify({ challenge }) }))
        goTo('totp-confirm')
        return
      }
      const result = await request<{ session: string; recoveryCodes: string[] }>(`/auth/enroll/${method === 'email' ? 'email' : 'totp'}/confirm`, { method: 'POST', body: JSON.stringify({ challenge, code: code.trim() }) })
      onAuthenticated(result.session, result.recoveryCodes)
    } catch (cause) {
      setFormError((cause as Error).message)
    } finally {
      setSubmitting(false)
    }
  }
  const send = async (path: string, done: () => void) => {
    setSending(true); setFormError('')
    try { await request(path, { method: 'POST', body: JSON.stringify({ challenge }) }); done() }
    catch (cause) { setFormError((cause as Error).message) }
    finally { setSending(false) }
  }
  const forgotPassword = async () => {
    setFormError(''); setInfo('')
    if (!email.trim()) return setFormError('Enter your email address above, then choose Forgot password.')
    await request('/auth/reset', { method: 'POST', body: JSON.stringify({ email }) }).catch(() => {})
    setInfo(`If an account exists for ${email}, a password reset link is on its way.`)
  }

  const confirming = step === 'totp-confirm'
  const verifying = step === 'verify' || step === 'reset-verify'
  const title = step === 'waiting' ? 'Verify your email' : verifying ? 'Two-factor verification' : step === 'enroll' ? 'Set up two-factor authentication' : confirming ? (method === 'email' ? 'Confirm your email code' : 'Confirm your authenticator') : step === 'reset-password' ? 'Choose a new password' : mode === 'login' ? 'Sign in' : 'Create account'
  const submitLabel = submitting ? 'Please wait...' : step === 'credentials' ? (mode === 'login' ? 'Continue' : 'Create account') : verifying ? 'Verify and sign in' : step === 'enroll' ? 'Continue' : step === 'reset-password' ? 'Set new password' : 'Confirm setup'
  const alerts = <div aria-live="polite">{(formError || error) && <div className="alert error">{formError || error}</div>}{info && <div className="alert">{info}</div>}</div>

  if (step === 'waiting') {
    return (
      <section className="auth-card">
        <div className="eyebrow">ACCOUNT ACCESS</div>
        <h1>{title}</h1>
        <p className="muted">This account has not verified its email address. Open the confirmation link sent to <strong>{email}</strong> to continue.</p>
        {alerts}
        <button className="primary" disabled={sending || verifyCooldown > 0} onClick={() => void send('/auth/verify/resend', () => { setVerifyCooldown(30); setInfo('Verification email sent.') })}>{sending ? 'Sending...' : verifyCooldown > 0 ? `Resend email in ${verifyCooldown}s` : 'Resend verification email'}</button>
        <button className="link" onClick={() => goTo('credentials')}>Back to sign in</button>
      </section>
    )
  }
  return (
    <section className="auth-card">
      <div className="eyebrow">ACCOUNT ACCESS</div>
      <h1>{title}</h1>
      <p className="muted">{invited && step === 'credentials' ? 'You were invited to RemoteSync. Create your account with the email address the invitation was sent to.' : 'Your RemoteSync account is separate from your VRChat account.'}</p>
      {alerts}
      {confirming && totp && method !== 'email' && <TotpSetup secret={totp.secret} uri={totp.uri} />}
      <form onSubmit={submit}>
        {step === 'credentials' && (
          <>
            <label>Email<input autoComplete="email" type="email" required autoFocus value={email} onChange={event => setEmail(event.target.value)} /></label>
            <label>Password<input autoComplete={mode === 'login' ? 'current-password' : 'new-password'} type="password" minLength={12} required value={password} onChange={event => setPassword(event.target.value)} />{mode === 'signup' && <small>At least 12 characters.</small>}</label>
            {mode === 'signup' && <label>Confirm password<input autoComplete="new-password" type="password" minLength={12} required value={repeat} onChange={event => setRepeat(event.target.value)} /></label>}
            {apiOrigin && <div className="captcha" key={captchaKey}><altcha-widget challenge={`${apiOrigin}/web/v1/auth/altcha/challenge`} name="altcha" /></div>}
            <label className="check-label"><input type="checkbox" checked={keep} onChange={event => setKeep(event.target.checked)} />Keep me signed in on this browser</label>
          </>
        )}
        {step === 'reset-password' && (
          <>
            <label>New password<input autoComplete="new-password" type="password" minLength={12} required autoFocus value={password} onChange={event => setPassword(event.target.value)} /><small>At least 12 characters.</small></label>
            <label>Confirm new password<input autoComplete="new-password" type="password" minLength={12} required value={repeat} onChange={event => setRepeat(event.target.value)} /></label>
          </>
        )}
        {(verifying || step === 'enroll') && (
          <label>{step === 'enroll' ? 'Choose a two-factor method' : 'Verification method'}
            <select value={method} onChange={event => { setMethod(event.target.value); setCode('') }}>
              {(step === 'enroll' ? ['totp', 'email'] : methods).map(item => <option key={item} value={item}>{METHOD_LABELS[item] ?? item}</option>)}
            </select>
          </label>
        )}
        {(verifying || confirming) && (
          <label>{method === 'recovery' ? 'Recovery code' : method === 'email' ? 'Email code' : '6-digit authenticator code'}
            <input type="text" name="code" autoFocus required autoComplete={method === 'recovery' ? 'off' : 'one-time-code'} inputMode={method === 'recovery' ? 'text' : 'numeric'} pattern={method === 'recovery' ? undefined : '[0-9]*'} value={code} onChange={event => setCode(event.target.value)} />
          </label>
        )}
        {verifying && method === 'email' && <button type="button" disabled={sending || codeCooldown > 0} onClick={() => void send('/auth/login/email-code', () => { setCodeCooldown(30); setInfo('Code sent. Check your email.') })}>{sending ? 'Sending...' : codeCooldown > 0 ? `Send code again in ${codeCooldown}s` : 'Send code to email'}</button>}
        <button className="primary" disabled={submitting}>{submitLabel}</button>
      </form>
      {step === 'credentials' ? (
        <>
          {mode === 'login' && <button className="link" onClick={() => void forgotPassword()}>Forgot password?</button>}
          <button className="link" onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setInfo(''); setFormError(''); setRepeat('') }}>{mode === 'login' ? 'Need an account? Sign up' : 'Already have an account? Sign in'}</button>
        </>
      ) : <button className="link" onClick={() => goTo('credentials')}>Back to sign in</button>}
    </section>
  )
}

function Overview({me,keyUnlocked,onForget}:{me:Me,keyUnlocked:boolean,onForget:()=>Promise<void>}) { const usage=me.usageBytes;const pct=me.quotaBytes?Math.min(100,usage/me.quotaBytes*100):0;return <>{me.recoveryCodesLeft<=2&&<div className="alert error">{me.recoveryCodesLeft===0?'No recovery codes remain.':`Only ${me.recoveryCodesLeft} recovery ${me.recoveryCodesLeft===1?'code remains':'codes remain'}.`} Generate a fresh set under <a href="/dashboard/security">Security</a>.</div>}<div className="hero"><div><div className="eyebrow">REMOTESYNC</div><h2>{me.syncAllowed?'Your account is ready':'Sync is disabled for this account'}</h2><p>{me.syncAllowed?'RemoteSync keeps your VRCX-0-Nanashi history encrypted on the server and available to your devices. Pair the app under Pair device, then unlock your key under Security to read history here.':'An administrator has turned off history sync for this account. Shared collections still work.'}</p></div><Activity size={48} aria-hidden="true"/></div><div className="cards"><article className="card"><div className="card-title">Storage usage</div><strong>{formatBytes(usage)}</strong><div className="progress"><i style={{width:`${pct}%`}}/></div><small>{me.quotaBytes?`of ${formatBytes(me.quotaBytes)} limit`:'No storage limit'}</small></article><article className="card"><div className="card-title">RemoteSync access</div><strong>{me.syncAllowed?'Enabled':'Disabled'}</strong><small>{me.collectorAllowed?'Collector access is allowed':'Collector access is disabled'}</small></article><article className="card"><div className="card-title">Security</div><strong>{me.twofaMethod==='totp'?'Authenticator app':me.twofaMethod==='email'?'Email codes':'Not set up'}</strong><small>{me.recoveryCodesLeft} recovery codes remaining</small></article></div>{keyUnlocked&&<div className="key-status">Sync key is unlocked in this tab's protocol Worker. <button onClick={()=>void onForget()}>Forget key</button></div>}<HistoryBrowser unlocked={keyUnlocked} accountId={me.accountId}/></>}


function Security({me,act,setNotice,showCodes,onUnlock,onForget,envelopes,setEnvelopes}:{me:Me,act:(f:()=>Promise<void>)=>Promise<void>,setNotice:(s:string)=>void,showCodes:(codes:string[])=>void,onUnlock:(key:string)=>Promise<void>,onForget:()=>Promise<void>,envelopes:any[]|null,setEnvelopes:(value:any[]|null)=>void}) {
  const verification=useReauth(me.twofaMethod)
  const [syncKey,setSyncKey]=useState(''); const [label,setLabel]=useState('Browser recovery'); const [newPassphrase,setNewPassphrase]=useState(''); const [unlockId,setUnlockId]=useState(''); const [unlockPassphrase,setUnlockPassphrase]=useState(''); const [keyUnlocked,setKeyUnlocked]=useState(false); const [savedPassphrase,setSavedPassphrase]=useState('')
  const reauth=verification.confirm
  const refreshEnvelopes=async()=>{await reauth();setEnvelopes(await request<any[]>('/envelopes'))}
  useEffect(()=>{let active=true;request<any[]>('/envelopes').then(value=>{if(active)setEnvelopes(value)}).catch(()=>{});return()=>{active=false}},[setEnvelopes])
  return <><article className="card"><h2>Recovery codes</h2><p>You have {me.recoveryCodesLeft} recovery {me.recoveryCodesLeft===1?'code':'codes'} remaining.</p><p className="muted">Generating a new set replaces the old codes. Uses the verification code entered at the top of this page.</p><button className="primary" disabled={!verification.ready} onClick={()=>act(async()=>{await reauth();const data=await request<{recoveryCodes:string[]}>('/recovery-codes',{method:'POST'});showCodes(data.recoveryCodes)})}>Generate new codes</button></article>
    <article className="card"><h2>Stored key envelopes</h2><p className="muted">Create an encrypted browser recovery envelope from your 64-character sync key. The passphrase is generated on this device and never sent to the server. Save both the passphrase and key somewhere safe.</p>
      <label>Sync key (64 hex characters or rss1 recovery string)<input type="password" autoComplete="off" value={syncKey} onChange={e=>setSyncKey(e.target.value)}/></label>
      <label>Envelope label<input maxLength={64} value={label} onChange={e=>setLabel(e.target.value)}/></label>
      <div className="actions"><button onClick={()=>setNewPassphrase(generatePassphrase())}>Generate passphrase</button><button onClick={()=>void generateWordPassphrase().then(setNewPassphrase)}>Generate 7 words</button>{newPassphrase&&<code className="secret-code">{newPassphrase}</code>}</div>
      {newPassphrase&&<button className="primary" onClick={()=>act(async()=>{const normalizedKey=normalizeSyncKey(syncKey);await reauth();const envelope=await createPassphraseEnvelope(me.accountId,normalizedKey,label,newPassphrase);await request('/envelopes',{method:'POST',body:JSON.stringify(envelope)});await onUnlock(normalizedKey);setKeyUnlocked(true);setSyncKey('');setEnvelopes(await request<any[]>('/envelopes'));setSavedPassphrase(newPassphrase);setNotice('Envelope saved.');setNewPassphrase('')})}>Encrypt and save envelope</button>}
      <p className="muted">Saving, loading and deleting envelopes use the verification code entered at the top of this page.</p>
      <p className="muted">Passphrase envelopes use Argon2id (256 MiB, 3 passes) and XChaCha20-Poly1305. A wrong passphrase or modified envelope fails to decrypt.</p>
      <button disabled={!verification.ready} onClick={()=>act(refreshEnvelopes)}>Load stored envelopes</button>{envelopes&&<div className="envelope-list">{envelopes.length===0?<p className="muted">No stored envelopes.</p>:envelopes.map((item:any)=><div className="envelope-row" key={item.envelopeId}><span><b>{item.label||'Unnamed envelope'}</b><small>{item.kind==='passkey-prf'?'Legacy passkey envelope · unsupported':item.kind} · Added {date(item.createdAtMs)}</small></span><div className="actions">{item.kind==='passphrase'&&<button onClick={()=>setUnlockId(item.envelopeId)}>Unlock</button>}<button className="danger" onClick={()=>{if(confirm(`Delete "${item.label||'this envelope'}"?`))act(async()=>{await reauth();await request(`/envelopes/${encodeURIComponent(item.envelopeId)}`,{method:'DELETE'});setEnvelopes(await request<any[]>('/envelopes'))})}}>Delete</button></div></div>)}</div>}
      {unlockId&&<div className="unlock-box"><label>Envelope passphrase<input type="password" autoComplete="off" value={unlockPassphrase} onChange={e=>setUnlockPassphrase(e.target.value)}/></label><button className="primary" onClick={()=>act(async()=>{await reauth();const envelope=await request<any>(`/envelopes/${encodeURIComponent(unlockId)}`);const key=await openPassphraseEnvelope(me.accountId,envelope,unlockPassphrase);await onUnlock(key);setKeyUnlocked(true);setUnlockPassphrase('')})}>Decrypt sync key</button></div>}
      {savedPassphrase&&<div className="secret-box"><b>Store this passphrase now</b><code className="secret-code">{savedPassphrase}</code><small>It unlocks the envelope you just saved and cannot be recovered or shown again.</small><div className="button-row"><button onClick={()=>void navigator.clipboard.writeText(savedPassphrase)}>Copy</button><button onClick={()=>setSavedPassphrase('')}>I saved it</button></div></div>}
      {keyUnlocked&&<div className="alert">Sync key is unlocked in the protocol Worker. The page does not retain the decrypted key. <button onClick={()=>void onForget().then(()=>setKeyUnlocked(false))}>Forget key</button></div>}
      {envelopes&&envelopes.length>0&&<button className="danger" onClick={()=>{if(confirm('Delete every stored key envelope?'))act(async()=>{await reauth();await request('/envelopes',{method:'DELETE'});setEnvelopes([])})}}>Delete all envelopes</button>}</article></>
}

function Admin({act,available,actorRole,actorId}:{act:(f:()=>Promise<void>)=>Promise<void>,available:boolean,actorRole:string,actorId:string}) {
  const [accounts,setAccounts]=useState<any[]>([]); const [code,setCode]=useState(''); const [unlocked,setUnlocked]=useState(false)
  const [settings,setSettings]=useState<any>(null); const [audit,setAudit]=useState<any[]>([]); const [inviteEmail,setInviteEmail]=useState(''); const [accountQuery,setAccountQuery]=useState(''); const [stateFilter,setStateFilter]=useState('all')
  const refresh=async()=>{const [a,s,l]=await Promise.all([request<any[]>('/admin/accounts'),request<any>('/admin/settings'),request<any[]>('/admin/audit')]);setAccounts(a);setSettings({...s,defaultQuota:s.defaultQuota==null?'unlimited':String(s.defaultQuota)});setAudit(l)}
  const saveSettings=()=>act(async()=>{await request('/admin/settings',{method:'PUT',body:JSON.stringify(settings)});await refresh()})
  const updateAccount=(a:any,path:string,body:any)=>act(async()=>{await request(`/admin/accounts/${a.accountId}/${path}`,{method:'PUT',body:JSON.stringify(body)});await refresh()})
  return <>
    <section className="card wide"><div className="section-heading"><div><h2>Administration</h2><p className="muted">Actions require an enrolled authenticator and recent TOTP verification.</p></div>{unlocked&&<button onClick={()=>act(refresh)}>Refresh</button>}</div>
      {!available?<div className="alert">Set up an authenticator app for this account before using the admin area. Email codes and recovery codes cannot unlock admin privileges.</div>:!unlocked?<div className="reauth"><label>Authenticator code<input type="text" name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" value={code} onChange={e=>setCode(e.target.value)}/></label><button className="primary" onClick={()=>act(async()=>{await request('/reauth',{method:'POST',body:JSON.stringify({method:'totp',code})});setCode('');setUnlocked(true);await refresh()})}>Unlock administration</button></div>:<>
      <div className="cards admin-cards">
        <article className="card"><h2>Registration and defaults</h2>{settings&&<><label>Registration<select value={settings.registration} onChange={e=>setSettings({...settings,registration:e.target.value})}><option value="request">Request approval</option><option value="closed">Closed</option></select></label><label>Default quota (for example 5 GiB)<input value={String(settings.defaultQuota)} placeholder="unlimited" onChange={e=>setSettings({...settings,defaultQuota:e.target.value||'unlimited'})}/></label><label className="check-label"><input type="checkbox" checked={settings.collectorDefaultAllowed} onChange={e=>setSettings({...settings,collectorDefaultAllowed:e.target.checked})}/> Allow collector by default</label><button className="primary" onClick={saveSettings}>Save settings</button></>}</article>
        <article className="card"><h2>Invite an account</h2><p className="muted">Sends a one-time sign-up link to this email address.</p><label>Email<input type="email" value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)}/></label><button className="primary" disabled={!inviteEmail} onClick={()=>act(async()=>{await request('/admin/invites',{method:'POST',body:JSON.stringify({email:inviteEmail})});setInviteEmail('');await refresh()})}>Send invitation</button></article>
      </div>
      {settings&&<p className="muted admin-meta">API {settings.apiOrigin} · Website origins: {(settings.websiteOrigins||[]).join(', ')} · Commit {settings.commit||'unknown'}</p>}
      <h2 className="admin-subhead">Accounts ({accounts.length})</h2><div className="admin-controls"><label>Find account<input type="search" value={accountQuery} onChange={e=>setAccountQuery(e.target.value)} placeholder="Email or account ID"/></label><label>State<select value={stateFilter} onChange={e=>setStateFilter(e.target.value)}><option value="all">All states</option><option value="pending">Pending</option><option value="active">Active</option><option value="suspended">Suspended</option></select></label></div><div className="admin-account-list">{accounts.filter((a:any)=>(stateFilter==='all'||a.state===stateFilter)&&(`${a.email} ${a.accountId}`.toLowerCase().includes(accountQuery.toLowerCase()))).map((a:any)=><AdminAccount key={a.accountId} account={a} actorRole={actorRole} actorId={actorId} update={updateAccount} act={act} refresh={refresh}/>)}</div>
      <section className="card wide"><div className="section-heading"><div><h2>Audit log</h2><p className="muted">Recent administrative actions.</p></div></div>{audit.length===0?<div className="empty-state">No audit entries.</div>:<div className="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target account</th></tr></thead><tbody>{audit.map((entry:any,i:number)=><tr key={`${entry.atMs}-${i}`}><td>{date(entry.atMs)}</td><td>{entry.actor}</td><td>{entry.action}</td><td>{entry.targetAccount||'-'}</td></tr>)}</tbody></table></div>}</section>
      </>}</section>
  </>
}

function AdminAccount({account:a,actorRole,actorId,update,act,refresh}:{account:any,actorRole:string,actorId:string,update:(a:any,path:string,body:any)=>Promise<void>,act:(f:()=>Promise<void>)=>Promise<void>,refresh:()=>Promise<void>}) {
  const [quota,setQuota]=useState(a.quotaBytes==null?'':String(a.quotaBytes)); const [vaults,setVaults]=useState(String(a.maxVaults)); const [confirmEmail,setConfirmEmail]=useState('')
  const protectedOwner=a.role==='owner'; const canManage=!protectedOwner&&(a.role!=='admin'||actorRole==='owner')
  const canManageSettings=canManage||(a.accountId===actorId&&a.role==='admin')||(actorRole==='owner'&&a.role==='owner')
  return <article className="card admin-account"><div className="section-heading"><div><b>{a.email}</b><div className="muted">{a.state} · {a.role} · {formatBytes(a.usageBytes)} / {a.quotaBytes!=null?formatBytes(a.quotaBytes):'unlimited'} · {a.maxVaults} vaults · Created {date(a.createdAtMs)}</div></div><div className="actions">{a.state==='pending'&&<><button onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/approve`,{method:'POST'});await refresh()})}>Approve</button><button className="danger" onClick={()=>{if(confirm(`Deny the account request from ${a.email}?`))void act(async()=>{await request(`/admin/accounts/${a.accountId}/deny`,{method:'POST'});await refresh()})}}>Deny</button></>}{canManage&&a.state!=='pending'&&<button onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/${a.state==='suspended'?'resume':'suspend'}`,{method:'POST'});await refresh()})}>{a.state==='suspended'?'Resume':'Suspend'}</button>}</div></div>
    {a.signupMessage&&<p className="muted">Signup request: {a.signupMessage}</p>}
    {canManage&&<div className="admin-controls">{actorRole==='owner'&&<><button onClick={()=>update(a,'role',{role:a.role==='admin'?'user':'admin'})}>{a.role==='admin'?'Remove admin':'Make admin'}</button><button onClick={()=>{if(confirm(`Reset two-factor authentication for ${a.email}?`))void act(async()=>{await request(`/admin/accounts/${a.accountId}/reset-2fa`,{method:'POST'});await refresh()})}}>Reset 2FA</button><button className="danger" onClick={()=>{if(confirm(`Permanently delete ${a.email} and all of its data?`))act(async()=>{await request(`/admin/accounts/${a.accountId}`,{method:'DELETE'});await refresh()})}}>Delete account</button></>}</div>}
    {canManageSettings&&<div className="admin-controls"><label>Quota in bytes (empty for unlimited)<input inputMode="numeric" value={quota} onChange={e=>setQuota(e.target.value)} placeholder="unlimited"/></label><label>Maximum vaults<input type="number" min="1" max="1000" value={vaults} onChange={e=>setVaults(e.target.value)}/></label><button onClick={()=>update(a,'limits',{quota:quota?`${quota} B`:'unlimited',maxVaults:Number(vaults)})}>Save limits</button><button onClick={()=>update(a,'collector',{allowed:!a.collectorAllowed})}>{a.collectorAllowed?'Disable':'Enable'} collector</button></div>}
    {canManageSettings&&a.syncAllowed&&<div className="sync-disable"><p className="muted">Disabling sync permanently deletes this account's encrypted server data.</p><label>Type {a.email} to confirm<input value={confirmEmail} onChange={e=>setConfirmEmail(e.target.value)}/></label><button className="danger" disabled={confirmEmail!==a.email} onClick={()=>act(async()=>{await request(`/admin/accounts/${a.accountId}/sync`,{method:'PUT',body:JSON.stringify({allowed:false,confirmEmail})});setConfirmEmail('');await refresh()})}>Disable sync and delete data</button></div>}
    {canManageSettings&&!a.syncAllowed&&<button onClick={()=>update(a,'sync',{allowed:true})}>Enable RemoteSync</button>}
  </article>
}
function date(value:number){return value?new Date(value).toLocaleString():'-'}
function BuildFooter({ build }: { build: Build | null }) {
  return <footer className="site-footer">{build ? `Build ${build.version}, manifest SHA-256 ${build.manifestSha256.slice(0, 16)}` : 'RemoteSync'} · <a href="/">Home</a> · <a href="/collections">Collections</a> · <a href="/themes">Themes</a> · <a href="/privacy">Privacy</a> · <a href="/licenses">Licenses</a></footer>
}
