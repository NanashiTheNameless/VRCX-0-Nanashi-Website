// ==UserScript==
// @name         VRCX-0-Nanashi website check
// @namespace    https://github.com/NanashiTheNameless/VRCX-0-Nanashi-Website
// @version      1.0.2
// @description  Checks in your own browser that the RemoteSync website runs the official unmodified code and whether it is the official instance. Shows the result at the top of the page. It never blocks the page. Install it from the source repository, not from the website it checks.
// @match        https://vrcx.namelessnanashi.dev/*
// @run-at       document-start
// @grant        none
// @noframes
// ==/UserScript==

(() => {
  'use strict'

  const CODE_KEYS = ['MCowBQYDK2VwAyEAZFMdbH5lgJK5hR3tqn3VwFJEZj7qXncSFgpV88pfKsk=']
  const INSTANCE_KEYS = ['MCowBQYDK2VwAyEA6HY7SO+vpZsdC/xzMWG9DSD9uWRVj7mW6mkBqHu0bmk=']
  const UNSIGNED_PATHS = new Set(['config.json', 'build.json', 'instance.json', 'instance.sig', 'web-manifest.json', 'web-manifest.sig'])
  const CHECKED_TYPES = /\.(js|mjs|css|wasm)$/

  const bytes = text => Uint8Array.from(atob(text.trim()), character => character.charCodeAt(0))
  const hex = buffer => Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, '0')).join('')
  const sha256 = async data => hex(await crypto.subtle.digest('SHA-256', data))

  async function signedBy(keys, message, signature) {
    for (const key of keys) {
      const imported = await crypto.subtle.importKey('spki', bytes(key), { name: 'Ed25519' }, false, ['verify'])
      if (await crypto.subtle.verify({ name: 'Ed25519' }, imported, signature, message)) return true
    }
    return false
  }

  async function load(path, cache) {
    const requestPath = path === 'index.html' ? '/' : path
    const response = await fetch(new URL(requestPath, location.origin), {
      cache,
      credentials: 'omit',
      redirect: 'error',
    })
    if (response.status === 404) return null
    if (!response.ok) throw new Error(`${path} returned ${response.status}`)
    return new Uint8Array(await response.arrayBuffer())
  }

  async function checkCode() {
    const manifestBytes = await load('/web-manifest.json', 'no-store')
    const signature = await load('/web-manifest.sig', 'no-store')
    if (!manifestBytes || !signature) return { ok: false, title: 'This website is not running the official published code', detail: 'It carries no signature for its files. Code here could capture your encryption key or sign-in if you enter them.' }
    if (!(await signedBy(CODE_KEYS, manifestBytes, bytes(new TextDecoder().decode(signature))))) {
      return { ok: false, title: 'The website code has been modified', detail: 'Its file list is not signed by the VRCX-0-Nanashi maintainer. Do not enter your encryption key or sign in here.' }
    }
    const manifest = JSON.parse(new TextDecoder().decode(manifestBytes))
    const expected = new Map(manifest.files.map(file => [file.path, file.sha256.toLowerCase()]))

    if (document.querySelector('script:not([src])')) return { ok: false, title: 'The website code has been modified', detail: 'The page contains a script that is not part of the signed release.' }
    const used = new Set(['index.html'])
    for (const element of document.querySelectorAll('script[src], link[rel~="stylesheet"][href]')) used.add(new URL(element.src || element.href, location.href).href)
    for (const entry of performance.getEntriesByType('resource')) used.add(entry.name)

    for (const item of used) {
      const url = new URL(item, location.origin)
      const path = url.pathname.replace(/^\//, '')
      if (url.origin !== location.origin) {
        if (CHECKED_TYPES.test(url.pathname)) return { ok: false, title: 'The website code has been modified', detail: `The page loaded code from ${url.origin}, which is not part of the signed release.` }
        continue
      }
      if (UNSIGNED_PATHS.has(path) || (path !== 'index.html' && !CHECKED_TYPES.test(path))) continue
      if (!expected.has(path)) return { ok: false, title: 'The website code has been modified', detail: `The page loaded ${path}, which is not part of the signed release.` }
      const body = await load(`/${path}`, path === 'index.html' ? 'no-store' : 'force-cache')
      if (!body || (await sha256(body)) !== expected.get(path)) return { ok: false, title: 'The website code has been modified', detail: `${path} differs from the signed release. Do not enter your encryption key or sign in here.` }
    }
    return { ok: true, title: `Official unmodified code (version ${manifest.version}, commit ${String(manifest.sourceCommit).slice(0, 12)})` }
  }

  async function checkInstance() {
    const statement = await load('/instance.json', 'no-store')
    const signature = await load('/instance.sig', 'no-store')
    if (!statement || !signature) return { ok: false, title: 'Not the official VRCX-0-Nanashi instance', detail: 'This server is run by someone else. Its operator can see your account email, device addresses, and when you sync, but cannot read your history.' }
    const invalid = { ok: false, title: 'This server presents an official-instance signature that is not valid', detail: 'Treat it as run by an unknown party that tried to look official.' }
    if (!(await signedBy(INSTANCE_KEYS, statement, bytes(new TextDecoder().decode(signature))))) return invalid
    const parsed = JSON.parse(new TextDecoder().decode(statement))
    if (parsed.v !== 1 || parsed.websiteOrigin !== location.origin || !(Date.now() <= parsed.expiresAtMs)) return invalid
    return { ok: true, title: 'Official VRCX-0-Nanashi instance' }
  }

  function show(results, failure) {
    const host = document.createElement('div')
    const shadow = host.attachShadow({ mode: 'closed' })
    const bar = document.createElement('div')
    const good = !failure && results.every(result => result.ok)
    Object.assign(bar.style, { position: 'fixed', top: '0', left: '0', right: '0', zIndex: '2147483647', padding: '6px 12px', font: '12px/1.5 monospace', color: '#101114', background: good ? '#92d9ad' : '#ffcf7a', boxShadow: '0 1px 4px rgba(0,0,0,.4)' })
    const lines = failure ? [{ title: 'The website check could not finish', detail: failure }] : results
    for (const result of lines) {
      const line = document.createElement('div')
      const title = document.createElement('b')
      title.textContent = `${result.ok ? 'Passed' : 'Warning'}: ${result.title}`
      line.append(title)
      if (result.detail) line.append(` ${result.detail}`)
      bar.append(line)
    }
    const close = document.createElement('button')
    close.textContent = 'Hide'
    Object.assign(close.style, { position: 'absolute', top: '4px', right: '8px', font: 'inherit', cursor: 'pointer' })
    close.addEventListener('click', () => host.remove())
    bar.append(close)
    shadow.append(bar)
    document.documentElement.append(host)
    if (good) setTimeout(() => host.remove(), 8000)
  }

  async function run() {
    try {
      show([await checkCode(), await checkInstance()])
    } catch (error) {
      show([], `${error instanceof Error ? error.message : error}. Nothing is known about this website; do not enter your encryption key until the check passes.`)
    }
  }

  if (document.readyState === 'complete') void run()
  else window.addEventListener('load', () => void run())
})()
