/**
 * @deepseek-ai/dsh-cookie-sentinel
 *
 * Desktop launches bind the Host Web server to a fresh random loopback port.
 * `@deepseek-ai/dsh-client-connection` names its browser-session cookie after
 * the request authority (`dsh-auth-<sha256(authority)>`), and the authority
 * includes that port. Cookies, however, are stored per host and ignore the
 * port, so every launch adds another `dsh-auth-…` cookie on 127.0.0.1 while
 * none of the previous ones expire (30 days). Once the accumulated `Cookie`
 * header passes Node's 16 KiB parser limit, the Host answers 431 before any
 * route runs and Electron's welcome transport reports
 * "desktop welcome: Web authentication failed".
 *
 * This Host bundle repairs both halves of that loop:
 *
 * 1. It raises the live `http.Server` header limit (new connections pick the
 *    value up) so the one request that carries the already-broken jar can
 *    reach the authentication route instead of dying in the parser.
 * 2. It wraps `connection.authorizeIndex` and inspects the response the
 *    authentication route writes. When that response mints a new
 *    `dsh-auth-…` cookie (the launch-token exchange), it appends `Set-Cookie`
 *    deletions for every other `dsh-auth-…` cookie the request carried. The
 *    Electron session stores them, so the jar shrinks back to the single
 *    current cookie and every later launch starts clean.
 *
 * Pruning is therefore driven by the cookie the Host actually mints, never by
 * a guessed name: if a later DSH version changes the cookie spelling, this
 * bundle simply stops deleting anything instead of deleting the valid cookie.
 *
 * The plugin never throws from `apply`: the Desktop shell treats a failed
 * startup entry as fatal, and a guard that can prevent a broken start must
 * never become the reason the app cannot start.
 */
import { appendFileSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Stable Loader identity. */
export const name = 'dsh-cookie-sentinel'
/** Both halves only make sense with a bound Web carrier and its auth owner. */
export const inject = ['webServer', 'connection']

/** The generated suffix is an unpadded SHA-256 base64url digest (43 chars). */
const COOKIE_NAME = /^dsh-auth-[A-Za-z0-9_-]{43}$/u
/** Same default the Host already uses today; kept as fallback for bad config. */
const DEFAULT_MAX_HEADER_SIZE = 128 * 1024
const MIN_MAX_HEADER_SIZE = 16 * 1024
const MAX_MAX_HEADER_SIZE = 1024 * 1024
/** Bound one response's cleanup list; one pruning round is normally < 200. */
const MAX_PRUNE_PER_RESPONSE = 1024
/** Wait for the `webServer` class plugin to create its server; 25 ms x 400 = 10 s. */
const HEADER_LIMIT_RETRY_MS = 25
const HEADER_LIMIT_RETRY_ATTEMPTS = 400
/** Marker preventing a second wrap of the same response. */
const PRUNED = Symbol('dsh-cookie-sentinel.pruned')

/** @param {unknown} value */
function headerLimit(value) {
  if (value === undefined) return DEFAULT_MAX_HEADER_SIZE
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= MIN_MAX_HEADER_SIZE && value <= MAX_MAX_HEADER_SIZE) return value
  return DEFAULT_MAX_HEADER_SIZE
}

/**
 * Best-effort audit line. Host stdout is not persisted by the Desktop shell,
 * so a one-line log makes the repair observable after the next restart.
 * @param {string} line
 */
function note(line) {
  try {
    const directory = join(homedir(), '.dsh')
    mkdirSync(directory, { recursive: true })
    appendFileSync(join(directory, 'cookie-sentinel.log'), `${new Date().toISOString()} ${line}\n`, 'utf8')
  } catch {
    // Observability is optional; never affect the request or startup.
  }
}

/** @param {unknown} value */
function cookieNameOf(value) {
  if (typeof value !== 'string') return undefined
  const at = value.indexOf('=')
  if (at === -1) return undefined
  const cookie = value.slice(0, at).trim()
  return COOKIE_NAME.test(cookie) ? cookie : undefined
}

/**
 * `dsh-auth-…` names carried by one request, in header order.
 * @param {string | string[] | undefined} cookieHeader
 */
function requestCookieNames(cookieHeader) {
  const raw = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader
  const names = new Set()
  if (typeof raw !== 'string' || raw === '') return names
  for (const pair of raw.split(';')) {
    const cookie = cookieNameOf(pair)
    if (cookie !== undefined) names.add(cookie)
    if (names.size >= MAX_PRUNE_PER_RESPONSE) break
  }
  return names
}

/**
 * `dsh-auth-…` names minted by the response's own `Set-Cookie` headers.
 * @param {readonly string[]} setCookie
 */
function mintedCookieNames(setCookie) {
  const names = new Set()
  for (const value of setCookie) {
    const cookie = cookieNameOf(value)
    if (cookie !== undefined) names.add(cookie)
  }
  return names
}

/** Deletion header for one host-only session cookie (same Path as the mint). */
function deletionFor(cookie) {
  return `${cookie}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
}

/**
 * Append deletion `Set-Cookie` headers to the response the index authentication
 * writes. Deletions are emitted only when the same response mints a session
 * cookie, and never for a name that response mints.
 * @param {import('node:http').ServerResponse} response
 * @param {Set<string>} candidates - `dsh-auth-…` names carried by the request.
 * @param {{ info: (message: string) => void }} [log]
 * @param {string} host
 */
function installPruning(response, candidates, log, host) {
  if (candidates.size === 0 || response[PRUNED] === true) return
  response[PRUNED] = true
  const original = response.writeHead
  let applied = false
  response.writeHead = function writeHeadWithCookiePruning(statusCode, statusMessage, headers) {
    if (applied) return original.apply(this, arguments)
    applied = true
    let message
    /** @type {Record<string, string | readonly string[]> | undefined} */
    let source
    if (typeof statusMessage === 'string') {
      message = statusMessage
      source = headers
    } else {
      source = statusMessage
    }
    /** @type {Record<string, string | string[]>} */
    const merged = {}
    /** @type {string[]} */
    const setCookie = []
    const entries = source === undefined || source === null ? [] : Array.isArray(source) ? source : Object.entries(source)
    for (const [key, value] of entries) {
      if (String(key).toLowerCase() === 'set-cookie') {
        if (Array.isArray(value)) setCookie.push(...value)
        else if (typeof value === 'string') setCookie.push(value)
        continue
      }
      merged[key] = value
    }
    const minted = mintedCookieNames(setCookie)
    if (minted.size > 0) {
      const stale = [...candidates].filter((cookie) => !minted.has(cookie))
      if (stale.length > 0) {
        for (const cookie of stale) setCookie.push(deletionFor(cookie))
        try {
          log?.info(`pruned ${String(stale.length)} stale browser-session cookie(s) for ${host}`)
        } catch {
          // A logging failure must not break the response that carries the repair.
        }
        note(`pruned=${String(stale.length)} host=${host}`)
      }
    }
    if (setCookie.length > 0) merged['set-cookie'] = setCookie
    return message === undefined
      ? original.call(this, statusCode, merged)
      : original.call(this, statusCode, message, merged)
  }
}

/**
 * Raise the live server's per-connection parser limit. The `webServer` service
 * is provided before its class plugin finishes `[Service.init]`, so the server
 * object may not exist yet on the first attempt; retry briefly.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{ info: (message: string) => void, warn: (message: string) => void } | undefined} log
 * @param {number} limit
 */
function installHeaderLimit(ctx, log, limit) {
  let disposed = false
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer
  let attempts = 0
  const attempt = () => {
    timer = undefined
    if (disposed) return
    let server
    try {
      server = ctx.webServer.server
    } catch (error) {
      log?.warn(`cannot read the Host HTTP server: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (server !== undefined && server !== null) {
      try {
        const previous = server.maxHeaderSize
        server.maxHeaderSize = limit
        if (server.maxHeaderSize !== limit) {
          log?.warn(`could not raise the Host header limit above its current value (${String(server.maxHeaderSize)})`)
          return
        }
        try {
          ctx.effect(() => () => {
            if (server.maxHeaderSize === limit) server.maxHeaderSize = previous
          }, 'dsh-cookie-sentinel: header limit')
        } catch (error) {
          log?.warn(`could not register the header limit cleanup: ${error instanceof Error ? error.message : String(error)}`)
        }
        log?.info(`Host header limit is ${String(limit)} bytes`)
        note(`ready headerLimit=${String(limit)}`)
      } catch (error) {
        log?.warn(`could not raise the Host header limit: ${error instanceof Error ? error.message : String(error)}`)
      }
      return
    }
    attempts += 1
    if (attempts >= HEADER_LIMIT_RETRY_ATTEMPTS) {
      log?.warn('Host HTTP server did not appear in time; cookie pruning stays active without extra header headroom')
      return
    }
    timer = setTimeout(attempt, HEADER_LIMIT_RETRY_MS)
    timer.unref?.()
  }
  try {
    ctx.effect(() => () => {
      disposed = true
      if (timer !== undefined) clearTimeout(timer)
    }, 'dsh-cookie-sentinel: header limit retry')
  } catch (error) {
    log?.warn(`could not register the header limit retry cleanup: ${error instanceof Error ? error.message : String(error)}`)
  }
  attempt()
}

/**
 * Install the repair on the live Host.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{ maxHeaderSize?: unknown } | undefined} config
 */
export function apply(ctx, config) {
  /** @type {ReturnType<typeof ctx.logger> | undefined} */
  let log
  try {
    if (typeof ctx.logger === 'function') log = ctx.logger('dsh-cookie-sentinel')
  } catch {
    // Logging is optional; a context that refuses the read must not stop the repair.
  }
  const limit = headerLimit(config?.maxHeaderSize)
  note('loaded')

  // 1. Headroom: the 70-cookie jar that already exists must survive one more
  //    request before pruning can shrink it. `maxHeaderSize` is read for each
  //    new connection, so setting it on the live server covers the next launch.
  //    A consumer of `webServer` may run while the class plugin is still in its
  //    own `[Service.init]`, so the server object can appear a few ticks later;
  //    retry briefly instead of leaving the broken parser in place.
  try {
    installHeaderLimit(ctx, log, limit)
  } catch (error) {
    log?.warn(`could not raise the Host header limit: ${error instanceof Error ? error.message : String(error)}`)
  }

  // 2. Pruning: only the index authentication route mints/refreshes the
  //    browser-session cookie, so it is the one place where the stale set is
  //    visible together with the authority that replaces it.
  try {
    const connection = ctx.connection
    const originalAuthorizeIndex = connection.authorizeIndex
    if (typeof originalAuthorizeIndex !== 'function') {
      log?.warn('connection.authorizeIndex is unavailable; cookie pruning is disabled')
      return
    }
    /** @this {import('@deepseek-ai/dsh-client-connection').HostConnectionService} */
    function authorizeIndexWithCookiePruning(request, response) {
      try {
        const candidates = requestCookieNames(request.headers.cookie)
        const host = typeof request.headers.host === 'string' ? request.headers.host : 'unknown host'
        installPruning(response, candidates, log, host)
      } catch (error) {
        log?.warn(`cookie pruning inspection failed: ${error instanceof Error ? error.message : String(error)}`)
      }
      return originalAuthorizeIndex.call(this, request, response)
    }
    connection.authorizeIndex = authorizeIndexWithCookiePruning
    ctx.effect(() => () => {
      if (connection.authorizeIndex === authorizeIndexWithCookiePruning) delete connection.authorizeIndex
    }, 'dsh-cookie-sentinel: stale cookie pruning')
    log?.info('stale browser-session cookies will be pruned on the index exchange')
  } catch (error) {
    log?.warn(`could not wrap connection.authorizeIndex: ${error instanceof Error ? error.message : String(error)}`)
  }
}
