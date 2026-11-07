# Auth Cookie Sentinel

A Host bundle for DeepSeek Harness Desktop that fixes the random-port
`dsh-auth-*` cookie lockout (`HTTP 431` → `desktop welcome: Web authentication failed`).

## The failure

DSH Desktop starts its Host Web server on a fresh random loopback port each
launch. `@deepseek-ai/dsh-client-connection` names its browser-session cookie
after the request authority, which includes that port:

```
dsh-auth-<sha256("127.0.0.1:<port>")>
```

Cookies are stored per host and ignore the port, and the minted cookie lives
for 30 days, so every launch leaves another `dsh-auth-…` cookie on `127.0.0.1`
while none of the earlier ones expire. Around 70 entries the accumulated
`Cookie` request header crosses Node's 16 KiB HTTP header limit; the Host
answers `431 Request Header Fields Too Large` before routing, and Electron's
welcome transport reports:

```
desktop welcome: Web authentication failed
```

## What this plugin does

Two things in `apply(ctx)`:

1. **Headroom.** Raises the live `http.Server` header limit to `128 KiB`
   (configurable, 16 KiB – 1 MiB). Node reads `server.maxHeaderSize` for every
   new connection, so the one request that still carries the already-broken jar
   reaches the authentication route instead of dying in the parser. The
   `webServer` service is provided before its class plugin finishes
   `[Service.init]`, so the bundle retries for up to 10 s if the server object
   does not exist yet.
2. **Mint-driven pruning.** Wraps `connection.authorizeIndex`, and only when
   that response mints a new `dsh-auth-…` cookie (the launch-token exchange)
   it appends `Set-Cookie: …; Max-Age=0` deletions for every other
   `dsh-auth-…` name the request carried. The Electron session stores those
   deletions, so the jar shrinks back to the current launch's cookie. A
   response that mints nothing (401, or the later 200) is left untouched — a
   future DSH version that changes the cookie spelling cannot make this plugin
   delete the valid cookie.

`apply` never throws: the Desktop shell treats a failed startup entry as fatal,
and a guard that can prevent a broken start must never become the reason the
app cannot start.

## Install

From the plugin market, or directly:

```sh
dsh plugin --profile <profile> add github:zhkkjF/dsh-cookie-sentinel
```

The package is host-only; no build step and no runtime dependencies beyond
Node built-ins.

## Config

```yaml
- insert:
    - id: dsh-cookie-sentinel
      name: dsh-cookie-sentinel
      config:
        maxHeaderSize: 131072   # 16 KiB – 1 MiB, default 128 KiB
```

## Audit log

One line per launch is appended to `~/.dsh/cookie-sentinel.log`:

```
2026-11-03T12:15:22.306Z loaded
2026-11-03T12:15:22.307Z ready headerLimit=131072
2026-11-03T12:15:22.315Z pruned=1 host=127.0.0.1:63104
```

`pruned=N` is the number of stale `dsh-auth-…` cookies deleted in the
launch-token response. After a clean first launch, later launches should report
`N=1`; a growing `N` means the Electron session is not storing the deletions
and a different repair is needed.

## Verification performed

- A 70-cookie request (17,638 bytes) returns `401`, not `431`.
- 500 cookies (125,998 bytes) still return `401`; 600 cookies (151,198 bytes)
  return `431`, matching the configured 128 KiB boundary.
- With a synthetic `authorizeIndex` that mints a cookie, 70 stale cookies
  produce 71 `Set-Cookie` headers (1 mint + 70 deletions) and the minted name is
  preserved; a no-mint response produces no deletions.
- The header limit is applied when the server object appears 120 ms after the
  consumer plugin runs (the retry path).

The Electron cookie jar itself is owned by Chromium and cannot be read while
the app is running; the audit log is the supported way to observe real pruning.

## License

MIT
