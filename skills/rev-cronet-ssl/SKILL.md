---
name: rev-cronet-ssl
description: Bypass SSL pinning in Cronet-based Android apps (TikTok, Douyin, and other ByteDance/Chromium-net apps). Activate when the user cannot capture HTTPS traffic from an app that uses libsscronet.so / Cronet / BoringSSL, sees "Exception in CronetUrlRequest" or custom_verify logs, or wants a version-specific Frida script to defeat SSL_CTX_set_custom_verify. Pairs with IDA MCP to locate the verify function/offset per app version.
---

# rev-cronet-ssl — Cronet / BoringSSL SSL-Pinning Bypass

For authorized security testing only (your own device, your own traffic, research, CTF).

TikTok and Douyin use Google's **Cronet** stack — Chromium's network layer extracted into
an SDK, bundled as `libsscronet.so`. Certificate verification (including SSL Pinning) is
delegated to Chromium's own logic via BoringSSL's `SSL_CTX_set_custom_verify`. Standard Java
pinning bypasses (JustTrustMe, okhttp hooks) **do not work** — verification happens entirely
in native code, below Java. That is why the app shows a generic network error while the
network itself is fine.

The goal: force the native verify callback to return `ssl_verify_ok` (0).

---

## Detection theory (why normal bypasses fail)

Cronet layering:

```
Java API  ->  JNI Bridge  ->  Cronet C API  ->  Chromium net stack  ->  BoringSSL + QUIC + DNS
```

During TLS handshake Chromium registers a custom verifier and disables BoringSSL's default:

```c
// enum ssl_verify_result_t { ssl_verify_ok=0, ssl_verify_invalid=1, ssl_verify_retry=2 };
void SSL_CTX_set_custom_verify(
    SSL_CTX *ctx, int mode,                                    // mode: SSL_VERIFY_PEER = 0x01
    enum ssl_verify_result_t (*callback)(SSL *ssl, uint8_t *out_alert));  // arg[2] = the callback
```

The `callback` (arg index 2) is where the app runs full cert validation + pinning. Two levers:

1. **Force the callback's return value to `0`** (ssl_verify_ok). Most reliable — see article
   `frida-ssl-pinning-bypass` (CYRUS STUDIO) and the kanxue TK writeup. This is the default in
   the bundled template.
2. **Zero the `mode` argument** (arg[1] -> 0 = SSL_VERIFY_NONE) at the `SSL_CTX_set_custom_verify`
   entry. Simpler but weaker — some versions still validate. Kept as an alternative below.

Symbol note: `SSL_CTX_set_custom_verify` lives in BoringSSL. Depending on how ByteDance links
it, the export appears in `libsscronet.so`, `libttboringssl.so`, or a verify wrapper
(`libvcnverify.so`, `libttmverify.so`). Hook it wherever it is exported.

---

## Quick start (try this first)

Most versions still export the symbol. Run the template as-is:

```bash
# TikTok
frida -U -f com.zhiliaoapp.musically -l assets/cronet_ssl_bypass.js
# Douyin
frida -U -f com.ss.android.ugc.aweme  -l assets/cronet_ssl_bypass.js
```

The template (`assets/cronet_ssl_bypass.js`):
- hooks `SSL_CTX_set_custom_verify` across all known modules (export lookup),
- captures `arg[2]` and forces that callback to return `0`,
- watches `dlopen`/`android_dlopen_ext` so it catches late-loaded modules,
- has an **offset fallback** (`CONFIG.offsets`) for stripped builds.

If you see `force verify result 1 -> 0` and traffic starts flowing in your proxy, you're done.
Note the **modern Frida CLI has no `--no-pause`** — the process resumes automatically.

If the quick start fails (symbol stripped, or hook lands but pinning persists), do the
version-specific IDA analysis below to find the exact offset.

---

## Version-specific analysis with IDA MCP

Use this when the export is missing or you must confirm the right function for a new version.
Pull the target `.so` from the device (or unzip the APK) and load it into IDA, then drive the
`mcp__ida-pro-mcp__*` tools.

### 1. Get the module on the device

```bash
adb shell pidof com.zhiliaoapp.musically                 # confirm running
# Preferred: dump from memory (defeats packing) — see rev-dex-dumper / SoFixer workflow.
# Simple path: pull from APK
adb shell pm path com.zhiliaoapp.musically               # find base.apk
unzip -o base.apk 'lib/arm64-v8a/*' -d ./tk_libs         # extract native libs
```

If the `.so` is packed/encrypted on disk, dump it from memory and repair with SoFixer:
`SoFixer -m <base_addr> -s libsscronet.so.dump.so -o fixed.so` (the Cronet articles use this).

### 2. Confirm which module exports the symbol

```bash
cd tk_libs/lib/arm64-v8a
# Which .so references Cronet / the verify symbol:
grep -rl "SSL_CTX_set_custom_verify" .
grep -rl "CronetUrlRequest" .            # usually libsscronet.so
```

### 3. Locate the verify function in IDA (MCP)

Load `libsscronet.so` (or the matching module) into IDA, then:

```
# Find the export directly — best case
mcp__ida-pro-mcp__lookup_funcs        queries="SSL_CTX_set_custom_verify"

# If stripped, find it by its Chromium log strings / source path markers:
mcp__ida-pro-mcp__find    type="string"   targets=["custom_verify", "ssl_client_socket_impl.cc", "start call custom verify", "SSL_CTX_set_custom_verify"]

# Follow xrefs from a matched string to the enclosing function:
mcp__ida-pro-mcp__xrefs_to            addrs=<string_addr>
mcp__ida-pro-mcp__analyze_function    addr=<func_addr>   include_asm=true
```

What the verify function looks like when decompiled (from the Cronet writeup) — a strong
fingerprint that you found the right function:

```c
// av_log(..., "custom_verify:start call custom verify ssl:%p host:%s port:%d");
v8  = Cronet_CertVerify_Create(...);
v10 = Cronet_VerifyParamsV2_Create(...);
Cronet_VerifyParamsV2_host_set(v10, host);
v11 = SSL_get0_peer_certificates(ssl);
...
v22 = Cronet_CertVerify_DoVerifyV2(v8, v10, v21);   // <- the actual pin check
return v22 > 1;                                     // return value gates the handshake
```

### 4. Extract the offset for the template

```
# The file offset = func_addr - module_base. Compute and confirm:
mcp__ida-pro-mcp__analyze_function    addr=<func_addr>        # note the address
# In Frida the runtime addr = Module base + this file offset.
```

Two offset targets depending on your lever:
- **Callback approach (preferred):** you rarely need an offset — hooking the exported
  `SSL_CTX_set_custom_verify` gives you `arg[2]` at runtime. Only when the *export* itself is
  stripped do you set `CONFIG.offsets['<module>'] = <offset of SSL_CTX_set_custom_verify>`.
- **Direct-verify approach:** put the offset of the *verify function itself* (the one returning
  `v22 > 1`) into `CONFIG.offsets` and let the template force its retval to 0. This is what the
  ByteDance 34.6.0 writeup does: `soAddr.add(0x33D05C)` then `retval.replace(ptr(0))`.

Confirm live before trusting an offset (ASLR-independent, base-relative):

```bash
frida -U com.zhiliaoapp.musically -q -e \
  'var m=Process.getModuleByName("libsscronet.so"); console.log(m.base, "size", m.size);'
```

### 5. Wire it into the template

Edit `assets/cronet_ssl_bypass.js`:

```javascript
offsets: {
    'libsscronet.so': 0x33D05C,   // <- your IDA offset for THIS version
},
```

Re-run. Turn on `CONFIG.printBacktrace = true` to confirm the caller chain
(`libsscronet.so` / `libvcn.so` / `libavmdlbase.so` are expected).

---

## Bypass strategy decision tree

```
Export SSL_CTX_set_custom_verify present?
├─ yes ─> hook export, force arg[2] callback -> 0     (template Strategy A, default)
│         still pinned? ─> also try zeroing mode (arg[1] -> 0) at the entry
└─ no  ─> IDA: find verify func by strings/xrefs
          ├─ export stripped only ─> offset of SSL_CTX_set_custom_verify -> CONFIG.offsets (Strategy B)
          └─ fully custom verify  ─> offset of the verify func itself, force retval 0 (Strategy B)

QUIC still hiding traffic (only some endpoints captured)?
└─ force protocol downgrade so HTTPS is used and proxy can see it:
   • return 0 from the verify callback often disables QUIC path (kanxue: "让他降级")
   • Java: org.chromium.CronetClient.tryCreateCronetEngine -> pass null (older versions)
   • Ali family (tb/xy/tm/elm): hook mtopsdk...SwitchConfig.isGlobalSpdySslSwitchOpen -> false
```

### Alternative lever: zero the mode argument

Weaker but sometimes enough; edit the entry hook to add:

```javascript
onEnter: function (args) {
    args[1] = ptr(0x0);   // SSL_VERIFY_NONE — skip requiring/validating peer cert
    hookVerifyCallback(args[2], moduleName);
}
```

### Persistent option: patch the .so

For a Frida-free capture, patch the verify function to always return success (IDA Keypatch):
change the `mode`/return so the check passes, save the `.so`, repack the APK, re-sign, reinstall.
The ByteDance article does exactly this (`#1 -> 0`). Note ByteDance changes the byte signature
every major version, so a patch is version-locked.

---

## Triage: confirm it's actually Cronet pinning

Before reversing, verify the failure mode from logs:

```bash
adb logcat -c
adb logcat --pid=$(adb shell pidof com.zhiliaoapp.musically) -v time > logcat.txt
# then reproduce the failure and grep:
grep -Ei "custom_verify|CronetUrlRequest|ttmverify|vcnnetwork|sscronet" logcat.txt
```

Signals that this skill is the right tool:
- `Exception in CronetUrlRequest` / `CronetUrlRequest.onError` in logs
- `custom_verify.c ... register verify` from `ttmverify` / `vcnnetwork` tags
- `loadLibrary libsscronet.so success`
- App reports a network error but the device has working internet and your proxy CA is trusted

---

## Frida API notes (modern CLI)

- No `--no-pause`; the process auto-resumes after the script loads.
- Prefer `Process.getModuleByName()` / `mod.getExportByName()` over deprecated
  `Module.findBaseAddress()`. The template falls back across API variants for compatibility.
- Callback signature is `int (*)(void* ssl, void* out_alert)`; hooking `onLeave` and calling
  `retval.replace(0)` is enough — no need to `Interceptor.replace` with a `NativeCallback`.
- `Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)` to trace
  which module drove the call.

---

## Reference apps / package names

| App     | Package                          | Primary module    |
|---------|----------------------------------|-------------------|
| TikTok  | com.zhiliaoapp.musically         | libsscronet.so    |
| Douyin  | com.ss.android.ugc.aweme         | libsscronet.so    |

TikTok and Douyin share the same protocol stack, so a working Douyin bypass generally applies
to TikTok and vice versa (only offsets differ by build). For geo-restricted TikTok endpoints:
remove the SIM, set device locale/timezone to an overseas region, and route the IP overseas.

---

## Files

- `assets/cronet_ssl_bypass.js` — universal, dlopen-aware, multi-module bypass with export +
  offset strategies. Tune `CONFIG` for your target/version.
