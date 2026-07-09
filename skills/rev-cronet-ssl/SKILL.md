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

The goal: make the native verify callback report success — flip its failure result (`1`) to
`ssl_verify_ok` (`0`), without disturbing the async-retry result (`2`).

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

1. **Rewrite the callback's return value** (preferred, most reliable). The callback returns
   `ssl_verify_result_t`: **`0`=ok, `1`=invalid, `2`=retry**. Flip a hard failure (`1`) to
   `0`. **Do NOT touch `2` (retry)** — it is the async "call me back later" signal; forcing it
   to `0` tells the TLS state machine verification finished while async structures are still
   unset, which crashes later on a media/worker thread. Blind `replace(0)` on every return
   works on happy-path builds but hits this crash on versions that use async verify. This is
   the whole reason to understand the enum instead of copy-pasting `retval.replace(0)`.
2. **Zero the `mode` argument** (arg[1] -> 0 = SSL_VERIFY_NONE) at the `SSL_CTX_set_custom_verify`
   entry. Simpler but weaker — many versions still run the callback and validate. Alternative only.

> **MANDATORY method — read before writing any hook.** There is exactly one correct technique.
> Deviations crash the app.
>
> - **DO:** `Interceptor.attach(callback, { onLeave })` and, only when `retval == 1`, `retval.replace(0)`.
>   The original callback runs to completion first (it fills the cert chain, host, OCSP, SCT,
>   SSLInfo, and internal state Cronet needs downstream); you adjust *only* the final result.
> - **DO NOT** use `Interceptor.replace` / a `NativeCallback` to substitute the verify callback,
>   and DO NOT "swap the callback to always-ok". Replacing the callback SKIPS the original, so
>   Cronet's state is never populated and the async/QUIC path dereferences unset structures →
>   crash (observed: `SIGTRAP/TRAP_BRKPT` on `ChromiumNet0`, or SIGSEGV on a media thread).
> - **DO NOT** unconditionally return `0` from the callback. Preserve `2` (retry) exactly; only
>   `1 -> 0`.
>
> Rule of thumb: **observe-and-nudge, never replace.** Let the real verifier run; change one
> return value at the boundary. If your script logs "callback swapped/replaced", it is wrong.

Symbol note: `SSL_CTX_set_custom_verify` lives in BoringSSL. Depending on how ByteDance links
it, the export appears in the app's **own** BoringSSL — `libttboringssl.so` (most common), or
statically inside `libsscronet.so`, or a verify wrapper (`libvcnverify.so`, `libttmverify.so`).
In `libsscronet.so` it is often just an **import thunk** to `libttboringssl.so`.

> **Critical: hook the app's BoringSSL, NOT the system `libssl.so`.** Android ships its own
> `libssl.so` (system BoringSSL) which is loaded from the very start. Cronet does **not** use it —
> it uses the bundled `libttboringssl.so`. Two traps a generated script must avoid:
>
> 1. **Never put `libssl.so` in the provider/module list.** It resolves the symbol fine but no
>    Cronet traffic flows through it, so you hook it and see *zero* callback hits. (Observed
>    failure: script logged `hook ... @ libssl.so!0x35104` then nothing — pinning never bypassed.)
> 2. **"Symbol resolved" ≠ "correct library".** The system `libssl.so` is always ready before the
>    app's `libttboringssl.so` finishes loading, so a poll that stops at the first module to
>    resolve the symbol will lock onto the wrong one. Keep polling for the app's BoringSSL
>    (`libttboringssl.so` / `libsscronet.so`) specifically; do not accept `libssl.so`.
>
> **Success signal:** you must see `hit | caller=libsscronet.so ...` followed by
> `force verify 1 -> 0`. Seeing only `hook ... @ <module>` with no `hit` means you hooked the
> wrong library — change the target, don't stop.

---

## Quick start (try this first)

Most versions still export the symbol. Run the script as-is:

```bash
# TikTok
frida -U -f com.zhiliaoapp.musically -l assets/tiktok_ssl_bypass.js
# Douyin
frida -U -f com.ss.android.ugc.aweme  -l assets/tiktok_ssl_bypass.js
```

The script (`assets/tiktok_ssl_bypass.js`) — verified on TikTok 45.7.1, also covers Douyin and
other Cronet apps:
- resolves `SSL_CTX_set_custom_verify` against the app's BoringSSL modules only
  (`libttboringssl.so`/`libsscronet.so`/`libcronet.so`/wrappers) — **excluding the system
  `libssl.so`** (any address owned by `libssl.so` is rejected),
- captures `arg[2]` and flips that callback's `1 -> 0` (leaves `2`/retry alone),
- **skips QUIC contexts** (tracked via `SSL_CTX_set_quic_method`) so the async verifier stays
  native and doesn't crash the media thread,
- dedupes by resolved **address** (several module names alias the same impl via PLT),
- **polls** for the app's BoringSSL (and watches `dlopen`) to catch ByteDance's custom loader,
- has an **offset fallback** (`CONFIG.offsets`) for stripped builds, and a `printBacktrace`
  debug switch.

If you see `force verify 1 -> 0` and traffic starts flowing in your proxy, you're done.
Note the **modern Frida CLI has no `--no-pause`** — the process resumes automatically.
The bypass must run at **spawn** (`-f`): the SSL_CTX is built early, so attaching late misses it.

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

### 5. Wire it into the script

Edit `assets/tiktok_ssl_bypass.js`:

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
├─ yes ─> hook export, flip arg[2] callback 1 -> 0 (keep retry)   (Strategy A, default)
│         still pinned? ─> also try zeroing mode (arg[1] -> 0) at the entry
└─ no  ─> IDA: find verify func by strings/xrefs
          ├─ export stripped only ─> offset of SSL_CTX_set_custom_verify -> CONFIG.offsets (Strategy B)
          └─ fully custom verify  ─> offset of the verify func itself, flip 1 -> 0 (Strategy B)

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
- Callback signature is `int (*)(void* ssl, void* out_alert)`. Hook it with `Interceptor.attach`
  and in `onLeave` flip **only** `1 -> 0`. Never `Interceptor.replace` it, never substitute a
  `NativeCallback`, never return a constant — that skips the real verifier and crashes Cronet
  (see the MANDATORY method box above).
- `Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)` to trace
  which module drove the call.

---

## Troubleshooting: bypass works but the app misbehaves

The bypass itself is one hook. Most pain comes *after* it works — API captures fine but video
won't play, or the app crashes seconds later. Resist the urge to pile on more hooks. Diagnose
first. Hard-won process:

**1. Establish a clean baseline.** Run the *minimal* script (one hook, `1 -> 0`, nothing else).
If a symptom persists with the minimal script, it is NOT caused by anything you added — stop
adding SSL-side hooks. Every extra hook (callback filtering, module isolation, offset tricks)
is a new suspect; the textbook single-hook scripts play video fine, so divergence from them is
the clue.

**2. Separate "bypass" from "Frida presence".** Run a **no-op script** (attach, zero hooks, just
an exception handler). If the app still crashes, the crash is from injection/spawn timing or a
device bug — not your bypass. This exonerates the SSL code in one step.

**3. Capture the REAL crash site, don't guess.** Install a native exception handler and print
the faulting `module!offset` + backtrace:

```javascript
Process.setExceptionHandler(function (d) {
    var m = Process.findModuleByAddress(d.address), n = m ? m.name : '';
    if (n.indexOf('boot.oat') >= 0) return false;  // ART's implicit-null-check SIGSEGVs — noise
    console.log('[exc] ' + d.type + ' @ ' + d.address + ' ' + (m ? n + '!0x' + d.address.sub(m.base) : ''));
    try { console.log('pc=' + d.context.pc + ' lr=' + d.context.lr); } catch (_) {}
    return false;  // log only, let it crash
});
```

The Android tombstone's own `backtrace:` (bottom of the crash dump) is the most reliable frame —
read it before theorizing. A crash in a **system lib** (`libstagefright.so`, media threads named
`Looper-V*`) is almost never your SSL code.

**4. Bypass is an MITM — it has side effects.** Once the app trusts your proxy, requests you did
not intend to intercept also flow through it. If the proxy alters/relays a response the app then
parses natively (config flags, media manifests), you can trigger crashes far from the SSL code.
Fix this at the **proxy**, not with more Frida hooks: set your proxy to **SSL-passthrough** (do
not decrypt) for domains you don't care about (media CDNs, config/abtest/settings services), and
only decrypt the API domains you actually want. This keeps video/config native and correct.

**5. The QUIC verify callback is an async state machine — do not flip its result.** Cronet
registers `SSL_CTX_set_custom_verify` twice: once for TLS, once for QUIC (the QUIC registration
site also calls `SSL_CTX_set_quic_method` on the same `SSL_CTX`). The TLS callback is synchronous
— flipping `1 -> 0` is safe. The QUIC callback is NOT: it returns `2`(retry), stashes context,
and gets re-invoked when async verification completes; forcing its `1 -> 0` desyncs that state
and crashes a media thread (`Looper-V*`). Identify QUIC contexts **portably, without hardcoded
offsets**: hook the exported `SSL_CTX_set_quic_method`, remember each `SSL_CTX` (arg[0]) it sets,
then at the `SSL_CTX_set_custom_verify` entry skip installing your hook when that ctx is a QUIC
ctx. (Implemented in `tiktok_ssl_bypass.js` — see `watchQuicMethod`.) You lose nothing: video
rides QUIC over UDP, which an HTTP/TCP proxy can't capture anyway.

**6. QUIC is invisible to HTTP/TCP proxies.** Even with pinning bypassed and the QUIC callback
left native, TikTok video (QUIC/UDP 443) won't appear in Charles/mitmproxy/Burp — expected, not
a failure. To capture it: block UDP 443 to force TCP/TLS fallback, downgrade QUIC (older:
`org.chromium.CronetClient.tryCreateCronetEngine` -> null), or use a QUIC-capable capture.

---

## Known limitation: libstagefright media-thread crash (device-specific)

On some ROMs (observed: Redmi/marble, Android 15/MIUI) the app crashes a few seconds into video
playback with a null-deref on a `Looper-V*` thread, tombstone top frames:

```
#00 libstagefright.so getServerConfigurableFlag+...
#01 VideoRenderQualityTracker::Configuration::getFromServerConfigurableFlags
#02 MediaCodec::MediaCodec
#03 MediaCodec::CreateByComponentName
```

**This is NOT caused by the bypass.** It reproduces with a zero-hook Frida script (spawn +
video). It is the system media framework's `VideoRenderQualityTracker` parsing a
server-configurable flag with `strtoll` and dereferencing a NULL result, triggered by Frida's
spawn injection perturbing media init on that ROM. It only surfaces once pinning/QUIC are handled
and video actually decodes.

Do NOT "fix" it inside this skill — the crashing offset is ROM-specific and would break
portability (an earlier attempt to hardcode a `libstagefright` offset was wrong for this exact
reason). Options, in order of preference:
- **Ignore it** if you only need API capture — SSL bypass and API traffic are unaffected.
- **Disable the trigger on-device** (no script): turn off the media DeviceConfig namespace, e.g.
  `adb shell device_config put media_native <flag> false` for the relevant render-metrics flag.
- **Try another device/emulator** — likely won't reproduce off this ROM.
- **Local band-aid, kept OUT of the skill:** a device-specific guard script that self-learns the
  faulting PC inside libstagefright and survives the null read. Ship it separately, never bundle
  it with the portable bypass.

**Anti-pattern (learned the hard way):** do not hardcode a system-lib offset (e.g. a
`libstagefright` function address) into the bypass to paper over a crash. It's device- and
build-specific, breaks the skill's portability, and treats a symptom. Prefer proxy passthrough
or a protocol choice.

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

- `assets/tiktok_ssl_bypass.js` — the single bypass script. Hooks `SSL_CTX_set_custom_verify`
  in the app's BoringSSL, flips `1 -> 0` (keeps retry), skips QUIC ctxs, dedupes by address,
  polls + watches `dlopen`. Export strategy by default; `CONFIG.offsets` fallback for stripped
  builds. Verified on TikTok 45.7.1; also covers Douyin and other Cronet apps.
