# tiktok-ssl-bypass-skill

> A [Claude Code](https://docs.claude.com/en/docs/claude-code) skill to bypass **Cronet / BoringSSL** SSL pinning in TikTok, Douyin, and other ByteDance apps — pairs with **Frida + IDA MCP** to generate version-specific bypass scripts.

中文: [README.md](README.md)

---

## ⚠️ Disclaimer

For **authorized security testing, protocol analysis, and education only** (your own device, your own traffic, CTF, sanctioned pentests). You are responsible for complying with all applicable laws. Do not use for any commercial or illegal purpose. The author assumes no liability.

---

## Why normal SSL bypasses fail on TikTok

TikTok and Douyin ship Google's **Cronet** stack — Chromium's network layer extracted into an SDK, bundled as `libsscronet.so`. Certificate verification (including SSL Pinning) happens entirely in **native code** via BoringSSL's `SSL_CTX_set_custom_verify` — **below the Java layer**.

That's why Java-level tricks (JustTrustMe, okhttp hooks, trusting a user CA) **do not work**. Symptom: the network is fine but the app errors out and your proxy shows `certificate_unknown`.

**Core idea:** In `SSL_CTX_set_custom_verify(ctx, mode, callback)`, the third argument `callback` is the app's own verifier; returning `0` means success (`ssl_verify_ok`). Hook that callback and force it to return `0` to bypass pinning globally.

```
Java API → JNI → Cronet C API → Chromium net stack → BoringSSL (SSL_CTX_set_custom_verify)
```

Full reversing workflow: [`skills/rev-cronet-ssl/SKILL.md`](skills/rev-cronet-ssl/SKILL.md)

---

## Contents

| File | Description |
|------|-------------|
| `skills/rev-cronet-ssl/SKILL.md` | The skill: activation triggers, detection theory, **IDA MCP workflow**, bypass decision tree |
| `skills/rev-cronet-ssl/assets/cronet_ssl_bypass.js` | **Universal template** — multi-module, dlopen + polling detection, export + offset strategies; tune `CONFIG` per target version |
| `skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js` | **Ready-to-run example** — verified on TikTok `45.7.1`, with polling detection and IDA-confirmed offsets |

### Which script?

- **Capturing TikTok 45.7.1 right now** → use `tiktok_ssl_bypass.js` as-is.
- **Other versions / Douyin / other ByteDance apps** → use `cronet_ssl_bypass.js` and follow the SKILL.md IDA MCP flow to find this version's export/offset, then fill in `CONFIG`.

> Most public scripts hook `android_dlopen_ext` to wait for the `.so` to load — but **newer ByteDance builds use bytehook/custom loaders, so that hook never fires** and the script silently fails. The scripts here **poll** for the module instead, avoiding this pitfall.

---

## Quick start

### Prerequisites

- Rooted Android device / emulator with your proxy CA trusted
- `frida-server` (or gadget) on device, `frida` tools on PC
- An intercepting proxy (mitmproxy / Charles / BurpSuite)

### Run (TikTok example)

```bash
# spawn mode (-H forwards to frida-server over network; use -U for local USB)
frida -U -f com.zhiliaoapp.musically \
      -l skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js

# Douyin
frida -U -f com.ss.android.ugc.aweme \
      -l skills/rev-cronet-ssl/assets/cronet_ssl_bypass.js
```

> The modern Frida CLI has **no `--no-pause`**; the process resumes automatically after the script loads.

### Success output

```
[tiktok-ssl] hook SSL_CTX_set_custom_verify @ 0x... (libsscronet.so!0x4b2580)
[tiktok-ssl] SSL_CTX_set_custom_verify hit | caller=libsscronet.so!0x... | mode=0x1 | cb=0x...
[tiktok-ssl] force verify 0x1 -> 0 (ssl_verify_ok) [export]
```

Once you see `force verify ... -> 0` and traffic flows in your proxy, the bypass works.

---

## Use as a Claude Code skill

With [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp), Claude can drive the whole loop: load the `.so` → locate `SSL_CTX_set_custom_verify` → confirm the verify callback → compute the offset → emit a version-specific script.

Install (symlink the skill into your project's `.claude/skills/`):

```bash
git clone https://github.com/Zskkk/tiktok-ssl-bypass-skill.git
ln -s "$(pwd)/tiktok-ssl-bypass-skill/skills/rev-cronet-ssl" \
      /path/to/your-project/.claude/skills/rev-cronet-ssl
```

Then ask Claude: "use rev-cronet-ssl with IDA MCP to produce a Frida script that bypasses TikTok SSL."

---

## Scope

| App | Package | Primary module |
|-----|---------|----------------|
| TikTok | `com.zhiliaoapp.musically` | `libsscronet.so` |
| Douyin | `com.ss.android.ugc.aweme` | `libsscronet.so` |

TikTok and Douyin share the same protocol stack (only offsets differ by build). For geo-restricted TikTok: remove the SIM, set device locale/timezone overseas, route the IP overseas.

## Versioning notes

- The export-based strategy (hook `SSL_CTX_set_custom_verify`, force callback return) usually survives **minor** version bumps.
- Fallback offsets are **version-locked**; re-locate them in IDA for major versions.
- QUIC-only endpoints may evade an HTTP proxy even after pinning is bypassed — that's a protocol issue, not a pinning one.

## License

MIT
