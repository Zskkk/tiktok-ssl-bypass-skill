/*
 * Cronet / BoringSSL SSL-Pinning bypass — TikTok / Douyin / ByteDance Cronet family.
 *
 * Verified: TikTok com.zhiliaoapp.musically 45.7.1 (arm64-v8a) and Douyin. Also works for other
 * apps that ship Google's Cronet stack. IDA (libsscronet.so v45.7.1): SSL_CTX_set_custom_verify
 * and SSL_CTX_set_quic_method are import thunks -> the real functions live in libttboringssl.so.
 *
 * How it works (Strategy A — export by name, version-portable):
 *   Resolve SSL_CTX_set_custom_verify in the app's OWN BoringSSL, capture arg[2] (the verify
 *   callback) and, in its onLeave, flip result 1 (ssl_verify_invalid) -> 0 (ssl_verify_ok).
 *
 * MANDATORY method (see rev-cronet-ssl skill — deviations crash the app):
 *   - observe-and-nudge, NEVER replace the callback. Let the real verifier run, then in onLeave
 *     flip ONLY 1 -> 0. Leave 2 (ssl_verify_retry, the async signal) untouched.
 *   - QUIC registers a second custom_verify on the same SSL_CTX (the one that also calls
 *     SSL_CTX_set_quic_method). Its callback is an async state machine returning 2; flipping it
 *     desyncs state and crashes a media thread. We remember QUIC ctxs and SKIP hooking them.
 *   - Never touch the system libssl.so — Cronet doesn't route through it; you'd hook it and see
 *     zero callback hits.
 *
 * Strategy B (fallback): if the export is stripped on some build, set CONFIG.offsets to the
 * verify function's file offset (found via IDA) and it's hooked directly (same 1 -> 0 rule).
 *
 * Run at spawn (the SSL_CTX is built early; attaching late misses it):
 *   frida -U -f com.zhiliaoapp.musically -l tiktok_ssl_bypass.js
 *   frida -U -f com.ss.android.ugc.aweme  -l tiktok_ssl_bypass.js   # Douyin
 *
 * Success signal: "hit | caller=libsscronet.so ..." then "force verify 1 -> 0".
 * QUIC/UDP video traffic stays native and won't show in an HTTP/TCP proxy — expected.
 */

'use strict';

var CONFIG = {
    // The app's OWN BoringSSL / Cronet modules, in priority order. NEVER add the system
    // libssl.so: it resolves the symbol but no Cronet traffic flows through it (zero hits).
    // Extra entries are harmless — absent modules are simply skipped.
    modules: [
        'libttboringssl.so',   // ByteDance BoringSSL (real home of the symbols)
        'libsscronet.so',      // ByteDance Cronet (PLT thunks; also statically-linked on some builds)
        'libcronet.so',        // stock Cronet / other Cronet apps
        'libvcnverify.so',     // ByteDance vcn verify wrapper
        'libttmverify.so'      // ByteDance ttm verify wrapper
    ],

    // OFFSET fallback (Strategy B): module -> file offset of the verify function (from IDA).
    // Only used when the export can't be resolved. Example: { 'libsscronet.so': 0x2C72E0 }
    offsets: {
        // 'libsscronet.so': 0x2C72E0,
    },

    pollMs: 200,             // poll interval for module/export detection
    pollTimeoutMs: 60000,    // stop polling after this long
    printBacktrace: false,   // print native backtrace at the custom_verify entry (debug)
    verbose: true
};

var installedExport = {};    // module -> true (custom_verify export hooked)
var installedOffset = {};    // module -> true (offset fallback hooked)
var quicWatched = {};        // module -> true (quic_method export hooked)
var hookedCbs = {};          // callback addr string -> true
var quicCtxs = {};           // SSL_CTX addr string -> true (skip these)
// Dedupe by ADDRESS: several module names resolve the SAME impl in libttboringssl.so via PLT,
// so keying only on module name would attach the same function multiple times.
var hookedAddrs = {};        // resolved function addr string -> true
var anyHooked = false;       // did we install at least one custom_verify hook?

function log(m) { if (CONFIG.verbose) console.log('[tt-ssl] ' + m); }

function findModuleByName(name) {
    if (Process.findModuleByName) return Process.findModuleByName(name);
    try { return Process.getModuleByName(name); } catch (_) { return null; }
}

function fmtAddr(addr) {
    var mod = Process.findModuleByAddress(addr);
    return mod === null ? addr.toString() : mod.name + '!0x' + addr.sub(mod.base).toString(16);
}

// Resolve a symbol in a module. Reject any address that lands in the system libssl.so —
// Cronet never routes through it, so hooking it yields a hook with no callback hits.
function findExport(moduleName, symbol) {
    var mod = findModuleByName(moduleName);
    if (mod === null) return null;
    var a = null;
    try { if (mod.getExportByName) a = mod.getExportByName(symbol); } catch (_) {}
    if (a === null) { try { if (Module.getExportByName) a = Module.getExportByName(moduleName, symbol); } catch (_) {} }
    if (a === null) { try { if (Module.findExportByName) a = Module.findExportByName(moduleName, symbol); } catch (_) {} }
    if (a === null || a.isNull()) return null;
    var owner = Process.findModuleByAddress(a);
    if (owner !== null && owner.name === 'libssl.so') return null;
    return a;
}

// Hook the verify callback: enum ssl_verify_result_t (*)(SSL*, uint8_t*).
// 0=ok, 1=invalid, 2=retry. Flip ONLY 1 -> 0. Never touch 2.
function hookVerifyCallback(cbPtr, src) {
    if (cbPtr === null || cbPtr.isNull()) return;
    var key = cbPtr.toString();
    if (hookedCbs[key]) return;
    hookedCbs[key] = true;

    log('hook verify callback ' + cbPtr + ' (' + fmtAddr(cbPtr) + ') from ' + src);
    try {
        Interceptor.attach(cbPtr, {
            onLeave: function (retval) {
                if (retval.toInt32() === 1) {
                    log('force verify 1 -> 0 (ssl_verify_ok) [' + src + ']');
                    retval.replace(0);
                }
            }
        });
    } catch (e) {
        console.error('[tt-ssl] failed to hook callback ' + cbPtr + ': ' + e);
    }
}

// Remember every SSL_CTX passed to SSL_CTX_set_quic_method so we can skip QUIC ctxs.
function watchQuicMethod(moduleName) {
    if (quicWatched[moduleName]) return;
    var addr = findExport(moduleName, 'SSL_CTX_set_quic_method');
    if (addr === null) return;
    quicWatched[moduleName] = true;
    var qkey = 'quic:' + addr.toString();
    if (hookedAddrs[qkey]) return;   // same impl via another module name — attach once
    hookedAddrs[qkey] = true;
    log('watch SSL_CTX_set_quic_method @ ' + addr + ' (' + fmtAddr(addr) + ') in ' + moduleName);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var ctx = args[0];
            if (ctx && !ctx.isNull()) {
                quicCtxs[ctx.toString()] = true;
                log('QUIC ctx registered: ' + ctx + ' (will skip its custom_verify)');
            }
        }
    });
}

// Strategy A: hook exported SSL_CTX_set_custom_verify, capture arg[2], skip QUIC ctxs.
function hookExport(moduleName) {
    if (installedExport[moduleName]) return true;
    var addr = findExport(moduleName, 'SSL_CTX_set_custom_verify');
    if (addr === null) return false;

    installedExport[moduleName] = true;
    var akey = addr.toString();
    if (hookedAddrs[akey]) {
        log('SSL_CTX_set_custom_verify @ ' + fmtAddr(addr) + ' already hooked (via another module) — skip');
        anyHooked = true;
        return true;
    }
    hookedAddrs[akey] = true;
    anyHooked = true;
    log('hook SSL_CTX_set_custom_verify @ ' + addr + ' (' + fmtAddr(addr) + ') in ' + moduleName);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            var ctx = args[0];
            var caller = Process.findModuleByAddress(this.returnAddress);
            log('hit | caller=' + (caller ? caller.name : 'unknown') +
                ' | ctx=' + ctx + ' | mode=' + args[1] + ' | cb=' + args[2]);
            if (CONFIG.printBacktrace) {
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
            if (ctx && quicCtxs[ctx.toString()]) {
                log('skip: QUIC ctx ' + ctx + ' (async retry callback, leave native)');
                return;
            }
            hookVerifyCallback(args[2], moduleName);
        }
    });
    return true;
}

// Strategy B: offset fallback for stripped symbols. Hook verify func, flip 1 -> 0.
function hookOffset(moduleName) {
    if (installedOffset[moduleName]) return true;
    var off = CONFIG.offsets[moduleName];
    if (off === undefined || off === null) return false;
    var mod = findModuleByName(moduleName);
    if (mod === null) return false;

    var target = mod.base.add(off);
    var akey = target.toString();
    installedOffset[moduleName] = true;
    if (hookedAddrs[akey]) return true;
    hookedAddrs[akey] = true;
    anyHooked = true;
    log('OFFSET fallback: hook ' + moduleName + '!0x' + off.toString(16) + ' @ ' + target);
    Interceptor.attach(target, {
        onLeave: function (retval) {
            if (retval.equals(1)) {
                log('offset verify 1 -> 0 [' + moduleName + ']');
                retval.replace(0);
            }
        }
    });
    return true;
}

function tryHookModule(moduleName) {
    // Register the QUIC watcher first so ctxs are known before custom_verify fires.
    watchQuicMethod(moduleName);
    if (hookExport(moduleName)) return true;
    if (hookOffset(moduleName)) return true;
    return false;
}

function scanLoaded() {
    CONFIG.modules.forEach(function (m) {
        if (findModuleByName(m) !== null) tryHookModule(m);
    });
    return anyHooked;
}

function watchDlopen() {
    ['android_dlopen_ext', 'dlopen'].forEach(function (loaderName) {
        var loader = null;
        try { loader = Module.getExportByName(null, loaderName); } catch (_) {}
        if (loader === null) { try { loader = Module.findExportByName(null, loaderName); } catch (_) {} }
        if (loader === null) return;
        Interceptor.attach(loader, {
            onEnter: function (args) {
                this.target = null;
                var p = args[0];
                if (!p || p.isNull()) return;
                var path = p.readCString();
                if (path === null) return;
                for (var i = 0; i < CONFIG.modules.length; i++) {
                    if (path.indexOf(CONFIG.modules[i]) >= 0) { this.target = CONFIG.modules[i]; break; }
                }
            },
            onLeave: function () {
                if (this.target) { log('loaded ' + this.target); tryHookModule(this.target); }
            }
        });
    });
}

// Poll until we've hooked the app's BoringSSL. dlopen watcher also catches late loads, but
// polling is the reliable path (ByteDance's custom loader can bypass the dlopen exports).
function startPolling() {
    if (scanLoaded()) return;
    var elapsed = 0;
    var timer = setInterval(function () {
        elapsed += CONFIG.pollMs;
        if (scanLoaded()) { clearInterval(timer); return; }
        if (elapsed >= CONFIG.pollTimeoutMs) {
            clearInterval(timer);
            log('gave up after ' + (CONFIG.pollTimeoutMs / 1000) + 's; no BoringSSL hooked. ' +
                'Confirm the app uses one of: ' + CONFIG.modules.join(', ') + ' and run at spawn (-f).');
        }
    }, CONFIG.pollMs);
}

function main() {
    log('starting; modules: ' + CONFIG.modules.join(', ') + ' (poll ' + CONFIG.pollMs + 'ms)');
    watchDlopen();
    startPolling();
}

setImmediate(main);
