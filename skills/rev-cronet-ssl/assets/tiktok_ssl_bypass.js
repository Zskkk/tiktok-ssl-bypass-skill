/*
 * TikTok SSL-Pinning bypass — Cronet / BoringSSL (libsscronet.so)
 *
 * Target : com.zhiliaoapp.musically 45.7.1 (2024507010), arm64-v8a
 * Verified against libsscronet.so via IDA (imagebase 0x0, offsets == runtime module offsets):
 *   - SSL_CTX_set_custom_verify  PLT export @ 0x4b2580 (resolves via .dynsym / extern)
 *   - TLS  verify callback  sub_2C72E0  (call site 0x2c5d08, mode W1=1 SSL_VERIFY_PEER, X2=cb)
 *   - QUIC verify callback  sub_42055C  (call site 0x41dd7c, mode W1=1 SSL_VERIFY_PEER, X2=cb)
 *
 * sub_2C72E0 fingerprint: SSL_get0_peer_certificates -> build "certificates" params ->
 * cert chain verify. Returning 0 (ssl_verify_ok) makes every peer cert pass -> MITM works.
 *
 * (38.9.16 for reference: export 0x522528, TLS cb sub_374700, QUIC cb sub_4964D4.)
 *
 * WHY THIS VERSION: ByteDance loads libsscronet.so via bytehook/custom loaders, so hooking
 * dlopen/android_dlopen_ext MISSES the load (the earlier attempt never fired). Instead we
 * POLL for the module/export on an interval — robust regardless of how the .so is loaded.
 * We also search the export GLOBALLY (null module) because SSL_CTX_set_custom_verify resolves
 * through .dynsym and may live in a different module than libsscronet.so.
 *
 * Strategy:
 *   A (primary): find SSL_CTX_set_custom_verify (per-module then global), hook it, capture
 *      arg[2] (the verify callback) and force its return value to 0. Covers TLS + QUIC.
 *   B (fallback, this build only): hook the two verify callbacks directly at their confirmed
 *      offsets inside libsscronet.so and force retval 0.
 *
 * Run (spawn):
 *   frida -U -f com.zhiliaoapp.musically -l tiktok_ssl_bypass.js
 * Or attach after launch (sometimes more reliable if spawn-gating races the loader):
 *   frida -U -F -l tiktok_ssl_bypass.js
 */

'use strict';

var CONFIG = {
    module: 'libsscronet.so',
    // Also probe these if present (BoringSSL may be split out on some builds/versions).
    extraModules: ['libttboringssl.so', 'libcronet.so', 'libvcnverify.so', 'libttmverify.so'],
    // Strategy B fallback — verify callbacks for THIS build. Used only if the export search
    // yields nothing after the module is loaded. Update per version via IDA.
    callbackOffsets: [0x2C72E0, 0x42055C],   // 45.7.1: TLS sub_2C72E0, QUIC sub_42055C
    pollMs: 200,          // module/export poll interval
    pollTimeoutMs: 60000, // stop polling after this long
    printBacktrace: false,
    verbose: true
};

var didHookExport = false;
var didHookOffsets = false;
var hookedCallbacks = {};    // callback addr string -> true

function log(msg) { if (CONFIG.verbose) console.log('[tiktok-ssl] ' + msg); }

function findModule(name) {
    if (Process.findModuleByName) return Process.findModuleByName(name);
    try { return Process.getModuleByName(name); } catch (_) { return null; }
}

function fmtAddr(addr) {
    var mod = Process.findModuleByAddress(addr);
    return mod === null ? addr.toString() : mod.name + '!0x' + addr.sub(mod.base).toString(16);
}

// Resolve a symbol: try the named module first, then EVERY loaded module, then global.
function resolveExport(symbol) {
    var names = [CONFIG.module].concat(CONFIG.extraModules);
    for (var i = 0; i < names.length; i++) {
        var mod = findModule(names[i]);
        if (mod === null) continue;
        try { if (mod.getExportByName) { var a = mod.getExportByName(symbol); if (a) return a; } } catch (_) {}
        try { if (Module.getExportByName) { var b = Module.getExportByName(names[i], symbol); if (b) return b; } } catch (_) {}
        try { if (Module.findExportByName) { var c = Module.findExportByName(names[i], symbol); if (c) return c; } } catch (_) {}
    }
    // Global fallback across all modules (handles .dynsym resolving elsewhere).
    try { if (Module.getExportByName) { var g = Module.getExportByName(null, symbol); if (g) return g; } } catch (_) {}
    try { if (Module.findExportByName) { var h = Module.findExportByName(null, symbol); if (h) return h; } } catch (_) {}
    return null;
}

// enum ssl_verify_result_t (*)(SSL* ssl, uint8_t* out_alert): 0=ok,1=invalid,2=retry. Force 0.
function hookVerifyCallback(cbPtr, tag) {
    if (cbPtr === null || cbPtr.isNull()) return;
    var key = cbPtr.toString();
    if (hookedCallbacks[key]) return;
    hookedCallbacks[key] = true;

    log('hook verify callback ' + cbPtr + ' (' + fmtAddr(cbPtr) + ') [' + tag + ']');
    try {
        Interceptor.attach(cbPtr, {
            onLeave: function (retval) {
                if (!retval.equals(0)) {
                    log('force verify ' + retval + ' -> 0 (ssl_verify_ok) [' + tag + ']');
                    retval.replace(0);
                }
            }
        });
    } catch (e) {
        console.error('[tiktok-ssl] failed to hook callback ' + cbPtr + ': ' + e);
    }
}

// Strategy A: hook SSL_CTX_set_custom_verify wherever it resolves, grab arg[2] at runtime.
function hookExport() {
    if (didHookExport) return true;
    var addr = resolveExport('SSL_CTX_set_custom_verify');
    if (addr === null) return false;

    didHookExport = true;
    log('hook SSL_CTX_set_custom_verify @ ' + addr + ' (' + fmtAddr(addr) + ')');
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var caller = Process.findModuleByAddress(this.returnAddress);
            log('SSL_CTX_set_custom_verify hit | caller=' +
                (caller ? caller.name + '!0x' + this.returnAddress.sub(caller.base).toString(16) : 'unknown') +
                ' | mode=' + args[1] + ' | cb=' + args[2]);
            if (CONFIG.printBacktrace) {
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
            hookVerifyCallback(args[2], 'export');
        }
    });
    return true;
}

// Strategy B: hook the two verify callbacks at their confirmed offsets (this build only).
function hookOffsets() {
    if (didHookOffsets) return true;
    var mod = findModule(CONFIG.module);
    if (mod === null) return false;
    didHookOffsets = true;
    log('OFFSET fallback on ' + CONFIG.module + ' base=' + mod.base);
    CONFIG.callbackOffsets.forEach(function (off) {
        hookVerifyCallback(mod.base.add(off), 'offset:0x' + off.toString(16));
    });
    return true;
}

// Poll until the target module is present and we've installed a hook.
function startPolling() {
    var elapsed = 0;
    var announcedModule = false;

    // Best case: everything is already available right now.
    if (hookExport()) return;

    var timer = setInterval(function () {
        elapsed += CONFIG.pollMs;

        // Prefer the export (covers TLS + QUIC, version-robust).
        if (hookExport()) { clearInterval(timer); return; }

        // If the module is loaded but the export is unresolvable, fall back to offsets.
        var mod = findModule(CONFIG.module);
        if (mod !== null) {
            if (!announcedModule) { announcedModule = true; log(CONFIG.module + ' present @ ' + mod.base); }
            if (hookOffsets()) { clearInterval(timer); return; }
        }

        if (elapsed >= CONFIG.pollTimeoutMs) {
            clearInterval(timer);
            log('gave up after ' + (CONFIG.pollTimeoutMs / 1000) + 's; module loaded=' + (mod !== null) +
                '. Try attach mode (-F) or verify the target uses ' + CONFIG.module + '.');
        }
    }, CONFIG.pollMs);
}

function main() {
    log('starting; target ' + CONFIG.module + ' (polling every ' + CONFIG.pollMs + 'ms)');
    startPolling();
}

setImmediate(main);
