/*
 * Cronet / BoringSSL SSL-Pinning bypass (TikTok / Douyin / ByteDance / Ali-Cronet family)
 *
 * Theory:
 *   ByteDance apps ship Google's Cronet stack (Chromium net + BoringSSL). Certificate
 *   verification (incl. SSL Pinning) is registered via:
 *
 *       void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode,
 *           enum ssl_verify_result_t (*callback)(SSL *ssl, uint8_t *out_alert));
 *
 *   The callback returns: 0 = ssl_verify_ok, 1 = ssl_verify_invalid, 2 = ssl_verify_retry.
 *   Forcing the callback to return 0 makes every peer certificate pass -> MITM works.
 *
 * Strategy (in order of robustness):
 *   A. EXPORT  - hook SSL_CTX_set_custom_verify by name, then hook arg[2] (the callback),
 *                force its return value to 0. Works whenever the symbol is exported.
 *   B. OFFSET  - if the symbol is stripped, hook the verify function at a version-specific
 *                file offset (found via IDA) and force retval 0. Fill CONFIG.offsets.
 *
 * Module detection: this template POLLS for the target module on an interval AND watches
 * dlopen/android_dlopen_ext. Polling is the reliable path — newer ByteDance builds load
 * libsscronet.so via bytehook/custom loaders that never hit the dlopen exports, so a
 * dlopen-only approach silently fails to install the hook.
 *
 * Usage:
 *   frida -U -f com.zhiliaoapp.musically -l cronet_ssl_bypass.js   # TikTok
 *   frida -U -f com.ss.android.ugc.aweme  -l cronet_ssl_bypass.js   # Douyin
 *
 * Tune CONFIG below for your target/version.
 */

'use strict';

var CONFIG = {
    // Modules that may contain SSL_CTX_set_custom_verify. First match wins per module.
    // Add/remove based on `nm -D`/grep results for your target.
    modules: [
        'libsscronet.so',      // ByteDance Cronet (TikTok/Douyin)
        'libcronet.so',        // stock Cronet / other apps
        'libttboringssl.so',   // ByteDance BoringSSL
        'libvcnverify.so',     // ByteDance vcn verify wrapper
        'libttmverify.so'      // ByteDance ttm verify wrapper
    ],

    // OFFSET fallback: module -> file offset of the custom_verify function (from IDA).
    // Only used when the export is not found. Example: { 'libsscronet.so': 0x33D05C }
    offsets: {
        // 'libsscronet.so': 0x33D05C,   // e.g. ByteDance 34.6.0 (verify func, force retval 0)
    },

    pollMs: 200,             // poll interval for module/export detection
    pollTimeoutMs: 60000,    // stop polling after this long
    printBacktrace: false,   // print native backtrace when the entry point is hit
    verbose: true            // log module loads and hook installs
};

var installedExport = {};    // module -> true  (SSL_CTX_set_custom_verify hooked)
var installedOffset = {};    // module -> true
var hookedCallbacks = {};    // callback addr string -> true

function log(msg) { if (CONFIG.verbose) console.log('[cronet-ssl] ' + msg); }

function findModuleByName(name) {
    if (Process.findModuleByName) return Process.findModuleByName(name);
    try { return Process.getModuleByName(name); } catch (_) { return null; }
}

function fmtAddr(addr) {
    var mod = Process.findModuleByAddress(addr);
    if (mod === null) return addr.toString();
    return mod.name + '!0x' + addr.sub(mod.base).toString(16);
}

function findExport(moduleName, symbol) {
    var mod = findModuleByName(moduleName);
    if (mod === null) return null;
    try { if (mod.getExportByName) return mod.getExportByName(symbol); } catch (_) {}
    try { if (Module.getExportByName) return Module.getExportByName(moduleName, symbol); } catch (_) {}
    try { if (Module.findExportByName) return Module.findExportByName(moduleName, symbol); } catch (_) {}
    return null;
}

// Hook the verify callback: enum ssl_verify_result_t (*)(SSL*, uint8_t*). Force ret 0.
function hookVerifyCallback(cbPtr, sourceModule) {
    if (cbPtr === null || cbPtr.isNull()) return;
    var key = cbPtr.toString();
    if (hookedCallbacks[key]) return;
    hookedCallbacks[key] = true;

    log('hook verify callback ' + cbPtr + ' (' + fmtAddr(cbPtr) + ') from ' + sourceModule);
    try {
        Interceptor.attach(cbPtr, {
            onLeave: function (retval) {
                if (!retval.equals(0)) {
                    log('force verify result ' + retval + ' -> 0 (ssl_verify_ok) [' + sourceModule + ']');
                    retval.replace(0);
                }
            }
        });
    } catch (e) {
        console.error('[cronet-ssl] failed to hook callback ' + cbPtr + ': ' + e);
    }
}

// Strategy A: hook the exported SSL_CTX_set_custom_verify, capture arg[2] callback.
function hookExport(moduleName) {
    if (installedExport[moduleName]) return true;
    var addr = findExport(moduleName, 'SSL_CTX_set_custom_verify');
    if (addr === null) return false;

    installedExport[moduleName] = true;
    log('hook SSL_CTX_set_custom_verify @ ' + addr + ' (' + fmtAddr(addr) + ') in ' + moduleName);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            var caller = Process.findModuleByAddress(this.returnAddress);
            log('SSL_CTX_set_custom_verify hit | caller=' + (caller ? caller.name : 'unknown') +
                ' | mode=' + args[1] + ' | cb=' + args[2]);
            if (CONFIG.printBacktrace) {
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
            hookVerifyCallback(args[2], moduleName);
        }
    });
    return true;
}

// Strategy B: offset fallback for stripped symbols. Hook verify func, force retval 0.
function hookOffset(moduleName) {
    if (installedOffset[moduleName]) return true;
    var off = CONFIG.offsets[moduleName];
    if (off === undefined || off === null) return false;
    var mod = findModuleByName(moduleName);
    if (mod === null) return false;

    var target = mod.base.add(off);
    installedOffset[moduleName] = true;
    log('OFFSET fallback: hook ' + moduleName + '!0x' + off.toString(16) + ' @ ' + target);

    Interceptor.attach(target, {
        onLeave: function (retval) {
            log('offset verify ' + retval + ' -> 0 [' + moduleName + ']');
            retval.replace(0);
        }
    });
    return true;
}

function tryHookModule(moduleName) {
    if (hookExport(moduleName)) return true;
    if (hookOffset(moduleName)) return true;
    return false;
}

function scanLoaded() {
    var any = false;
    CONFIG.modules.forEach(function (m) {
        if (findModuleByName(m) !== null) { if (tryHookModule(m)) any = true; }
    });
    return any;
}

// Catch modules that load after startup via dlopen / android_dlopen_ext.
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

// Poll until at least one target module is hooked. Reliable regardless of loader.
function startPolling() {
    if (scanLoaded()) return;   // best case: already loaded

    var elapsed = 0;
    var timer = setInterval(function () {
        elapsed += CONFIG.pollMs;
        if (scanLoaded()) { clearInterval(timer); return; }
        if (elapsed >= CONFIG.pollTimeoutMs) {
            clearInterval(timer);
            log('gave up after ' + (CONFIG.pollTimeoutMs / 1000) + 's; no target module hooked. ' +
                'Check the module list in CONFIG, or try attach mode (-F).');
        }
    }, CONFIG.pollMs);
}

function main() {
    log('starting; target modules: ' + CONFIG.modules.join(', ') +
        ' (polling every ' + CONFIG.pollMs + 'ms)');
    watchDlopen();     // catch future loads (belt-and-suspenders alongside polling)
    startPolling();    // primary: poll for already/late-loaded modules
}

setImmediate(main);
