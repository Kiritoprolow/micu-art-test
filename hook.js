/*
 * Micu engine license gate hunter
 */
'use strict';

var MOD = 'arm64-v8a.so';

function log(s) {
    try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); }
}
function ts() { return new Date().toISOString().substr(11, 12); }

var mods = Process.enumerateModules();
log('modules=' + mods.length);
mods.forEach(function (m) {
    if (m.name.indexOf('arm64-v8a') >= 0 || m.name.indexOf('Mixu') >= 0) {
        log('FOUND ' + m.name + ' base=' + m.base + ' size=' + m.size + ' path=' + m.path);
    }
});

function hookFileOps() {
    ['open', 'openat', 'fopen', 'fopen64', 'access', 'stat', 'lstat', 'readlinkat'].forEach(function (fn) {
        var p = null;
        try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        var s = null;
                        if (fn === 'open' || fn === 'fopen' || fn === 'fopen64' || fn === 'access' || fn === 'stat' || fn === 'lstat') {
                            s = args[0].readUtf8String();
                        } else if (fn === 'openat' || fn === 'readlinkat') {
                            s = args[1].readUtf8String();
                        }
                        if (s && (s.indexOf('Mixu') >= 0 || s.indexOf('mixu') >= 0 || s.indexOf('Key') >= 0)) {
                            log('FILE ' + fn + '("' + s + '")');
                        }
                    } catch (e) { }
                }
            });
            log('hooked ' + fn);
        } catch (e) { }
    });
}

function hookLog() {
    var p = null;
    try { p = Module.getGlobalExportByName('__android_log_print'); } catch (e) { }
    if (!p) { try { p = Module.findGlobalExportByName('__android_log_print'); } catch (e) { } }
    if (!p) { log('no __android_log_print'); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var tag = args[1].readUtf8String();
                if (tag && tag.indexOf('Mixu') >= 0) {
                    log('LOG tag=' + tag + ' fmt=' + args[2].readUtf8String());
                }
            } catch (e) { }
        }
    });
    log('hooked __android_log_print');
}

function hookExit() {
    ['abort', 'exit', '_exit', 'kill', 'pthread_kill', 'raise'].forEach(function (fn) {
        var p = null;
        try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    log('EXIT-CALL ' + fn + ' arg0=' + args[0] + ' from ' + this.returnAddress);
                    try {
                        log('  bt: ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(' | '));
                    } catch (e) { }
                }
            });
        } catch (e) { }
    });
    log('hooked exit family');
}

function scanStrings() {
    var m = null;
    Process.enumerateModules().forEach(function (x) {
        if (x.name.indexOf('arm64-v8a') >= 0) m = x;
    });
    if (!m) { log('engine module not found'); return; }
    log('scanning ' + m.name + ' base=' + m.base + ' size=' + m.size);
    var patterns = ['Dang Nhap', 'Nhap key', 'Get Key', 'Ky Tu', 'tiep tuc', 'MixuKey', 'mixu|dm', '12/2030', 'HH9RyWZq'];
    patterns.forEach(function (pat) {
        var hexpat = pat.split('').map(function (c) { return ('0' + c.charCodeAt(0).toString(16)).slice(-2); }).join(' ');
        try {
            var res = Memory.scanSync(m.base, m.size, hexpat);
            if (res.length) log('  STR "' + pat + '" x' + res.length + ' @ ' + res[0].address);
            else log('  STR "' + pat + '" NOT FOUND');
        } catch (e) { log('  scan err ' + pat + ': ' + e); }
    });
}

setImmediate(function () {
    log('=== micu hunter start ' + ts() + ' ===');
    hookLog();
    hookFileOps();
    hookExit();
    scanStrings();
    log('=== hooks armed ===');
});
