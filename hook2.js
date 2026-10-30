'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var ENGINE = null, SCANNED = false;

function scanEngine(m) {
    if (SCANNED) return; SCANNED = true;
    log('=== SCAN ' + m.name + ' base=' + m.base + ' size=' + m.size + ' ===');
    var patterns = ['Dang Nhap','Nhap key','Get Key','Ky Tu','tiep tuc','MixuKey','mixu|dm','12/2030','HH9RyWZq','cmdli/files','da duoc cap','Ban Quyen','noban','banned','_devices'];
    patterns.forEach(function (pat) {
        var hexpat = pat.split('').map(function (c) { return ('0' + c.charCodeAt(0).toString(16)).slice(-2); }).join(' ');
        try {
            var res = Memory.scanSync(m.base, m.size, hexpat);
            if (res.length) log('  STR "' + pat + '" x' + res.length + ' @ ' + res[0].address + ' (base+' + res[0].address.sub(m.base) + ')');
            else log('  STR "' + pat + '" NOT FOUND');
        } catch (e) { log('  scan err ' + pat + ': ' + e); }
    });
    try {
        var exps = m.enumerateExports();
        log('  exports=' + exps.length);
        exps.slice(0, 40).forEach(function (e) { log('    exp ' + e.type + ' ' + e.name + ' @ ' + e.address); });
    } catch (e) { log('  no exports: ' + e); }
    ['zygisk_module_entry','mixu_start','panel_gate','panel_auth'].forEach(function (n) {
        var a = null;
        try { a = m.findExportByName(n); } catch (e) { }
        if (!a) { try { a = Module.findGlobalExportByName(n); } catch (e) { } }
        log('  sym ' + n + ' = ' + a);
    });
}

function hookDlopen() {
    ['dlopen','android_dlopen_ext','dlsym'].forEach(function (fn) {
        var p = null;
        try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        var name = args[0].readCString();
                        if (name && (name.indexOf('arm64-v8a') >= 0 || name.indexOf('Mixu') >= 0)) { log('DLOPEN "' + name + '"'); this.target = name; }
                    } catch (e) { }
                },
                onLeave: function (ret) {
                    if (this.target && !ret.isNull()) {
                        log('DLOPEN OK "' + this.target + '" handle=' + ret);
                        setTimeout(function () {
                            Process.enumerateModules().forEach(function (m) {
                                if (m.name.indexOf('arm64-v8a') >= 0 && !ENGINE) { ENGINE = m; scanEngine(m); }
                            });
                        }, 500);
                    }
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
    if (!p) return;
    Interceptor.attach(p, { onEnter: function (args) {
        try { var tag = args[1].readUtf8String(); if (tag && tag.indexOf('Mixu') >= 0) log('LOG ' + tag + ' | ' + args[2].readUtf8String()); } catch (e) { }
    }});
}

function hookFileOps() {
    ['open','openat','fopen','fopen64','access','stat','lstat'].forEach(function (fn) {
        var p = null;
        try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        try {
            Interceptor.attach(p, { onEnter: function (args) {
                try {
                    var s = (fn === 'openat') ? args[1].readUtf8String() : args[0].readUtf8String();
                    if (s && (s.indexOf('Mixu') >= 0 || s.indexOf('mixu') >= 0 || s.indexOf('Key') >= 0 || s.indexOf('cmdli') >= 0)) log('FILE ' + fn + '("' + s + '")');
                } catch (e) { }
            }});
        } catch (e) { }
    });
}

function hookExit() {
    ['abort','exit','_exit','kill','pthread_kill','raise'].forEach(function (fn) {
        var p = null;
        try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        try {
            Interceptor.attach(p, { onEnter: function (args) {
                log('EXIT ' + fn + '(' + args[0] + ') from ' + this.returnAddress);
                try { log('  bt: ' + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,8).map(function (a) { var s = DebugSymbol.fromAddress(a); return (s.name || '?') + '@' + a; }).join(' | ')); } catch (e) { }
            }});
        } catch (e) { }
    });
}

setImmediate(function () {
    log('=== micu hunter v2 ' + ts() + ' ===');
    hookLog(); hookDlopen(); hookFileOps(); hookExit();
    Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('arm64-v8a') >= 0) { ENGINE = m; scanEngine(m); } });
    log('=== armed ===');
});
