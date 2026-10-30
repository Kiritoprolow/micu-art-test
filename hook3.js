'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
function listAll() {
    log('--- ALL MODULES ---');
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf('Mixu') >= 0 || m.name.indexOf('arm64-v8a') >= 0 || m.name.indexOf('QuyMixu') >= 0) log('  * ' + m.name + ' base=' + m.base + ' size=' + m.size + ' path=' + m.path);
    });
    log('--- END ---');
}
function scanEngine(m) {
    log('=== SCAN ' + m.name + ' base=' + m.base + ' size=' + m.size + ' ===');
    var patterns = ['Dang Nhap','Nhap key','Get Key','Ky Tu','tiep tuc','MixuKey','mixu|dm','12/2030','HH9RyWZq','cmdli/files','da duoc cap','Ban Quyen','noban','banned','_devices','panel_targets'];
    patterns.forEach(function (pat) {
        var hexpat = pat.split('').map(function (c) { return ('0' + c.charCodeAt(0).toString(16)).slice(-2); }).join(' ');
        try {
            var res = Memory.scanSync(m.base, m.size, hexpat);
            if (res.length) log('  STR "' + pat + '" x' + res.length + ' @ ' + res[0].address + ' (base+' + res[0].address.sub(m.base) + ')');
            else log('  STR "' + pat + '" NOT FOUND');
        } catch (e) { log('  err ' + pat + ': ' + e); }
    });
    try { var exps = m.enumerateExports(); log('  exports=' + exps.length); exps.slice(0,30).forEach(function (e) { log('    ' + e.type + ' ' + e.name + ' @ ' + e.address); }); } catch (e) { }
    ['zygisk_module_entry','mixu_start','panel_gate','panel_auth','JNI_OnLoad'].forEach(function (n) {
        var a = null; try { a = m.findExportByName(n); } catch (e) { }
        if (!a) { try { a = Module.findGlobalExportByName(n); } catch (e) { } }
        log('  sym ' + n + ' = ' + a);
    });
}
function hookLog() {
    var p = null; try { p = Module.getGlobalExportByName('__android_log_print'); } catch (e) { }
    if (!p) { try { p = Module.findGlobalExportByName('__android_log_print'); } catch (e) { } }
    if (!p) { log('no log fn'); return; }
    Interceptor.attach(p, { onEnter: function (args) {
        try { var tag = args[1].readUtf8String(); if (tag && (tag.indexOf('Mixu') >= 0 || tag.indexOf('zygisk') >= 0)) log('LOG ' + tag + ' | ' + args[2].readUtf8String()); } catch (e) { }
    }});
    log('hooked log');
}
function hookDlopen() {
    ['dlopen','android_dlopen_ext'].forEach(function (fn) {
        var p = null; try { p = Module.getGlobalExportByName(fn); } catch (e) { }
        if (!p) { try { p = Module.findGlobalExportByName(fn); } catch (e) { } }
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function (args) { try { var n = args[0].readCString(); if (n && n.indexOf('Mixu') >= 0) { log('DLOPEN ' + n); this.t = n; } } catch (e) { } },
            onLeave: function (ret) { if (this.t) { log('DLOPEN done ' + this.t + ' -> ' + ret); setTimeout(listAll, 300); } }
        });
        log('hooked ' + fn);
    });
}
setImmediate(function () {
    log('=== v3 ' + ts() + ' ===');
    hookLog(); hookDlopen(); listAll();
    Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('arm64-v8a') >= 0 || m.name.indexOf('Mixu') >= 0) scanEngine(m); });
    setTimeout(function () { log('--- rescan 15s ---'); listAll();
        Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('arm64-v8a') >= 0 || m.name.indexOf('Mixu') >= 0) scanEngine(m); });
    }, 15000);
    log('=== armed ===');
});
