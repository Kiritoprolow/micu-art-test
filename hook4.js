'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
function listAll(tag) {
    var mods = Process.enumerateModules();
    log('--- ' + tag + ' : ' + mods.length + ' modules ---');
    log('  modules > 3MB:');
    mods.forEach(function (m) { if (m.size > 3000000) log('    ' + m.name + ' base=' + m.base + ' size=' + m.size + ' path=' + m.path); });
    log('  modules chua mixu/v8a/haegin/quy:');
    mods.forEach(function (m) {
        var n = m.name.toLowerCase();
        if (n.indexOf('mixu') >= 0 || n.indexOf('v8a') >= 0 || n.indexOf('haegin') >= 0 || n.indexOf('quy') >= 0) log('    ' + m.name + ' base=' + m.base + ' size=' + m.size);
    });
    log('--- END ' + tag + ' ---');
}
function hookMmap() {
    var p = null; try { p = Module.getGlobalExportByName('mmap'); } catch (e) { }
    if (!p) { try { p = Module.findGlobalExportByName('mmap'); } catch (e) { } }
    if (p) {
        Interceptor.attach(p, {
            onEnter: function (args) { this.len = args[1].toInt32(); this.prot = args[2].toInt32(); },
            onLeave: function (ret) { if (this.len > 3000000 && !ret.isNull() && this.len < 30000000) log('MMAP size=' + this.len + ' prot=' + this.prot + ' -> ' + ret); }
        });
        log('hooked mmap');
    }
    var q = null; try { q = Module.getGlobalExportByName('fopen'); } catch (e) { }
    if (!q) { try { q = Module.findGlobalExportByName('fopen'); } catch (e) { } }
    if (q) {
        Interceptor.attach(q, { onEnter: function (a) {
            try { var s = a[0].readUtf8String(); if (s && (s.indexOf('Mixu') >= 0 || s.indexOf('v8a') >= 0 || s.indexOf('Quy') >= 0)) log('FOPEN ' + s); } catch (e) { }
        }});
    }
}
setImmediate(function () {
    log('=== v4 ' + ts() + ' ===');
    listAll('initial'); hookMmap();
    setTimeout(function () { listAll('after 8s'); }, 8000);
    setTimeout(function () { listAll('after 20s'); }, 20000);
    log('=== armed ===');
});
