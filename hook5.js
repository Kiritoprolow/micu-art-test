'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
function findEngineByRva() {
    log('--- tim engine qua RVA 0x14f2074 ---');
    var hits = [];
    Process.enumerateRanges('r-x').forEach(function (r) {
        if (r.size < 5000000) return;
        try {
            var addr = r.base.add(0x14f2074);
            if (addr.compare(r.base) < 0 || addr.compare(r.base.add(r.size)) >= 0) return;
            log('  candidate base=' + r.base + ' size=' + r.size + ' file=' + (r.file ? r.file.path : 'ANON'));
            hits.push(r);
        } catch (e) { }
    });
    log('  candidates=' + hits.length);
}
function listAnonExec() {
    log('--- anonymous exec ranges > 1MB ---');
    Process.enumerateRanges('r-x').forEach(function (r) {
        if (r.size > 1000000) log('  ' + r.base + ' size=' + r.size + ' file=' + (r.file ? r.file.path : 'ANON'));
    });
}
setImmediate(function () {
    log('=== v5 ' + ts() + ' ===');
    listAnonExec(); findEngineByRva();
    log('=== done ===');
});
