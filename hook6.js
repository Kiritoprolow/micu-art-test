'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var CAND = [ptr('0x7b9a03a000'), ptr('0x7b9982d000')];
function scanRange(base, size, tag) {
    log('=== scan ' + tag + ' base=' + base + ' size=' + size + ' ===');
    var pats = ['Dang Nhap','Nhap key','Get Key','Ky Tu','tiep tuc','MixuKey','mixu|dm','12/2030','HH9RyWZq','cmdli/files','da duoc cap','Ban Quyen','noban','banned','_devices','panel_targets','Mixu','Key'];
    pats.forEach(function (pat) {
        var hexpat = pat.split('').map(function (c) { return ('0' + c.charCodeAt(0).toString(16)).slice(-2); }).join(' ');
        try {
            var res = Memory.scanSync(base, size, hexpat);
            if (res.length) log('  STR "' + pat + '" x' + res.length + ' @ ' + res[0].address + ' (base+' + res[0].address.sub(base) + ')');
        } catch (e) { }
    });
    try {
        var arr = new Uint8Array(base.readByteArray(16));
        if (arr[0] === 0x7f && arr[1] === 0x45 && arr[2] === 0x4c && arr[3] === 0x46) log('  >>> ELF HEADER OK');
        else log('  khong phai ELF: ' + Array.from(arr).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));
    } catch (e) { log('  read err: ' + e); }
}
setImmediate(function () {
    log('=== v6 ' + ts() + ' ===');
    CAND.forEach(function (b) {
        try { var arr = new Uint8Array(b.readByteArray(16)); log('--- probe ' + b + ' : ' + Array.from(arr).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(' ')); } catch (e) { log('  probe err ' + b + ': ' + e); }
    });
    scanRange(CAND[1], 13877248, 'ANON-BIG');
    scanRange(CAND[0], 8437760, 'ANON-MID');
    log('=== done ===');
});
