'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var BRIDGE = null;
var OFF = { mixu_start: 0x94f4, panel_auth: 0x96c8, panel_gate: 0x9eec, state: 0xa140 };
setImmediate(function () {
    log('=== v8 ' + ts() + ' ===');
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf('MixuPanelBridge') >= 0) BRIDGE = m;
    });
    if (!BRIDGE) {
        Process.enumerateRanges('r-x').forEach(function (r) {
            if (r.file && r.file.path && r.file.path.indexOf('MixuPanelBridge') >= 0) BRIDGE = { name: 'bridge', base: r.base, size: r.size, path: r.file.path };
        });
    }
    if (!BRIDGE) { log('bridge not found'); return; }
    log('bridge base=' + BRIDGE.base + ' size=' + BRIDGE.size + ' path=' + BRIDGE.path);
    var elfBase = BRIDGE.base;
    try {
        var arr = new Uint8Array(elfBase.readByteArray(4));
        if (!(arr[0] === 0x7f && arr[1] === 0x45)) {
            Process.enumerateRanges('r--').forEach(function (r) {
                if (r.file && r.file.path && r.file.path.indexOf('MixuPanelBridge') >= 0) {
                    try { var a = new Uint8Array(r.base.readByteArray(4)); if (a[0] === 0x7f && a[1] === 0x45) elfBase = r.base; } catch (e) { }
                }
            });
        }
    } catch (e) { log('elf probe err ' + e); }
    log('elfBase=' + elfBase);
    Object.keys(OFF).forEach(function (name) {
        var addr = elfBase.add(OFF[name]);
        log('  ' + name + ' @ ' + addr);
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.n = name;
                    if (name === 'mixu_start') { log('>> mixu_start base=' + args[0] + ' vm=' + args[1] + ' env=' + args[2] + ' module=' + args[3]); }
                    else if (name === 'panel_gate') { this.out = args[0]; }
                    else if (name === 'state') { log('>> state active=' + args[2] + ' remain=' + args[3]); }
                },
                onLeave: function (ret) {
                    if (this.n === 'panel_gate') { var outv = 'n/a'; try { outv = this.out.readU64(); } catch (e) { } log('<< panel_gate ret=' + ret.toInt32() + ' *out=' + outv); }
                    else if (this.n === 'panel_auth' || this.n === 'mixu_start') { log('<< ' + this.n + ' ret=' + ret.toInt32()); }
                }
            });
            log('    hooked ' + name);
        } catch (e) { log('    hook ' + name + ' FAILED: ' + e); }
    });
    log('=== armed ===');
});
