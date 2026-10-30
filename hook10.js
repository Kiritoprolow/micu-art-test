'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var BRIDGE = null;
var OFF = { panel_gate: 0x9eec, panel_auth: 0x96c8, state: 0xa140 };
var cnt = { panel_gate: 0, panel_auth: 0, state: 0 };
setImmediate(function () {
    log('=== v10 ' + ts() + ' ===');
    Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('MixuPanelBridge') >= 0) BRIDGE = m; });
    if (!BRIDGE) { log('bridge not found'); return; }
    var base = BRIDGE.base;
    log('base=' + base);
    Object.keys(OFF).forEach(function (name) {
        var addr = base.add(OFF[name]);
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    cnt[name]++;
                    if (name === 'panel_gate') {
                        this.out = args[0];
                        var s = 'null';
                        try { if (!args[0].isNull()) s = args[0].toString(); } catch (e) { }
                        log('#' + cnt[name] + ' panel_gate(out=' + s + ')');
                    } else if (name === 'state') {
                        var why = '?';
                        try { if (!args[4].isNull()) why = args[4].readCString(); } catch (e) { }
                        log('#' + cnt[name] + ' state(active=' + args[2].toInt32() + ' remain=' + args[3].toString() + ' why=' + why + ')');
                    } else {
                        log('#' + cnt[name] + ' ' + name + '()');
                    }
                },
                onLeave: function (ret) {
                    if (name === 'panel_gate') {
                        var orig = ret.toInt32();
                        var outv = -1;
                        try { if (this.out && !this.out.isNull()) outv = this.out.readU64().toString(); } catch (e) { }
                        log('#' + cnt[name] + ' panel_gate ORIG ret=' + orig + ' *out=' + outv + '  -> FORCED 1');
                        ret.replace(ptr(1));
                        try { if (this.out && !this.out.isNull()) this.out.writeU64(1); } catch (e) { log('  out write skipped: ' + e); }
                    } else if (name === 'panel_auth') {
                        log('#' + cnt[name] + ' panel_auth ORIG ret=' + ret.toInt32() + ' -> FORCED 1');
                        ret.replace(ptr(1));
                    } else if (name === 'state') {
                        log('#' + cnt[name] + ' state done');
                    }
                }
            });
            log('  hooked ' + name);
        } catch (e) { log('  FAIL ' + name + ': ' + e); }
    });
    log('=== armed ===');
});
