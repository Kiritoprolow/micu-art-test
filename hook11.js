'use strict';
/* v11 - cho bridge load roi moi hook, force gate=1 */
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }

var OFF = { panel_gate: 0x9eec, panel_auth: 0x96c8, state: 0xa140, mixu_start: 0x94f4 };
var cnt = { panel_gate: 0, panel_auth: 0, state: 0, mixu_start: 0 };
var HOOKED = false;

function findBridge() {
    var b = null;
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf('MixuPanelBridge') >= 0) b = m;
    });
    return b;
}

function doHook(base) {
    if (HOOKED) return;
    HOOKED = true;
    log('>>> HOOKING at base=' + base);
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
                    } else if (name === 'mixu_start') {
                        log('#' + cnt[name] + ' mixu_start(base=' + args[0] + ' vm=' + args[1] + ' env=' + args[2] + ' mod=' + args[3] + ')');
                    } else {
                        log('#' + cnt[name] + ' ' + name + '()');
                    }
                },
                onLeave: function (ret) {
                    if (name === 'panel_gate') {
                        var o = ret.toInt32(), ov = -1;
                        try { if (this.out && !this.out.isNull()) ov = this.out.readU64().toString(); } catch (e) { }
                        log('#' + cnt[name] + ' panel_gate ORIG ret=' + o + ' *out=' + ov + ' => FORCE 1');
                        ret.replace(ptr(1));
                        try { if (this.out && !this.out.isNull()) this.out.writeU64(1); } catch (e) { }
                    } else if (name === 'panel_auth') {
                        log('#' + cnt[name] + ' panel_auth ORIG ret=' + ret.toInt32() + ' => FORCE 1');
                        ret.replace(ptr(1));
                    } else if (name === 'state') {
                        log('#' + cnt[name] + ' state done');
                    } else {
                        log('#' + cnt[name] + ' ' + name + ' ret=' + ret.toInt32());
                    }
                }
            });
            log('    hooked ' + name);
        } catch (e) { log('    FAIL ' + name + ': ' + e); }
    });
    log('=== ARMED ===');
}

/* poll moi 300ms, toi 40 lan */
var tries = 0;
var iv = setInterval(function () {
    tries++;
    var b = findBridge();
    if (b) {
        clearInterval(iv);
        log('bridge found sau ' + tries + ' lan: ' + b.base + ' size=' + b.size);
        doHook(b.base);
    } else if (tries === 1) {
        log('cho bridge load... (lan ' + tries + ')');
    } else if (tries > 40) {
        clearInterval(iv);
        log('HET CHO sau 40 lan, khong thay bridge');
        log('modules: ' + Process.enumerateModules().length);
    }
}, 300);

log('=== v11 ' + ts() + ' module count=' + Process.enumerateModules().length + ' ===');
