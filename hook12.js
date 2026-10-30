'use strict';
/* v12 - hook log __android_log_print, theo doi UI66 phase/access_bit, ep gate */
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }

var OFF = { panel_gate: 0x9eec, panel_auth: 0x96c8, state: 0xa140, mixu_start: 0x94f4 };
var done = {}, cnt = {};

function findBridge() {
    var r = null;
    Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('MixuPanelBridge') >= 0) r = m; });
    return r;
}

function hookAll(m) {
    var base = m.base;
    log('HOOKING base=' + base + ' size=' + m.size);
    Object.keys(OFF).forEach(function (name) {
        if (done[name]) return;
        var addr = base.add(OFF[name]);
        try {
            Interceptor.attach(addr, {
                onEnter: function (a) {
                    cnt[name] = (cnt[name] || 0) + 1;
                    if (name === 'panel_gate') { this.out = a[0]; }
                    else if (name === 'state') {
                        var why = '?'; try { if (!a[4].isNull()) why = a[4].readCString(); } catch (e) { }
                        log('#' + cnt[name] + ' state(active=' + a[2].toInt32() + ' remain=' + a[3].toString() + ' why=' + why + ')');
                    } else if (name === 'mixu_start') {
                        log('#' + cnt[name] + ' mixu_start(base=' + a[0] + ' env=' + a[2] + ')');
                    } else { log('#' + cnt[name] + ' ' + name); }
                },
                onLeave: function (ret) {
                    if (name === 'panel_gate') {
                        var o = ret.toInt32(), ov = -1;
                        try { if (this.out && !this.out.isNull()) ov = this.out.readU64().toString(); } catch (e) { }
                        log('#' + cnt[name] + ' panel_gate ORIG=' + o + ' out=' + ov + ' => FORCE 1');
                        ret.replace(ptr(1));
                        try { if (this.out && !this.out.isNull()) this.out.writeU64(1); } catch (e) { }
                    } else if (name === 'panel_auth') {
                        log('#' + cnt[name] + ' panel_auth ORIG=' + ret.toInt32() + ' => FORCE 1');
                        ret.replace(ptr(1));
                    }
                }
            });
            done[name] = true;
            log('  hooked ' + name);
        } catch (e) { log('  FAIL ' + name + ': ' + e); }
    });
}

/* hook log de bat UI66 */
function hookLog() {
    var p = null;
    try { p = Module.getGlobalExportByName('__android_log_print'); } catch (e) { }
    if (!p) { try { p = Module.findGlobalExportByName('__android_log_print'); } catch (e) { } }
    if (!p) { log('no log fn'); return; }
    Interceptor.attach(p, {
        onEnter: function (a) {
            try {
                var fmt = a[2].readCString();
                if (fmt && (fmt.indexOf('UI66') >= 0 || fmt.indexOf('GATE66') >= 0 || fmt.indexOf('DIAG66') >= 0 || fmt.indexOf('access_bit') >= 0)) {
                    var tag = '?'; try { tag = a[1].readCString(); } catch (e) { }
                    log('LOG[' + tag + '] ' + fmt);
                }
            } catch (e) { }
        }
    });
    log('hooked log');
}

var tries = 0;
function tick() {
    tries++;
    var m = findBridge();
    if (m) { hookAll(m); if (done.panel_gate) { log('=== ARMED ==='); return; } }
    if (tries < 400) setTimeout(tick, 250);
    else log('GIVE UP ' + tries);
}

setImmediate(function () {
    log('=== v12 ' + ts() + ' modules=' + Process.enumerateModules().length + ' ===');
    hookLog();
    tick();
});
