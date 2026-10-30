'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var BRIDGE = null;
var OFF = { mixu_start: 0x94f4, panel_auth: 0x96c8, panel_gate: 0x9eec, state: 0xa140 };
var counts = { mixu_start: 0, panel_auth: 0, panel_gate: 0, state: 0 };
setImmediate(function () {
    log('=== v9 ' + ts() + ' ===');
    Process.enumerateModules().forEach(function (m) { if (m.name.indexOf('MixuPanelBridge') >= 0) BRIDGE = m; });
    if (!BRIDGE) { log('bridge not found'); return; }
    var elfBase = BRIDGE.base;
    log('bridge base=' + elfBase + ' size=' + BRIDGE.size);
    Object.keys(OFF).forEach(function (name) {
        var addr = elfBase.add(OFF[name]);
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    counts[name]++;
                    if (name === 'mixu_start') log('[' + counts[name] + '] >> mixu_start base=' + args[0] + ' vm=' + args[1] + ' env=' + args[2] + ' mod=' + args[3]);
                    else if (name === 'panel_gate') this.out = args[0];
                    else if (name === 'state') { var why = '?'; try { why = args[4].readCString(); } catch (e) { } log('[' + counts[name] + '] >> state active=' + args[2].toInt32() + ' remain=' + args[3].toString() + ' why=' + why); }
                },
                onLeave: function (ret) {
                    if (name === 'panel_gate') {
                        var outv = 'n/a'; try { outv = this.out.readU64().toString(); } catch (e) { }
                        log('[' + counts[name] + '] << panel_gate ret=' + ret.toInt32() + ' *out=' + outv);
                        ret.replace(ptr(1)); try { this.out.writeU64(1); } catch (e) { }
                    } else if (name === 'panel_auth') log('[' + counts[name] + '] << panel_auth ret=' + ret.toInt32());
                    else if (name === 'mixu_start') log('[' + counts[name] + '] << mixu_start ret=' + ret.toInt32());
                }
            });
            log('  hooked ' + name + ' @ ' + addr);
        } catch (e) { log('  FAILED ' + name + ': ' + e); }
    });
    log('=== armed (FORCING gate=1) ===');
});
