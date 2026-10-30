'use strict';
/* v13 - bat backtrace tai cho log UI66/access_bit de tim ham gate trong engine */
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }

var ENGINE = null;
function findEngine() {
    var best = null;
    Process.enumerateRanges('r-x').forEach(function (r) {
        if (r.file) return;
        if (r.size < 1000000) return;
        try {
            var a = new Uint8Array(r.base.readByteArray(4));
            if (a[0] === 0x7f && a[1] === 0x45 && a[2] === 0x4c && a[3] === 0x46) {
                if (!best || r.size > best.size) best = { base: r.base, size: r.size };
            }
        } catch (e) { }
    });
    return best;
}

setImmediate(function () {
    log('=== v13 ' + ts() + ' ===');
    ENGINE = findEngine();
    if (ENGINE) log('ENGINE anon ELF base=' + ENGINE.base + ' size=' + ENGINE.size);
    else log('engine anon ELF NOT found');

    var p = null;
    try { p = Module.getGlobalExportByName('__android_log_print'); } catch (e) { }
    if (!p) { try { p = Module.findGlobalExportByName('__android_log_print'); } catch (e) { } }
    if (!p) { log('no log fn'); return; }

    Interceptor.attach(p, {
        onEnter: function (a) {
            try {
                var tag = a[1].readCString();
                if (!tag || tag.indexOf('Mixu') < 0) return;
                var fmt = a[2].readCString();
                if (!fmt) return;
                /* chi quan tam dong co access_bit / GATE / phase */
                if (fmt.indexOf('access_bit') < 0 && fmt.indexOf('GATE') < 0 && fmt.indexOf('phase') < 0) return;
                log('LOG ' + tag + ' | ' + fmt);
                var bt = Thread.backtrace(this.context, Backtracer.FUZZY);
                bt.slice(0, 10).forEach(function (addr, i) {
                    var off = '';
                    if (ENGINE && addr.compare(ENGINE.base) >= 0 && addr.compare(ENGINE.base.add(ENGINE.size)) < 0) {
                        off = '  <== ENGINE +0x' + addr.sub(ENGINE.base).toString(16);
                    }
                    var sym = DebugSymbol.fromAddress(addr);
                    log('   #' + i + ' ' + addr + ' ' + (sym.name || '?') + off);
                });
            } catch (e) { }
        }
    });
    log('=== log hook armed ===');
});
