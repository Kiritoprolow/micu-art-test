'use strict';
function log(s) { try { send('[micu] ' + s); } catch (e) { console.log('[micu] ' + s); } }
function ts() { return new Date().toISOString().substr(11, 12); }
var BASE = ptr('0x7b9982d000');
function parseElf() {
    var hdr = new Uint8Array(BASE.readByteArray(64));
    var dv = new DataView(hdr.buffer);
    var e_entry = Number(dv.getBigUint64(0x18, true));
    var e_phoff = Number(dv.getBigUint64(0x20, true));
    var e_phentsize = dv.getUint16(0x36, true);
    var e_phnum = dv.getUint16(0x38, true);
    log('ELF entry=0x' + e_entry.toString(16) + ' phoff=0x' + e_phoff.toString(16) + ' phnum=' + e_phnum);
    for (var i = 0; i < e_phnum; i++) {
        var off = e_phoff + i * e_phentsize;
        var ph = new Uint8Array(BASE.add(off).readByteArray(56));
        var pdv = new DataView(ph.buffer);
        var p_type = pdv.getUint32(0, true);
        if (p_type !== 1) continue;
        var p_flags = pdv.getUint32(4, true);
        var p_offset = Number(pdv.getBigUint64(8, true));
        var p_vaddr = Number(pdv.getBigUint64(16, true));
        var p_filesz = Number(pdv.getBigUint64(32, true));
        log('  LOAD off=0x' + p_offset.toString(16) + ' vaddr=0x' + p_vaddr.toString(16) + ' filesz=0x' + p_filesz.toString(16) + ' flags=' + p_flags + (p_flags & 1 ? ' [X]' : ''));
    }
    return e_entry;
}
function findSyms() {
    var hdr = new Uint8Array(BASE.readByteArray(64));
    var dv = new DataView(hdr.buffer);
    var e_shoff = Number(dv.getBigUint64(0x28, true));
    var e_shentsize = dv.getUint16(0x3a, true);
    var e_shnum = dv.getUint16(0x3c, true);
    log('shoff=0x' + e_shoff.toString(16) + ' shnum=' + e_shnum);
    var dynsym = null, dynstr = null;
    for (var i = 0; i < e_shnum; i++) {
        var so = e_shoff + i * e_shentsize;
        if (so + 64 > 14000000) break;
        var sh = new Uint8Array(BASE.add(so).readByteArray(64));
        var sdv = new DataView(sh.buffer);
        var sh_type = sdv.getUint32(4, true);
        var sh_addr = Number(sdv.getBigUint64(16, true));
        var sh_off = Number(sdv.getBigUint64(24, true));
        var sh_size = Number(sdv.getBigUint64(32, true));
        if (sh_type === 11) dynsym = { addr: sh_addr, off: sh_off, size: sh_size };
        if (sh_type === 3 && !dynstr) dynstr = { addr: sh_addr, off: sh_off, size: sh_size };
    }
    log('dynsym=' + (dynsym ? '0x' + dynsym.addr.toString(16) + ' size=' + dynsym.size : 'null'));
    if (!dynsym) return;
    var n = Math.floor(dynsym.size / 24);
    for (var j = 0; j < n; j++) {
        var eo = dynsym.off + j * 24;
        var e = new Uint8Array(BASE.add(eo).readByteArray(24));
        var edv = new DataView(e.buffer);
        var st_name = edv.getUint32(0, true);
        var st_value = Number(edv.getBigUint64(8, true));
        var st_size = Number(edv.getBigUint64(16, true));
        if (st_name === 0) continue;
        try {
            var nm = BASE.add((dynstr ? dynstr.off : 0) + st_name).readCString();
            if (nm && (nm.indexOf('zygisk') >= 0 || nm.indexOf('mixu') >= 0 || nm.indexOf('panel') >= 0 || nm.indexOf('entry') >= 0)) log('  SYM ' + nm + ' value=0x' + st_value.toString(16) + ' size=' + st_size);
        } catch (err) { }
    }
}
setImmediate(function () { log('=== v7 ' + ts() + ' ==='); parseElf(); findSyms(); log('=== done ==='); });
