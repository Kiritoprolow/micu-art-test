#!/usr/bin/env python3
import sys, os, shutil, hashlib

MAGIC_OFFS = [14402656,14403168,14403680,14404216,14409888,14410848,14411360,14411872,14412384,14412896,14413408]
CSET_OFFS  = [14411372,14412388,14412900,14413412]
NEW_CMP = bytes.fromhex('7f010b6b')
NEW_MOV = bytes.fromhex('23008052')

def main():
    path = sys.argv[1]
    data = bytearray(open(path,'rb').read())
    print('size=%d' % len(data))
    bak = path + '.orig'
    if not os.path.exists(bak):
        shutil.copyfile(path, bak); print('backup -> %s' % bak)
    changed = 0
    for off in MAGIC_OFFS:
        cur = bytes(data[off:off+4])
        if cur[3] != 0x6b:
            print('  SKIP magic 0x%x %s' % (off, cur.hex())); continue
        data[off:off+4] = NEW_CMP; changed += 1
        print('  0x%x %s -> %s cmp w11,w11' % (off, cur.hex(), NEW_CMP.hex()))
    for off in CSET_OFFS:
        cur = bytes(data[off:off+4])
        if cur[3] != 0x1a:
            print('  SKIP cset 0x%x %s' % (off, cur.hex())); continue
        data[off:off+4] = NEW_MOV; changed += 1
        print('  0x%x %s -> %s mov w3,#1' % (off, cur.hex(), NEW_MOV.hex()))
    if changed == 0:
        print('KHONG VA DUOC'); return 2
    open(path,'wb').write(data)
    print('da va %d/%d' % (changed, len(MAGIC_OFFS)+len(CSET_OFFS)))
    print('sha256=%s' % hashlib.sha256(bytes(data)).hexdigest())
    return 0

if __name__ == '__main__':
    sys.exit(main())
