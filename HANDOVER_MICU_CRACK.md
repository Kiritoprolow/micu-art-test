# BÀN GIAO — CRACK `Micu_Module_adr.zip` (QuyMixu / "Mixu Play Together")

> File này ghi lại **toàn bộ** quá trình: cái gì xong, cái gì hỏng, tại sao, và bước tiếp theo cụ thể.
> Đọc hết trước khi làm bất cứ gì — có mấy "bẫy" đã tốn rất nhiều thời gian mới phát hiện.

---

## 0. TL;DR — Đang ở đâu

| Tầng | Trạng thái | Ghi chú |
|---|---|---|
| **Tầng 1** — license server (`libMixuPanelBridge.so`) | ✅ **XONG, đã kiểm chứng trên máy thật** | Vô hiệu RSA + `trumptg.pp.ua` hoàn toàn |
| **Tầng 2** — engine gate (`arm64-v8a.so`) | 🟡 **ĐÃ VÁ FILE, CHƯA DEPLOY** | 15 điểm vá xong, verify bằng disasm, chưa cài lên máy |
| **Xác nhận cuối** (panel có mở không) | ❌ **CHƯA CÓ** | Chưa ai nhìn thấy menu mở |

**Việc cần làm ngay:** deploy engine đã vá (mục 7) → mở game → đọc log `access_bit`.

---

## 1. Target & môi trường

### File
```
Micu_Module_adr.zip                    11.4 MB
├── module.prop                        id=QuyMixu, author=Quý Mixu, version=1
├── zygisk/arm64-v8a.so                14,462,976 B   ← ENGINE (packed/obfuscated)
├── zygisk/libMixuPanelBridge.so          58,536 B   ← LICENSE + DEX nhúng (plain)
└── META-INF/com/google/android/{update-binary, updater-script}
```

### Thiết bị đã dùng
| | Máy 1 | Máy 2 (hiện tại) |
|---|---|---|
| Model | Pixel 4 | Xiaomi 2109119BC |
| Android | 10 / SDK 29 | 13 / SDK 33 |
| Root | `su` custom (`/data/.mci/su`), **không Magisk** | **Kitsune Mask** (`io.github.huskydg.magisk`), magisk 29999 |
| SELinux | Disabled | — |
| Ghi chú | Phải dựng Zygisk thủ công bằng NeoZygisk | Magisk thật, cài module bình thường |

### App đích
`com.haegin.playtogether` — PLAY TOGETHER (Unity, launcher activity `com.google.firebase.MessagingUnityPlayerActivity`)

### Kết nối
Dùng tool `termux_run` (Termux agent polling). Shell 32-bit → **mọi phép tính offset > 2GB phải tính sẵn từ sandbox** rồi truyền literal.

---

## 2. Kiến trúc bảo vệ (đã reverse xong)

### 2.1. Sơ đồ

```
arm64-v8a.so  ::  zygisk_module_entry  (vaddr 0x1b10000)
   │  dlopen("/data/adb/modules/QuyMixu/zygisk/libMixuPanelBridge.so", RTLD_NOW)
   │  dlsym("mixu_start")
   ▼
libMixuPanelBridge.so :: mixu_start (0x94f4)
   ├── embedded_dex @ vaddr 0x790, size 0x4C3C (19,516 B)
   │      └── InMemoryDexClassLoader → vn.mixu.license.v3.*
   │            ├── Bridge.authenticate(key)
   │            │     └── ApiV3Client → POST https://trumptg.pp.ua/panel/apiv3.php
   │            │           verify SHA256withRSA (public key nhúng trong ServerKey.java)
   │            ├── SessionPolicy (deadline/revoked)
   │            └── Bridge.publish(active, remain, why)  ──JNI──▶ native state()
   │
   └── panel_gate() / panel_auth() / state()   ← cổng native
         └── ghi MAGIC 0xa17c3e5d (valid) hoặc 0x13579bdf (expired)
             vào base+0x1591510
                          │
                          ▼  (engine đọc lại)
arm64-v8a.so  ── đọc base+0x15e12e0 ── so magic ──▶ access_bit (0/1)
                                                       └──▶ panel "Mixu — Dang Nhap"
```

### 2.2. Chi tiết license v3 (Java trong DEX)

- Device binding: `sha256("mixu-panel-v3:" + ANDROID_ID)`
- Response JSON: `payload` (base64) + `signature` (base64) → verify RSA
- Payload phải thoả ĐỒNG THỜI:
  - `protocol == 3`
  - `valid_until == expires_at - 600`
  - `nonce` khớp
  - `request_hash == sha256(request bytes)`
  - `session_policy == "continue_verified_session_until_key_expiry"`
- `SessionPolicy.verifiedGrant()`: `deadline = elapsed + (expires_at - valid_until)*1000`
- `SessionPolicy.active()`: `!revoked && keyId != "" && now < deadline`

👉 **Không thể đoán key.** Server ký bằng RSA private key. Key `thangchomatle` chỉ sống nếu server còn chạy + device khớp. Crack bắt buộc patch logic verify.

### 2.3. Chi tiết engine (arm64-v8a.so)

- ELF64 DYN, arm64, `entry=0x0`, `phoff=0x40`, `phnum=10`, `shnum=31`, `e_shoff=0xd9c568`
- **`zygisk_module_entry` ở vaddr `0x1b10000`** (192 B) — trong dynsym, dùng `dlopen`+`dlsym`
- Segment `vaddr 0x1ae8000` (file offset `0xda0000`, size `0x2b000`) là **code ARM64 THẬT, không obfuscate** — đây là chỗ chứa toàn bộ gate logic
- Segment `vaddr 0x0` (file `0x0`, size `0x80c208`) phần lớn là rác/obfuscated
- Có cơ chế tự giải mã: `mprotect` (`svc #0`, `x8=0xe2`) trên vùng `0x1aea000`
- Anti-tamper: log hàng loạt `ARMED_EXIT_<hex>`, `ARMED_DIRECT_EXIT_<hex>` → tự kill process khi phát hiện sửa đổi
- Log tags: `MixuDiag66`, `MixuPanelV3`

### 2.4. Bản đồ chuỗi quan trọng trong `arm64-v8a.so`

| Chuỗi | File offset | Vaddr |
|---|---|---|
| `MixuDiag66` | `0xdac000` | `0x1af4000` |
| `GATE66 now=%llu value_a=%llu value_b=%llu` | `0xdbf480` | `0x1b07480` |
| `UI66 phase=%u width=%u height=%u` | `0xdbfa00` | `0x1b07a00` |
| **`UI66 phase=%u access_bit=%u`** | **`0xdbfa8e`** | **`0x1b07a8e`** |
| `mixu\|dm` | `0x19f13a` | `0x19f13a` |
| `=12/2030` | `0x19f1e6` | `0x19f1e6` |
| `banned` | `0x19f2d1` | `0x19f2d1` |
| `Key HH9RyWZq0TE9y11JcevV9iiLsDc9vm1Gku4` | `0x19f46b` | `0x19f46b` |
| `_devices` | `0x19f516` | `0x19f516` |
| `pKhmixuptg.zayorzBbMadj3jISoVBEtLES8LVkHLTb` | `0x19f7a1` | `0x19f7a1` |
| `9774d56d682e549ccmdli/files/MixuKey.t` (bị obfuscate chồng) | `0x19fbb6` | `0x19fbb6` |

> Lưu ý: chuỗi UI tiếng Việt (`Dang Nhap`, `Nhap key`, `Get Key`, `1764`, `Ky Tu`) **KHÔNG tồn tại** dạng plaintext ở cả file lẫn RAM (đã scan kỹ, cả ASCII lẫn UTF-16LE). Chúng được sinh runtime hoặc nằm trong font atlas.

---

## 3. ⭐ GATE LOGIC — phát hiện then chốt

Disassembly tại `0x1b06a4c` (trong segment `0x1ae8000`, code thật):

```asm
0x1b06a4c  adrp x10, #0x15e1000
0x1b06a50  add  x10, x10, #0x2e0        ; x10 = base + 0x15e12e0
0x1b06a54  ldar w10, [x10]              ; đọc magic
0x1b06a58  mov  w11, #0x3e5d
0x1b06a5c  movk w11, #0xa17c, lsl #16   ; w11 = 0xa17c3e5d  ← MAGIC VALID
0x1b06a60  cmp  w10, w11
0x1b06a64  cset w3, eq                  ; ★ access_bit = (magic khớp)
0x1b06a68  ldr  w4, [x21]
0x1b06a6c  ldr  w5, [x22]
0x1b06a70  lsl  x11, x4, #0x20
0x1b06a74  orr  x11, x11, x5
0x1b06a78  orr  x11, x11, x3, lsl #63   ; bit63 = access_bit
0x1b06a7c  adrp x10, #0x1b07000
0x1b06a80  add  x10, x10, #0x900        ; cache value
0x1b06a84  ldr  x12, [x10]
0x1b06a88  cmp  x12, x11
0x1b06a8c  b.eq #0x1b06aa0              ; nếu không đổi thì skip log
0x1b06a90  str  x11, [x10]
0x1b06a94  adrp x0, #0x1b07000
0x1b06a98  add  x0, x0, #0xa00          ; "UI66 phase=%u access_bit=%u"
0x1b06a9c  bl   #0x1aef000              ; __android_log_print
```

### Ý nghĩa
- `0xa17c3e5d` = **MAGIC VALID**, `0x13579bdf` = **MAGIC EXPIRED** (thấy trong `state()` của bridge: `mov w9,#0x3e5d ; movk w9,#0xa17c` vs `mov w9,#0x9bdf ; movk w9,#0x1357`)
- Bridge ghi magic vào `base+0x1591510`, engine đọc ở `base+0x15e12e0` — **hai tầng nối nhau bằng đúng một word**
- **`access_bit` là biến duy nhất quyết định panel hiện hay không**

### 11 chỗ load magic & 4 chỗ sinh access_bit

```
11 site load magic (0xa17c3e5d):
  0x1b04458  0x1b04658  0x1b04858  0x1b04a70  0x1b06098
  0x1b06458  0x1b06658  0x1b06858  0x1b06a58  0x1b06c58  0x1b06e58
  → lệnh `cmp w10, w11` nằm tại mỗi site + 8

4 site sinh access_bit:
  0x1b0666c  cset w3, ne
  0x1b06a64  cset w3, eq
  0x1b06c64  cset w3, eq
  0x1b06e64  cset w3, eq
```

Mỗi site ứng với một gate khác nhau: `GATE66`, `UI66`, `DIAG53..DIAG66`, `LOCAL_INIT66`.

---

## 4. ✅ TẦNG 1 — ĐÃ XONG (bridge)

### 4.1. Patch native `libMixuPanelBridge.so`

> ⚠️ File này `vaddr != file_offset` ở `.text` (delta `0x4000`). Phải map qua PT_LOAD:
> ```
> PT_LOAD  vaddr=0x0       off=0x0       filesz=0x54f4
> PT_LOAD  vaddr=0x94f4    off=0x54f4    filesz=0xdec
> PT_LOAD  vaddr=0xe2e0    off=0x62e0    filesz=0x1a8
> ```

| Vaddr | Gốc | Vá | Bytes | Tác dụng |
|---|---|---|---|---|
| `0x9f0c` | `cset w9, lo` | `mov w9, #1` | `29008052` | `panel_gate()` out-param = 1 |
| `0x9f18` | `cset w0, lo` | `mov w0, #1` | `20008052` | `panel_gate()` return = 1 |
| `0xa150` | `and w20, w2, #0xff` | `mov w20, #1` | `34008052` | `state()` force active |
| `0xa16c` | `add x8, x0, x19` | `movz x8, #0x7fff, lsl #48` | `e8ffefd2` | deadline = vô cực |
| **`0xa178`** | **`csel x9, x8, xzr, ne`** | **`mov x9, x8`** | **`e90308aa`** | **★ KHÔNG để csel ghi deadline về 0** |
| `0x9c60` | `mov w2, #0x4c3c` | `mov w2, #18292` | `82ee8852` | size DEX mới |

**`0xa178` là cái bẫy lớn nhất.** Bản vá đầu tiên chỉ sửa `0xa16c`, nhưng `csel ... ne` ngay sau đó ghi đè `x9 = 0` khi server từ chối → deadline về 0 → gate vẫn FAIL. Chỉ phát hiện được nhờ Unicorn emulation. **Nếu bỏ sót điểm này, coi như chưa vá gì.**

### 4.2. Patch DEX (Java)

Trích `embedded_dex` @ `0x790`, baksmali bằng apktool, sửa 4 method:

| Method | Bản vá |
|---|---|
| `Bridge.authenticate(String)` | trả thẳng `"valid|31/12/2099"`, vẫn gọi `publish(true, 0x7fff<<48, "ok")` |
| `SessionPolicy.active()` | `return true` |
| `SessionPolicy.remainingMillis()` | `return 0x7fff000000000000L` |
| `SessionPolicy.expired()` | `return false` |

DEX mới: **19,516 → 18,292 bytes**. Phải tính lại header: `file_size` (offset 32), SHA-1 (12..32), adler32 (8).

Nhúng ngược vào slot `0x790`, pad `0x00` tới `0x4C3C`.

### 4.3. Hash bản đúng

```
libMixuPanelBridge.so  sha256 = 6e42018662f4204d52d401d3d8f4c0d09aa03041fd5eb0c86dc2c9b9c9b8561b
                       size   = 58,536
```
> ❌ **TUYỆT ĐỐI KHÔNG dùng** `f5554b337aee24490af1fe4777c5ee9cb998ee6d7abcc2b9fd4a02731b1332a2`
> — đó là bản 4 điểm, **thiếu fix `csel`**. File `work/micu/patched/libMixuPanelBridge.so` là bản SAI này.

### 4.4. Bằng chứng đã kiểm chứng

**(a) DEX chạy trên ART thật của thiết bị** (`dalvikvm64`, đóng gói thành jar):
```
== MICU CRACKED DEX ON ART ==
key=[thangchomatle] -> valid|31/12/2099
key=[wrong_key_xyz] -> valid|31/12/2099
key=[]              -> valid|31/12/2099
key=[abcdefghijkl]  -> valid|31/12/2099
== DONE ==
```

**(b) Unicorn emulate `panel_gate()`**:
```
ORIGINAL  millis=1000000     -> panel_gate()=0  *out=0
CRACKED   millis=1000000     -> panel_gate()=1  *out=1
ORIGINAL  millis=4294967294  -> panel_gate()=0
CRACKED   millis=4294967294  -> panel_gate()=1
```

**(c) Unicorn emulate `state()`**:
```
active=0 (server từ chối):  ORIG deadline=0x0                 gate=FAIL
                            CRACK deadline=0x7fff000000000000  gate=PASS
sau 1 năm:                  ORIG deadline=0x953c0             gate=FAIL
                            CRACK deadline=0x7fff000000000000  gate=PASS
```

**(d) Trên máy — đọc RAM tiến trình đang chạy** qua `/proc/PID/map_files/`:
```
file_off=0x5f0c : 29008052   mov w9, #1
file_off=0x5f18 : 20008052   mov w0, #1
file_off=0x6150 : 34008052   mov w20, #1
file_off=0x616c : e8ffefd2   movz x8, #0x7fff, lsl 48
file_off=0x6178 : e90308aa   mov x9, x8
```
→ 5 lệnh vá sống trong RAM của **37 tiến trình** cùng lúc.

---

## 5. 🟡 TẦNG 2 — ĐÃ VÁ FILE, CHƯA DEPLOY

### 5.1. Patch engine `arm64-v8a.so`

Segment `vaddr 0x1ae8000` ↔ file `0xda0000` → `file_off = 0xda0000 + (vaddr - 0x1ae8000)`

| Loại | Số điểm | Vaddr | Gốc | Vá | Bytes |
|---|---|---|---|---|---|
| magic compare | 11 | `0x1b04460, 0x1b04660, 0x1b04860, 0x1b04a78, 0x1b060a0, 0x1b06460, 0x1b06660, 0x1b06860, 0x1b06a60, 0x1b06c60, 0x1b06e60` | `cmp w10, w11` | `cmp w11, w11` | `7f010b6b` |
| access_bit | 4 | `0x1b0666c, 0x1b06a64, 0x1b06c64, 0x1b06e64` | `cset w3, eq/ne` | `mov w3, #1` | `23008052` |

Cùng với **1 file offset** tương ứng:
```
magic cmp: 14402656 14403168 14403680 14404216 14409888 14410848
           14411360 14411872 14412384 14412896 14413408
cset     : 14411372 14412388 14412900 14413412
```

> ⚠️ Bẫy đã từng mắc: mã hoá ARM64 của `cmp wN, wM` — `Rn = (w>>5)&0x1f`, **`Rm = (w>>16)&0x1f`**. Lần đầu lấy nhầm `w0&0x1f` ra `w31` → sinh `cmp w31, w31` (vô nghĩa). Kiểm tra lại: `cmp w11, w11` = `7f010b6b`.

### 5.2. File đã vá

```
work/micu/patched3/arm64-v8a.so
size    = 14,462,976
sha256  = 4449a0a8278ef7cffafbb1fd94e831b176e483fa5c32ede7f2b39effeb6588fb
```

Verify bằng disasm (đọc lại từ file đã vá):
```
0x1b06a60  cmp  w11, w11     ✓
0x1b06a64  mov  w3, #1       ✓
0x1b06660  cmp  w11, w11     ✓
0x1b0666c  mov  w3, #1       ✓
```

### 5.3. Cách deploy — **VÁ TẠI CHỖ, KHÔNG TRUYỀN 14.4MB**

Đã viết sẵn `patch_on_device.py` — chỉ ghi **60 byte** vào file đang cài. Nhanh hơn nhiều so với upload 14.4MB qua GitHub (giới hạn 5MB/file, phải chia 4 phần).

---

## 6. ❌ NHỮNG THỨ ĐÃ THẤT BẠI / GIỚI HẠN

### 6.1. Hiểu nhầm về screenshot
Ảnh `Screenshot_2026-10-30-11-32-00-523_com.tykeji.ugphone.jpg` (app UGPhone = cloud phone client) chụp lúc **11:32**, module cài lúc **12:19** → ảnh chụp **TRƯỚC** khi cài. Nó **không** chứng minh bản vá thất bại. Nhưng cũng không có bằng chứng nào cho thấy panel đã mở — **chưa ai xác nhận được**.

### 6.2. frida — cài được nhưng không dùng được trọn vẹn

**Đã làm được:**
- `frida-server 17.24.3` → `/data/local/tmp/fs` (84.7 MB), chạy được, listen `127.0.0.1:27042`
- `frida-inject 17.24.3` → `/data/local/tmp/fi` (84.4 MB), chạy được
- Giải nén `.xz` **phải dùng Python của Termux**: `/data/data/com.termux/files/usr/bin/python3 -c "import lzma; open('fs','wb').write(lzma.open('fs.xz').read())"` — máy **không có** `xz`, toybox chỉ có `gzip`/`zcat`

**Không làm được:**
| Vấn đề | Chi tiết |
|---|---|
| Sandbox không nối được tới máy | Không có `adb`, không có IP công khai. Chỉ dùng được `termux_run`. |
| `pip install frida` trên Termux | PyPI **không có wheel** cho `android_aarch64`; build từ source fail (`failed-wheel-build-for-install`) |
| Spawn qua frida | Làm **crash `com.google.android.gms`** vì module Micu inject vào *mọi* process |
| Micu phát hiện frida | pid 59747 báo `refused to load frida-agent` |
| Hook `panel_gate` | Gây `SIGSEGV @ 0x18` — **đây là bằng chứng hook CHẠM ĐÚNG hàm** (nó được gọi), chỉ là `out`-pointer null. Sửa guard là hết. |

### 6.3. Bẫy tìm PID — RẤT tốn thời gian
```bash
# SAI: trả về process con (chỉ 8 modules)
pgrep -f com.haegin.playtogether

# ĐÚNG: lọc theo có module trong maps
for p in $(pgrep -f playtogether); do
  grep -qs MixuPanelBridge /proc/$p/maps && echo "pid=$p maps=$(wc -l < /proc/$p/maps)"
done
```
Tiến trình thật có **~6000+ maps**; process con chỉ ~100-900 maps.

PID **đổi liên tục** mỗi lần game restart (do crash hoặc force-stop).

### 6.4. Engine nạp ẨN DANH — bẫy lớn nhất
`arm64-v8a.so` **không bao giờ** xuất hiện tên file trong `/proc/PID/maps`. Nó là anonymous `mmap`.

**Cách tìm đúng:**
```javascript
Process.enumerateRanges('r-x').forEach(function (r) {
    if (r.file) return;              // chỉ vùng ẩn danh
    if (r.size < 1000000) return;
    var a = new Uint8Array(r.base.readByteArray(4));
    if (a[0]===0x7f && a[1]===0x45 && a[2]===0x4c && a[3]===0x46) {
        // ELF header → đây là engine
    }
});
```
Kết quả thực tế: base `0x7b9982d000` (size **13,877,248**) và một bản thứ hai tại `0x7b9cc49000` (size **8,437,760**).

**Hai bản trong RAM**, chứa cùng chuỗi ở offset khác nhau (`+0x19fxxx` và `+0x6a9xxx`) → nghi là **cặp chống patch**: sửa bản này thì bản kia phát hiện. Chưa xác minh.

### 6.5. Đọc `/proc/PID/mem` — shell 32-bit tràn số
```bash
# SAI: $((0x7b9ac15000/4096))  → -414699
# ĐÚNG: tính sẵn từ sandbox rồi truyền literal
dd if=/proc/$P/mem bs=1 iflag=skip_bytes,count_bytes skip=530877337600 count=65536
```
- Phải dùng `iflag=skip_bytes,count_bytes`
- `map_files/` **không** có entry cho vùng anonymous → chỉ dùng được với vùng có file backing
- Khối tối đa đọc ổn định: **64 KB** (dùng 1 MB hay bị 0 byte)

### 6.6. Lỗi môi trường lặt vặt
| Lỗi | Cách xử lý |
|---|---|
| `unzip -d ex` báo "couldn't chdir" | `mkdir -p ex` trước |
| apktool put class vào `defpackage` | Phải thêm package rõ ràng (`Lxt/Poc;`) — class ở default package (`LXTest;`) ART **không load được** |
| `dalvikvm` `ClassNotFoundException` | Do class ở default package. Đổi sang `Lxt/Poc;` là chạy |
| dex2jar → `VerifyError: stackmap frame` | Bỏ, dùng `dalvikvm` trên máy thật thay JVM |
| Maven 404 cho `smali/baksmali` | Dùng `apktool d/b` để baksmali/smali thay thế |
| `keystone` thiếu `pkg_resources` | `pip install --force-reinstall "setuptools<81"` |
| `zip` command không có | Dùng Python `zipfile` |
| Terminal trả `clean — nothing to commit` thay output | Glitch của shell. Workaround: ghi ra file rồi đọc bằng `od -c` |

### 6.7. Bước cuối bị chặn
Lần cuối chạy:
```
su -c 'cd /data/local/tmp; curl -sSL -o patch_on_device.py ...'
→ Permission denied (exit 13)
```
**Chưa rõ nguyên nhân.** Nghi: `su -c` với cwd `/data/local/tmp` + redirect. Cần thử lại với đường dẫn tuyệt đối, hoặc `chmod`, hoặc ghi vào `/sdcard/Download`.

---

## 7. ▶️ BƯỚC TIẾP THEO — làm đúng thứ tự này

### Bước 1: Deploy engine đã vá (ưu tiên: patch tại chỗ)

```bash
# 1a. Lấy script patch lên máy (thử nhiều cách)
su -c 'curl -sSL -o /data/local/tmp/pod.py \
  https://raw.githubusercontent.com/Kiritoprolow/micu-art-test/main/patch_on_device.py'
# nếu Permission denied → thử:
su -c 'cd /sdcard/Download && curl -sSL -O \
  https://raw.githubusercontent.com/Kiritoprolow/micu-art-test/main/patch_on_device.py'

# 1b. Backup TRƯỚC KHI VÁ
su -c 'cp /data/adb/modules/QuyMixu/zygisk/arm64-v8a.so /data/local/tmp/arm64-v8a.so.orig'

# 1c. Vá
su -c 'PY=/data/data/com.termux/files/usr/bin/python3; \
  $PY /data/local/tmp/pod.py /data/adb/modules/QuyMixu/zygisk/arm64-v8a.so'

# Kỳ vọng: "da va 15/15 diem"
# sha256 phải = 4449a0a8278ef7cffafbb1fd94e831b176e483fa5c32ede7f2b39effeb6588fb
```

**Cách dự phòng nếu patch tại chỗ vẫn fail:** chia `work/micu/patched3/arm64-v8a.so` thành 4 phần ≤4MB, đẩy lên `Kiritoprolow/micu-art-test`, rồi trên máy `curl` từng phần + `cat part_* > arm64-v8a.so`.

### Bước 2: Đảm bảo bridge là bản ĐÚNG
```bash
su -c 'sha256sum /data/adb/modules/QuyMixu/zygisk/libMixuPanelBridge.so'
# PHẢI là 6e42018662f4204d52d401d3d8f4c0d09aa03041fd5eb0c86dc2c9b9c9b8561b
# nếu là f5554b33... → bản SAI, phải lấy từ:
#   https://raw.githubusercontent.com/Kiritoprolow/micu-art-test/main/libMixuPanelBridge.so
```

### Bước 3: Restart và test
```bash
su -c 'am force-stop com.haegin.playtogether'
su -c 'setprop ctl.restart zygote'          # hoặc reboot máy
sleep 25
su -c 'monkey -p com.haegin.playtogether -c android.intent.category.LAUNCHER 1'
sleep 30
su -c 'logcat -d | grep MixuDiag66 | tail -20'
```

### Bước 4: Đọc kết quả — **đây là lúc biết thành công hay không**
```
Tìm dòng:  UI66 phase=0 width=1280 height=720
           UI66 phase=0 access_bit=?

access_bit=1   → ✅ THÀNH CÔNG, panel đã mở
access_bit=0   → ❌ thất bại, xem mục 8
```

### Bước 5: Nếu panel vẫn hiện
1. Kiểm tra engine có bị **verify checksum** không — tìm log `ARMED_EXIT_*` / `ARMED_DIRECT_EXIT_*` xuất hiện bất thường
2. Nếu có → tìm và NOP lệnh `kill`/`exit` trong segment `0x1ae8000`
3. Kiểm tra **bản ANON thứ hai** (`+0x6a9xxx`) — nếu engine đối chiếu 2 bản thì phải vá cả hai trong RAM (dùng frida `Memory.patchCode`)
4. Hook `__android_log_print` bắt tag `MixuDiag66`, xem gate nào báo fail

---

## 8. 🗺️ Nếu phải làm lại từ đầu — bản đồ nhanh

```bash
# 0. Môi trường sandbox
export PATH="/root/tools:/root/tools/jadx/bin:$PATH"
pip install keystone-engine capstone unicorn pyelftools
pip install --force-reinstall "setuptools<81"     # cho unicorn

# 1. Giải nén + audit
unzip -o Micu_Module_adr.zip -d work/micu

# 2. Trích DEX nhúng trong bridge
#    embedded_dex @ vaddr 0x790, size đọc từ header DEX (offset 32)
#    → baksmali bằng: đóng gói thành apk nháp → apktool d

# 3. Vá DEX + native bridge → xem mục 4
#    Script tái lập đầy đủ: work/patch_micu.py

# 4. Vá engine → xem mục 5
#    Script: work/patch_engine.py

# 5. Kiểm chứng trước khi deploy
#    - disasm lại file đã vá (capstone)
#    - Unicorn emulate panel_gate() / state()
#    - DEX → jar → dalvikvm64 trên máy thật
```

### Công cụ có sẵn
| Tool | Đường dẫn |
|---|---|
| apktool 3.0.3 | `/root/tools/apktool` |
| jadx | `/root/tools/jadx/bin/jadx` |
| dex2jar 2.4 | `/root/tools/dex2jar/dex-tools-v2.4/d2j-dex2jar.sh` |
| radare2 6.2.5 | `r2` (không có r2ghidra plugin — `pdg` fail) |
| REA/Ghidra headless | `source ~/tools/rea/env.sh; rea decompile ...` |
| tesseract OCR | cài bằng `apt-get install -y tesseract-ocr` |
| keystone/capstone/unicorn/pyelftools | pip |

---

## 9. 📁 File trong workspace

| File | Trạng thái | Ghi chú |
|---|---|---|
| `Micu_Module_adr.zip` | gốc | không sửa |
| `work/build/stage/zygisk/libMixuPanelBridge.so` | ✅ **ĐÚNG** `6e420186` | bản bridge chuẩn |
| `work/micu/patched/libMixuPanelBridge.so` | ❌ SAI `f5554b33` | thiếu fix `csel` — **đừng dùng** |
| `work/micu/patched3/arm64-v8a.so` | ✅ `4449a0a8` | engine đã vá 15 điểm |
| `Micu_Module_adr_cracked.zip` | ✅ 11,901,683 B | chỉ tầng 1, bridge đúng |
| `Micu_Module_adr_cracked_v2.zip` | ⚠️ 11,901,662 B | **bridge SAI** (script `pack_v2.py` copy nhầm path) — phải build lại |
| `micu_patch_only.zip` | ✅ 26,264 B | chỉ .so + module.prop |
| `work/patch_micu.py` | ✅ | tái lập vá tầng 1 (có `csel`) |
| `work/patch_engine.py` | ✅ | tái lập vá engine |
| `work/patch_on_device.py` | ✅ | vá tại chỗ trên máy (60 byte) |
| `work/pack_v2.py` | ⚠️ | có bug path bridge — sửa dòng copy |
| `work/xref_accessbit.py`, `work/find_magic.py` | ✅ | script tìm xref/magic |
| `frida/hook1..13.js` | ✅ | 13 script hook đã phát triển |
| `BAOCAO_CRACK_MICU.md` | ✅ | báo cáo tầng 1 |
| `BAOCAO_FRIDA_MICU.md` | ✅ | báo cáo phiên frida |

### GitHub trung gian
`Kiritoprolow/micu-art-test` (public) chứa: `part_00..03`, `libMixuPanelBridge.so` (bản đúng), `module.prop`, `xtest.dex/jar`, `hook1..13.js`, `patch_on_device.py`, `NeoZygisk-v2.4-289-release.zip`

---

## 10. 🔑 Bài học quan trọng nhất

1. **Không có "key đúng" để đoán.** Server ký RSA. Phải patch logic verify, không phải brute-force.
2. **Bridge và engine nối nhau bằng MỘT WORD magic `0xa17c3e5d`.** Vá bridge mà không vá engine = vô ích. Đây là lý do bản tầng 1 không mở được panel.
3. **`csel` sau `add` là cái bẫy chết người.** Luôn emulate để kiểm chứng, đừng tin disasm suông.
4. **Engine load ẩn danh.** Không bao giờ tìm bằng tên file. Phải scan `r-x` anonymous + check ELF magic.
5. **Segment `0x1ae8000` là mỏ vàng.** Toàn bộ gate logic nằm ở đó, code thật không obfuscate. Vào thẳng đây thay vì mò trong 8MB rác.
6. **Luôn có bản gốc backup** trước khi vá file trên máy.
7. **Kiểm chứng từng lớp trước khi lên máy:** disasm → Unicorn → ART thật → deploy.
