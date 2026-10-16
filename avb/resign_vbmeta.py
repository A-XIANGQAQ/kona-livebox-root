#!/usr/bin/env python3
"""验证并重签 vbmeta。

Android boot image v2 头布局（关键偏移）：
   0   magic[8] "ANDROID!"
   8   kernel_size      (u32)
  12   kernel_addr
  16   ramdisk_size     (u32)   ← 注意是 16，不是 12
  20   ramdisk_addr
  24   second_size      (u32)
  28   second_addr
  32   tags_addr
  36   page_size        (u32)
  40   header_version   (u32)
1648  dtb_size         (u32)   （header_version >= 2）

镜像真实大小 = page + pad(kernel) + pad(ramdisk) + pad(second) + pad(dtb)   （各自按 page 对齐）
AVB 只校验这前 image_size 个字节，分区尾部是填充。
"""
import struct
import sys
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

BACKUP = os.environ.get("AVB_BACKUP", "backup")
KEYS = os.environ.get("AVB_KEYS", "keys")          # 放 AOSP testkey_rsa4096.pem 的目录
ORIG_BOOT = os.environ.get("AVB_ORIG_BOOT", "boot.img")
NEW_BOOT = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("AVB_NEW_BOOT", "new-boot.img")


def boot_image_size(path):
    with open(path, "rb") as f:
        hdr = f.read(4096)
    assert hdr[:8] == b"ANDROID!", "不是 Android boot 镜像"
    kernel_sz, ramdisk_sz, second_sz = struct.unpack_from("<III", hdr, 8)[0], \
                                       struct.unpack_from("<I", hdr, 16)[0], \
                                       struct.unpack_from("<I", hdr, 24)[0]
    page = struct.unpack_from("<I", hdr, 36)[0]
    ver = struct.unpack_from("<I", hdr, 40)[0]
    dtb = struct.unpack_from("<I", hdr, 1648)[0] if ver >= 2 else 0

    def pad(x):
        return (x + page - 1) // page * page

    return page + pad(kernel_sz) + pad(ramdisk_sz) + pad(second_sz) + pad(dtb), \
           dict(page=page, ver=ver, kernel=kernel_sz, ramdisk=ramdisk_sz, second=second_sz, dtb=dtb)


def avb_digest(path, size, salt):
    h = hashlib.sha256()
    h.update(salt)
    with open(path, "rb") as f:
        left = size
        while left > 0:
            chunk = f.read(min(8 * 1024 * 1024, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    return h.digest()


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def u64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def find_boot_desc(aux, desc_off, desc_size):
    """在辅助块里定位 HASH 描述符。

    AvbHashDescriptor 布局（有 reserved[60] 填充，这点极易踩坑）：
      0   image_size            (u64)
      8   hash_algorithm[32]
      40  partition_name_len    (u32)
      44  salt_len              (u32)
      48  digest_len            (u32)
      52  flags                 (u32)
      56  reserved[60]          ← 填充到 116
      116 partition_name[] / salt[] / digest[]   （都是精确长度，不带 NUL）
    """
    p = desc_off
    while p + 16 <= desc_off + desc_size:
        tag, ln = u64(aux, p), u64(aux, p + 8)
        body = p + 16
        if ln == 0 or body + ln > len(aux):
            break
        if tag == 2:                                   # HASH
            pn = u32(aux, body + 40)
            sl = u32(aux, body + 44)
            dl = u32(aux, body + 48)
            name_off = body + 116
            name = bytes(aux[name_off:name_off + pn]).decode("ascii", "replace")
            yield body, name_off, name_off + pn, name_off + pn + sl, name, sl, dl
        p = body + ln


def main():
    print("=== 1) 计算两个 boot 镜像的真实大小 ===")
    for label, p in (("原始 boot.img", ORIG_BOOT), ("Magisk 补丁后", NEW_BOOT)):
        sz, info = boot_image_size(p)
        print(f"  {label}: page={info['page']} ver={info['ver']} kernel={info['kernel']:,} "
              f"ramdisk={info['ramdisk']:,} dtb={info['dtb']:,}")
        print(f"     → image_size = {sz:,}")

    orig_size, _ = boot_image_size(ORIG_BOOT)
    new_size, _ = boot_image_size(NEW_BOOT)

    data = bytearray(open(os.path.join(BACKUP, "vbmeta_a.img"), "rb").read())
    auth, aux_sz = u64(data, 12), u64(data, 20)
    desc_off, desc_sz = u64(data, 96), u64(data, 104)
    base = 256 + auth
    aux = bytearray(data[base:base + aux_sz])
    aux_data_orig = bytes(aux)          # 原始辅助块（用于复现厂商签名）

    print("\n=== 2) ★ 终极致命验证：用我的理解算 vbmeta 里 boot 的摘要 ===")
    ok_any = False
    for body, name_off, salt_off, dig_off, name, sl, dl in find_boot_desc(aux, desc_off, desc_sz):
        img_size = u64(aux, body)
        salt = bytes(aux[salt_off:salt_off + sl])
        stored = bytes(aux[dig_off:dig_off + dl])
        if name != "boot":
            print(f"  （{name}: size={img_size:,}）")
            continue
        print(f"  boot: vbmeta 记录 image_size = {img_size:,}")
        print(f"        salt   = {salt.hex()}")
        print(f"        digest = {stored.hex()}")
        calc = avb_digest(ORIG_BOOT, img_size, salt)
        print(f"  我算出的 digest = {calc.hex()}")
        if calc == stored:
            print("  ★★★ 完全一致！我的模型是对的，可以放心重签 ✅✅✅")
            ok_any = True
        else:
            print("  ✗ 不一致 —— 说明还有理解偏差，绝不能刷！")
    if not ok_any:
        print("\n验证失败，停止。")
        return

    print(f"\n=== 3) 生成补丁后的 vbmeta ===")
    print(f"  boot image_size: {orig_size:,} → {new_size:,}")
    new_dig = avb_digest(NEW_BOOT, new_size, salt)
    print(f"  新 digest = {new_dig.hex()}")

    for body, name_off, salt_off, dig_off, name, sl, dl in find_boot_desc(aux, desc_off, desc_sz):
        if name != "boot":
            continue
        struct.pack_into(">Q", aux, body, new_size)
        aux[dig_off:dig_off + dl] = new_dig
        print("  已写入描述符（image_size + digest）")

    print("\n=== 4) ★ 密钥终极验证：能否复现厂商原始签名 ===")
    # 注意基准不同：
    #   hash_offset / signature_offset   → 相对【认证块】起点 (256)
    #   public_key_offset / descriptors_offset → 相对【辅助块】起点 (256 + auth_size)
    hash_off, hash_sz = u64(data, 32), u64(data, 40)
    sig_off, sig_sz = u64(data, 48), u64(data, 56)
    pk_off, pk_sz = u64(data, 64), u64(data, 72)
    print(f"  hash@auth+{hash_off}/{hash_sz}  sig@auth+{sig_off}/{sig_sz}  pubkey@aux+{pk_off}/{pk_sz}")
    print(f"  绝对位置: hash@{256 + hash_off}  sig@{256 + sig_off}  auth 块 {256}..{base}")

    key = serialization.load_pem_private_key(
        open(os.path.join(KEYS, "avb_testkey_rsa4096.pem"), "rb").read(), None)

    orig_hdr = bytearray(data[:256])
    orig_hdr[32:40] = b"\x00" * 8
    orig_digest = hashlib.sha256(bytes(orig_hdr) + aux_data_orig).digest()
    orig_sig_calc = key.sign(orig_digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    orig_sig_file = bytes(data[256 + sig_off: 256 + sig_off + sig_sz])
    stored_hash = bytes(data[256 + hash_off: 256 + hash_off + hash_sz])

    print(f"\n  头部哈希字段 = {stored_hash.hex()}")
    print(f"  我算的头部哈希 = {orig_digest.hex()}   → {'一致 ✅' if stored_hash == orig_digest else '不一致 ✗'}")
    print(f"  文件里的签名 = {orig_sig_file[:32].hex()}…")
    print(f"  我复现的签名 = {orig_sig_calc[:32].hex()}…")
    if orig_sig_calc == orig_sig_file:
        print("  ★★★★ 签名逐字节一致！密钥 100% 正确 —— 就是 AOSP testkey_rsa4096 ✅✅✅")
    else:
        print("  ✗ 签名不一致！绝对不能刷 ✗✗✗")
        return

    print("\n=== 5) 用该私钥签新的 vbmeta ===")
    out = bytearray(data[:256]) + bytearray(auth) + bytes(aux)
    out[base:base + aux_sz] = aux
    out[32:40] = b"\x00" * 8
    digest = hashlib.sha256(bytes(out[:256]) + bytes(aux)).digest()
    print(f"  新头部哈希 = {digest.hex()}")

    sig = key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    print(f"  签名长度 = {len(sig)}（认证块偏移 {sig_off}，块共 {auth} 字节）")
    assert len(sig) == sig_sz, f"签名长度 {len(sig)} != 头部声明的 {sig_sz}"

    out[256 + hash_off: 256 + hash_off + hash_sz] = digest
    out[256 + sig_off: 256 + sig_off + sig_sz] = sig

    # 补齐到分区大小（尾部补零，与原厂一致）
    if len(out) < 65536:
        out += bytes(65536 - len(out))

    dest = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("AVB_OUT", "new-vbmeta.img")
    open(dest, "wb").write(out)
    print(f"\n✅ 已写出 {dest}  ({len(out):,} 字节)")

    print("\n=== 6) 自校验（用修正后的绝对偏移）===")
    chk = bytearray(out)
    chk[32:40] = b"\x00" * 8
    d2 = hashlib.sha256(bytes(chk[:256]) + bytes(aux)).digest()
    pub = key.public_key()
    filed_sig = bytes(out[256 + sig_off: 256 + sig_off + sig_sz])
    try:
        pub.verify(filed_sig, d2, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        print("  ✅ 签名用 testkey 公钥验证通过")
    except Exception as e:
        print(f"  ✗ 签名验证失败: {e}")
    print(f"  {'✅' if bytes(out[256 + hash_off:256 + hash_off + hash_sz]) == d2 else '✗'} 头部哈希字段匹配")

    # 用 avbtool 做第三方复核
    print("\n=== 7) 用官方 avbtool 复核新 vbmeta ===")
    import subprocess
    avb = os.environ.get("AVBTOOL", "avbtool.py")   # 官方 avbtool（AOSP external/avb 里取）
    env = dict(os.environ)
    env["TEMP"] = env["TMP"] = os.path.dirname(dest)
    r = subprocess.run([sys.executable, avb, "info_image", "--image", dest],
                       capture_output=True, text=True, env=env)
    out_txt = (r.stdout or "") + (r.stderr or "")
    for line in out_txt.splitlines():
        if any(k in line for k in ("Algorithm", "Rollback", "Partition Name", "Image Size",
                                   "Digest", "Salt", "Public key", "Flags", "Chain")):
            print("   " + line.strip())

    # 复核新描述符
    aux2 = bytearray(out[base:base + aux_sz])
    for body, name_off, salt_off, dig_off, name, sl, dl in find_boot_desc(aux2, desc_off, desc_sz):
        if name == "boot":
            s2 = bytes(aux2[salt_off:salt_off + sl])
            print(f"  ✅ 新描述符: image_size={u64(aux2, body):,} digest={bytes(aux2[dig_off:dig_off+dl]).hex()[:32]}…")
            chk2 = avb_digest(NEW_BOOT, u64(aux2, body), s2)
            print(f"  ✅ 用补丁镜像重算摘要一致: {chk2 == bytes(aux2[dig_off:dig_off+dl])}")


if __name__ == "__main__":
    main()



