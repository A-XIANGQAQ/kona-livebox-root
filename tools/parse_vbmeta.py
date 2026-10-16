#!/usr/bin/env python3
"""解析 Android vbmeta 镜像，列出所有 descriptor —— 判定 boot 是否被 hash 钉死。"""
import struct
import sys

TAGS = {0: "PROPERTY", 1: "HASHTREE", 2: "HASH", 3: "KERNEL_CMDLINE", 4: "CHAIN_PARTITION"}
ALGOS = {0: "NONE", 1: "SHA256_RSA2048", 2: "SHA256_RSA4096", 3: "SHA256_RSA8192",
         4: "SHA512_RSA2048", 5: "SHA512_RSA4096", 6: "SHA512_RSA8192"}


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def u64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def parse(path):
    data = open(path, "rb").read()
    print(f"=== {path}  ({len(data)} 字节) ===")
    if data[:4] != b"AVB0":
        print("  不是 vbmeta（magic 不是 AVB0）")
        return

    o = 4
    major, minor = u32(data, o), u32(data, o + 4); o += 8
    auth_sz, aux_sz = u64(data, o), u64(data, o + 8); o += 16
    algo = u32(data, o); o += 4
    fields = {}
    for name in ("hash", "signature", "public_key", "public_key_metadata", "descriptors"):
        fields[name + "_off"] = u64(data, o)
        fields[name + "_size"] = u64(data, o + 8)
        o += 16
    rollback_index = u64(data, o); o += 8
    flags = u32(data, o); o += 4
    rollback_loc = u32(data, o); o += 4
    release = data[o:o + 48].split(b"\x00")[0].decode("ascii", "replace")

    print(f"  avb 版本        : {major}.{minor}")
    print(f"  认证块大小      : {auth_sz}")
    print(f"  辅助块大小      : {aux_sz}")
    print(f"  签名算法        : {ALGOS.get(algo, algo)}")
    print(f"  公钥大小        : {fields['public_key_size']}  (0 = 未签名)")
    print(f"  签名大小        : {fields['signature_size']}")
    print(f"  rollback_index  : {rollback_index}   (flags=0x{flags:x})")
    print(f"  release_string  : {release}")

    desc_start = 256 + auth_sz + fields["descriptors_off"]
    desc_end = desc_start + fields["descriptors_size"]
    print(f"  descriptors     : {fields['descriptors_size']} 字节 @ {desc_start}")

    print("\n  ---- descriptor 列表 ----")
    p = desc_start
    n = 0
    while p + 16 <= desc_end:
        tag = u64(data, p)
        ln = u64(data, p + 8)
        body = p + 16
        end = body + ln
        if end > len(data) or ln == 0:
            break
        name = TAGS.get(tag, f"UNKNOWN({tag})")

        if tag == 2:  # hash descriptor
            img_size = u64(data, body)
            algo_s = data[body + 8:body + 40]
            pn_len = u32(data, body + 40)
            salt_len = u32(data, body + 44)
            dig_len = u32(data, body + 48)
            dflags = u32(data, body + 52)
            q = body + 56
            pname = data[q:q + pn_len].decode("ascii", "replace"); q += pn_len
            salt = data[q:q + salt_len]; q += salt_len
            digest = data[q:q + dig_len]
            print(f"   [{n}] HASH         分区={pname:<16} 镜像大小={img_size:>12,} "
                  f"digest={digest.hex()[:32]}... flags=0x{dflags:x}")
            if pname in ("boot", "boot_a", "boot_b"):
                print("        ^^^^^^^^ >>> boot 被 vbmeta 用 hash 钉死了！")

        elif tag == 1:  # hashtree (dm-verity)
            ver = u32(data, body)
            img_size = u64(data, body + 4)
            tree_off = u64(data, body + 12)
            tree_size = u64(data, body + 20)
            dbs = u32(data, body + 28)
            hbs = u32(data, body + 32)
            q = body + 36 + 4 + 8 + 8
            pn_len = u32(data, body + 88)
            salt_len = u32(data, body + 92)
            rd_len = u32(data, body + 96)
            q = body + 100
            pname = data[q:q + pn_len].decode("ascii", "replace")
            print(f"   [{n}] HASHTREE     分区={pname:<16} 镜像大小={img_size:>12,} "
                  f"block={dbs}/{hbs} tree={tree_size:,}")

        elif tag == 0:
            kn = u64(data, body)
            vn = u64(data, body + 8)
            k = data[body + 16:body + 16 + kn].decode("ascii", "replace")
            v = data[body + 16 + kn:body + 16 + kn + vn].decode("ascii", "replace")
            print(f"   [{n}] PROPERTY     {k} = {v!r}")

        elif tag == 3:
            cl = u32(data, body + 4)
            cmd = data[body + 8:body + 8 + cl].decode("ascii", "replace")
            print(f"   [{n}] CMDLINE      {cmd!r}")

        elif tag == 4:
            rl = u32(data, body)
            pn_len = u32(data, body + 4)
            pk_len = u32(data, body + 8)
            pname = data[body + 12:body + 12 + pn_len].decode("ascii", "replace")
            print(f"   [{n}] CHAIN        分区={pname:<16} rollback_loc={rl} pubkey={pk_len}")

        else:
            print(f"   [{n}] {name} 长度={ln}")

        p = end
        n += 1

    print(f"\n  共 {n} 个 descriptor")


if __name__ == "__main__":
    for a in sys.argv[1:]:
        parse(a)
        print()
