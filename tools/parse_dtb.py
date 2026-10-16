#!/usr/bin/env python3
"""解析 Qualcomm boot 镜像里的 DTB（可能是多个 DTB 拼接），找出 USB/Type-C 相关节点与属性。

FDT 结构：
  header: magic(0xd00dfeed) totalsize off_dt_struct off_dt_strings off_mem_rsvmap ...
  structure block: FDT_BEGIN_NODE(1)+name | FDT_PROP(3)+len+nameoff+value | FDT_END_NODE(2) | FDT_NOP(4) | FDT_END(9)
  strings block: 属性名字符串表
"""
import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "dtb.img"
FDT_MAGIC = 0xD00DFEED
BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9

INTEREST = ("usb", "typec", "type-c", "extcon", "dwc3", "usbpd", "pd", "role",
            "bq2589", "charger", "pm8150", "pm8998", "redriver", "mux", "switch", "phy")
KEY_PROPS = ("dr_mode", "extcon", "usb-role-switch", "role-switch-default-mode",
             "qcom,usb-role-switch", "qcom,default-mode", "maximum-speed",
             "qcom,initial-pr", "qcom,initial-dr", "initial_pr", "initial_dr",
             "qcom,usbpd-phandle", "usb-phy", "phys", "phy-names", "status")


def cstr(buf, off):
    e = buf.find(b"\x00", off)
    return buf[off:e].decode("utf-8", "replace")


def parse_fdt(data, base):
    magic, totalsize, off_struct, off_strings = struct.unpack_from(">IIII", data, base)
    if magic != FDT_MAGIC:
        return None
    ver, last_ver, boot_cpu, size_strings, size_struct = struct.unpack_from(">IIIII", data, base + 16)
    return dict(total=totalsize, off_struct=base + off_struct,
                off_strings=base + off_strings, ver=ver)


def walk(data, fdt):
    p = fdt["off_struct"]
    strings = fdt["off_strings"]
    path = []
    out = []
    while True:
        tag, = struct.unpack_from(">I", data, p); p += 4
        if tag == BEGIN_NODE:
            name = cstr(data, p)
            p += (len(name.encode()) + 1 + 3) & ~3
            path.append(name)
        elif tag == END_NODE:
            if path:
                path.pop()
        elif tag == PROP:
            ln, nameoff = struct.unpack_from(">II", data, p); p += 8
            val = data[p:p + ln]
            p += (ln + 3) & ~3
            pname = cstr(data, strings + nameoff)
            out.append(("/".join(path), pname, val))
        elif tag == NOP:
            continue
        elif tag == END:
            break
        else:
            break
    return out


def fmt_val(v):
    if len(v) == 4:
        n, = struct.unpack(">I", v)
        return f"u32={n}"
    if all(32 <= c < 127 or c == 0 for c in v):
        return repr(v.rstrip(b"\x00").decode("utf-8", "replace"))
    return v[:16].hex() + ("…" if len(v) > 16 else "")


def main():
    data = open(PATH, "rb").read()
    print(f"=== 文件 {len(data):,} 字节 ===")

    # 找出所有拼接的 DTB
    bases = []
    i = 0
    while i + 4 <= len(data):
        if data[i:i + 4] == b"\xd0\x0d\xfe\xed":
            bases.append(i)
            total, = struct.unpack_from(">I", data, i + 4)
            i += total if 0 < total <= len(data) - i else 4
        else:
            i += 4
    print(f"=== 发现 {len(bases)} 个 DTB ===")

    total_nodes = 0
    hits = {}
    allprops = set()
    for b in bases:
        fdt = parse_fdt(data, b)
        if not fdt:
            continue
        for node, pname, val in walk(data, fdt):
            total_nodes += 1
            allprops.add(pname)
            low = node.lower()
            if any(k in low for k in INTEREST):
                key = (node, pname)
                if key not in hits:
                    hits[key] = (fmt_val(val), b)
    print(f"=== 共 {total_nodes} 条属性 ===")

    print("\n=== ★ USB/Type-C 相关节点及其属性 ===")
    shown = set()
    for (node, pname), (v, b) in sorted(hits.items()):
        if node not in shown:
            print(f"\n  [节点] {node}   (DTB@{b:#x})")
            shown.add(node)
        print(f"      {pname:<34} = {v}")

    print("\n=== ★ 所有含 role/mode/initial 的属性名（全局）===")
    for p in sorted(allprops):
        if any(k in p.lower() for k in ("role", "initial", "dr_mode", "typec", "usbpd")):
            print("    " + p)


if __name__ == "__main__":
    main()
