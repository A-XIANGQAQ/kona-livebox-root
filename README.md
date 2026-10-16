# 高通 kona 直播机 · Android 10 Root 方案（不解锁 BL、不刷第三方固件）

> **适用对象**：厂商固件里留了「写属性 → init 以 root 执行厂商脚本」后门的机型。
> **最终结果**：拿到稳定 root → 开机自启持久化 → 装上 Magisk + LSPosed（全程不碰引导链、不需解锁 BL、不需 fastboot/EDL）。
> **前提**：SELinux 为 permissive，且 bootloader 已锁（既成事实）。

本文只给**能直接照做的步骤和关键文件**，不写探索过程。

---

## 0. 先判断你的机器适不适用（30 秒自检）

```bash
adb shell getenforce                                  # 期望: Permissive
adb shell ls -l /dev/socket/property_service           # 期望: 世界可写 (srwxrwxrwx)
adb shell "ls -Z /vendor/bin/init.*.sh"                # 找厂商自己的启动钩子
adb shell "grep -rn 'rats\|on property:' /vendor/etc/init/*.rc /system/etc/init/*.rc | head"
```

三条都命中，就可以按本文做。命不中说明后门形态不同，但**第 3 节的 AVB 重签思路照样通用**。

---

## 1. 第一步：拿到第一个 root

### 1.1 后门长什么样

典型形态（本方案针对的就是这类）：

```
/dev/socket/property_service 世界可写 + SELinux permissive
   → 任意进程能写任意系统属性（含 ctl.* 和厂商自定义属性）
   ↓
厂商 rc 里有：on property:sys.xxx.mode=<值> → exec - root root -- /system/bin/厂商脚本.sh
   → 我们写这个属性，就等于让 init 以 root 跑厂商脚本
```

### 1.2 从「root 执行脚本」到「root 代码执行」

厂商脚本里通常有这类**未加引号的变量拼接**：

```sh
cp $prop /mnt/vendor/persist/build.prop      # $prop 未加引号，可词分割
```

两个经典利用点：

| 技巧 | 说明 |
|---|---|
| **`cp -s` 符号链接穿透** | 先让目标成为指向任意文件的符号链接，`cp` 会**跟随链接写入真实文件** |
| **`/proc/sys/kernel/core_pattern`** | 写成 `\|/path/payload` 后，任何进程崩溃时内核会**以 root 执行 payload** |

组合起来就是：

```bash
# 1) 用厂商脚本的 cp 把 core_pattern 打开（或用任意可写路径）
# 2) 投放 payload 并设可执行
# 3) 触发一次崩溃 → 内核以 root 执行 payload → 得到 root
```

> 编译 `probe/rootpay.c` 得到 payload，`probe/sysctlwrite.c` 用来写 core_pattern。

### 1.3 投放一个自己的 root shell（推荐，后续全靠它）

第一个 root 是**易失的**（重启就没了），所以立刻投放常驻服务：

```bash
# 编译（用设备自带的 clang，或 PC 上的 NDK aarch64 工具链）
clang -O2 -o rootsvc probe/rootsvc.c

# 推到设备并起服务（监听 9999，仅接受外部来源连接）
```

`probe/rootsvc.c` 的两个设计要点：

- **拒绝来源为本机自身 IP / 127.0.0.1 的连接** —— 否则设备上任何 App 连 `127.0.0.1:9999` 就能直接拿 root
- 可选令牌文件，连入时校验

> **为什么必须有独立于 Android 框架的 root 通道**：调试阶段框架（system_server）崩过两次，
> 那时 adb/图形界面全废，只有这条原生 TCP 通道还能用，才救得回来。

---

## 2. 持久化（不碰 boot 分区）

厂商固件通常自带一个开机执行的钩子，**利用它比自己写 service 更稳**：

```bash
# 找厂商的启动钩子
grep -rn "init\..*\.sh\|persist" /vendor/etc/init/*.rc | head
```

典型形态：`/vendor/bin/init.xxx.sh` 会在 `late_start` 阶段执行
`/mnt/vendor/persist/<厂商目录>/init.custom.sh`（以 root 身份）。

于是持久化 = **往那个路径写一个脚本**：

```bash
#!/system/bin/sh
# init.custom.sh —— 每次开机自动恢复一切
umask 022
P=/mnt/vendor/persist/<厂商目录>

# 1) 起 root shell
$P/bin/rootsvc &

# 2) 应用机型伪装（见第 4 节）
[ -x $P/bin/rsprop ] && $P/bin/rsprop -f $P/bin/model-spoof.txt

# 3) 恢复 adb over WiFi
mkdir -p /data/misc/adb && cat $P/bin/adbkey.pub >> /data/misc/adb/adb_keys
setprop persist.adb.tcp.port 5555
setprop service.adb.tcp.port 5555
setprop ctl.restart adbd

# 4) 看门狗：厂商 init 会不定时 stop adbd，要守着
( while true; do
    sleep 60
    [ "$(getprop init.svc.adbd)" = "running" ] || setprop ctl.restart adbd
    pgrep -x rootsvc >/dev/null || $P/bin/rootsvc &
  done ) &
```

> 完整可用版本见 `probe/persist_init.sh`（把里面的 `<厂商目录>`/端口改成你自己的即可）。

**注意**：persist 分区的目录权限要 `755`，否则 uid 2000 的 shell 读不到（踩过一次）。

---

## 3. 装 Magisk（本方案能装上的原因）

### 3.1 为什么通常认为装不了

- boot 分区的哈希被 vbmeta 钉死 → 改了 boot 就过不了验证
- bootloader 已锁 + 无 fastboot/EDL → 刷坏了救不回
- 于是结论往往是「不可能」

### 3.2 突破口：厂商用的是 **AOSP 公开测试密钥**

自检命令：

```bash
# 从 vbmeta 里提取公钥，和 AOSP 的 testkey 对比
python3 avb/extract_pubkey.py vbmeta.img          # 或直接 strings + 解析
# AOSP 公钥来源（公开）：
#   platform/external/avb/test/data/testkey_rsa4096_pub.pem
```

**如果公钥 = AOSP testkey_rsa4096，那私钥是公开的** → 你就能自己签 vbmeta → 合法地把改过的 boot 刷进去。

### 3.3 步骤

```bash
# 0) 备份（务必先做）
dd if=/dev/block/by-name/boot_a   of=/sdcard/boot_a.img
dd if=/dev/block/by-name/vbmeta_a of=/sdcard/vbmeta_a.img

# 1) 用 magiskboot 给 boot 打补丁
magiskboot unpack boot_a.img
#   → kernel / ramdisk.cpio / dtb
magiskboot cpio ramdisk.cpio "add 0750 init magiskinit"
magiskboot cpio ramdisk.cpio "mkdir 0750 overlay.d"
magiskboot cpio ramdisk.cpio "mkdir 0750 overlay.d/sbin"
magiskboot cpio ramdisk.cpio "add 0644 overlay.d/sbin/magisk32.xz magisk32.xz"
magiskboot cpio ramdisk.cpio "add 0644 overlay.d/sbin/magisk64.xz magisk64.xz"
magiskboot cpio ramdisk.cpio "patch"
magiskboot repack boot_a.img new-boot.img

# 2) 重签 vbmeta（关键一步，见 avb/README.md 的偏移陷阱）
python3 avb/resign_vbmeta.py vbmeta_a.img new-boot.img new-vbmeta.img

# 3) 空出 A/B 槽的 B 槽作为兜底，然后刷入
dd if=new-boot.img   of=/dev/block/by-name/boot_a
dd if=new-vbmeta.img of=/dev/block/by-name/vbmeta_a
sync && reboot
```

### 3.4 验证

```bash
adb shell su -c id                     # uid=0(root) context=u:r:magisk:s0
adb shell getprop ro.boot.verifiedbootstate   # green = 引导程序认可你重签的 vbmeta
```

---

## 4. 附：机型伪装（只改需要的那一个字段）

有些 App 会根据机型解锁更高规格（码率/清晰度等）。**不要全局改**，那会让厂商自己的 App
也上报错误的品牌，可能影响厂商服务端下发的配置。

**实测结论：只改 `ro.product.model` 就够了**，品牌/厂商/fingerprint 全部保持原厂。

```bash
# ro.product.model=目标机型
# 其余保持原值
$P/bin/rsprop -f $P/bin/model-spoof.txt
```

`rsprop` 的用途是**在运行时改写只读的 `ro.*` 属性**，原理见第 7 节。

> 部分 App 会直接解析 `/system/build.prop` 文件，可以额外用 bind mount 覆盖那个文件保持一致。

---

## 5. 危险清单（务必不要做）

| 禁止 | 原因 |
|---|---|
| ❌ 写 `xbl` / `xbl_config` / `abl` 等引导链分区 | 这些由 PBL 校验，写坏 = **永久砖**，无 EDL、无 fastboot，救不回 |
| ❌ 在没有 B 槽兜底的情况下刷 boot | 出问题只能拆机 |
| ❌ 手改 vbmeta 里的偏移而不校验 | 本项目的踩坑：`hash/signature` 偏移相对**认证块**，`public_key/descriptors` 相对**辅助块**；`AvbHashDescriptor` 里有 `reserved[60]`，`partition_name` 在 **116** 而非 56 |
| ❌ 把 root shell 暴露在无鉴权的 `0.0.0.0` 上 | 设备上任何 App 连 `127.0.0.1` 即可提权 |

---

## 6. 关键文件

| 文件 | 作用 |
|---|---|
| `files/rsprop.c` | **运行时改写只读 `ro.*` 属性**（O_RDWR 打开 `/dev/__properties__/*` 做 seqlock 原地更新） |
| `files/rootsvc.c` | 独立于 Android 框架的 root shell（拒绝本机来源） |
| `files/rootpay.c` | `core_pattern` payload（获取第一个 root） |
| `files/sysctlwrite.c` | 写 `/proc/sys/kernel/core_pattern` |
| `files/persist_init.sh` | 开机自启钩子（含 adb 恢复 + 看门狗） |
| `avb/resign_vbmeta.py` | **重签 vbmeta**（Magisk 路径的核心，含完整自检） |
| `avb/README.md` | AVB 结构要点与偏移陷阱 |
| `tools/parse_vbmeta.py` | vbmeta 解析/校验 |
| `tools/parse_dtb.py` | 设备树解析（判断某功能是否可改：配置在 DT 里才改得动） |

编译 `rsprop.c` / `rootsvc.c` 直接用设备上的 clang：

```bash
clang -O2 -o rsprop files/rsprop.c
clang -O2 -o rootsvc files/rootsvc.c
```

---

## 7. 原理速查（三个通用技术点）

### A. 运行时改写只读属性

`ro.*` 属性区是 `PROT_READ` 映射的，`__system_property_set` 对 `ro.` 直接拒绝，`mprotect` 也会 EPERM。
可行做法：**用 O_RDWR 打开 `/dev/__properties__/<context>_prop`，mmap 成可写，按 seqlock 协议原地更新**：

```c
// 简化示意
int fd = open("/dev/__properties__/u:object_r:build_prop:s0", O_RDWR);
void *area = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
// 定位 prop_info：atomic 递增 serial（奇数=写入中）→ memcpy 值 → serial 设为偶数
__sync_synchronize();
```

完整实现见 `files/rsprop.c`。

> 注意：zygote 在开机时已把 `android.os.Build` 预加载进内存，**Java 层读到的仍是开机时的值**；
> 只有 native（`__system_property_get`）读到的才是新值。要让 Java 层也看到，需 `setprop ctl.restart zygote`。

### B. AVB hash 描述符的偏移陷阱

- header 里的 `hash_offset` / `signature_offset` 是**相对认证块（base + 256）**
- `public_key_offset` / `descriptors_offset` 是**相对辅助块（base + 256 + auth_size）**
- `AvbHashDescriptor` 布局：`image_size(0) | hash_algorithm[32](8) | partition_name_len(40) | salt_len(44) | digest_len(48) | flags(52) | reserved[60](56) | partition_name(116) | salt | digest`
- `image_size` 填的是**真实镜像大小**（页对齐的各段之和），**不是分区大小**

重签后务必**自检**：用重算出的 digest 再验证一遍，并确认能逐字节复现原厂签名。

### C. `cp -s` 的符号链接穿透

`cp -s src dst` 创建符号链接；但如果 `dst` **已存在且是符号链接**，后续 `cp file dst`
会**跟随链接写到真实目标**——这就是「任意 root 文件写入」的来源。
配合未加引号的 shell 变量拼接（词分割），可以把任意路径塞进目标位置。

---

## License

仅供**你自己的设备**的兼容性研究/恢复用途。请遵守当地法律与设备厂商条款。
