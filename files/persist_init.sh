#!/system/bin/sh
# 开机自启钩子（放到厂商自己会以 root 执行的那个路径上，见 README 第 2 节）
#
# 放置示例：把本文件放到 /mnt/vendor/persist/<厂商目录>/init.custom.sh
# 触发方：厂商自带的 /vendor/bin/init.<厂商>.sh 每次开机以 root 后台调用
#
# 现在负责：
#   1) root shell（拒绝本机来源，防 App 绕过提权）
#   2) 机型伪装（系统属性）
#   3) 机型伪装（/system/build.prop 的 bind mount）
#   4) adb over WiFi
#   5) 看门狗（厂商 init 会不定时 stop adbd）
#
# 只改运行时（内存 + 挂载层），不写任何分区、不动启动链、不破坏 dm-verity。

umask 022

# ======== 按你自己的机器改这两处 ========
P=/mnt/vendor/persist/ubiot     # 厂商在 persist 分区里的目录（自启钩子所在目录）
RS_PORT=9999                    # root shell 监听端口
# =======================================

LOG=$P/boot.log
PATH=/sbin:/system/bin:/system/xbin:/vendor/bin
export PATH

exec >> $LOG 2>&1
echo "=== boot $(date) uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null) ==="

# ---------- 0) 清理历史遗留：卸掉自研 su 的挂载 ----------
if mount | grep -q ' /system/xbin '; then
    umount /system/xbin 2>/dev/null && echo "已卸掉 /system/xbin 挂载（还原原厂 xbin）"
fi
for pid in $(ps -A -o PID,NAME 2>/dev/null | grep -E '^sudaemon$' | awk '{print $1}'); do
    kill -9 "$pid" 2>/dev/null && echo "已停自研 sudaemon PID=$pid"
done

# ---------- 1) root shell @9999 ----------
if netstat -tln 2>/dev/null | grep -q ':9999 '; then
    echo "rootsvc already listening"
elif [ -x $P/bin/rootsvc ]; then
    $P/bin/rootsvc &
    echo "rootsvc started pid=$!"
else
    echo "ERROR: $P/bin/rootsvc 不存在或不可执行"
fi

# ---------- 2) 机型伪装：系统属性 ----------
if [ -x $P/bin/rsprop ] && [ -f $P/bin/model-spoof.txt ]; then
    echo "--- 应用机型伪装（属性）---"
    $P/bin/rsprop -f $P/bin/model-spoof.txt 2>&1 | tail -20
    echo "属性 model=$($P/bin/rsprop ro.product.model 2>/dev/null | sed 's/.*= //')"
else
    echo "WARN: rsprop 或 model-spoof.txt 缺失"
fi

# ---------- 3) 机型伪装：/system/build.prop 的 bind mount ----------
if [ -f $P/bin/build.prop ]; then
    if mount | grep -q ' /system/build.prop '; then
        echo "build.prop 已挂载"
    else
        mount --bind $P/bin/build.prop /system/build.prop
        echo "build.prop bind mount rc=$?"
    fi
    echo "文件 model=$(grep -m1 '^ro.product.model=' /system/build.prop 2>/dev/null)"
else
    echo "WARN: $P/bin/build.prop 缺失，跳过挂载"
fi

# ---------- 4) 等系统起来（最多 180 秒）----------
i=0
while [ $i -lt 180 ]; do
    [ "$(getprop sys.boot_completed)" = "1" ] && break
    sleep 1
    i=$((i + 1))
done
echo "boot_completed=$(getprop sys.boot_completed) (等了 ${i}s)"

# ---------- 5) adb 授权公钥 ----------
mkdir -p /data/misc/adb
if cat $P/bin/adbkey.pub > /data/misc/adb/adb_keys 2>/dev/null; then
    chown system:shell /data/misc/adb/adb_keys
    chmod 640 /data/misc/adb/adb_keys
    echo "adb_keys written ($(wc -c < /data/misc/adb/adb_keys) bytes)"
else
    echo "WARN: adb_keys 写入失败"
fi

# ---------- 6) adb over WiFi ----------
setprop persist.sys.usb.config mtp,adb
setprop sys.usb.config mtp,adb
setprop service.adb.root 1
setprop service.adb.tcp.port 5555
setprop persist.adb.tcp.port 5555
setprop sys.adb.enable 1

n=0
while [ $n -lt 6 ]; do
    setprop ctl.start adbd
    sleep 4
    if netstat -tln 2>/dev/null | grep -q ':5555 '; then
        echo "adbd 监听 5555 成功（第 $((n + 1)) 次尝试）"
        break
    fi
    echo "adbd 未监听，重试 $((n + 1))（state=$(getprop init.svc.adbd)）"
    n=$((n + 1))
done

echo "final: adbd=$(getprop init.svc.adbd) 9999=$(netstat -tln 2>/dev/null | grep -c ':9999 ') 5555=$(netstat -tln 2>/dev/null | grep -c ':5555 ') prop=$($P/bin/rsprop ro.product.model 2>/dev/null | sed 's/.*= //') file=$(grep -m1 '^ro.product.model=' /system/build.prop 2>/dev/null | cut -d= -f2)"

# ---------- 7) 看门狗 ----------
echo "看门狗启动 $(date)"
WATCH=0
while true; do
    sleep 60
    WATCH=$((WATCH + 1))

    # adb：厂商 init 触发器会不定时 stop adbd
    if ! netstat -tln 2>/dev/null | grep -q ':5555 '; then
        echo "[看门狗 $WATCH] 5555 掉了，重新拉起 $(date)"
        setprop persist.sys.usb.config mtp,adb
        setprop sys.usb.config mtp,adb
        setprop service.adb.tcp.port 5555
        setprop sys.adb.enable 1
        setprop ctl.start adbd
    fi

    # root shell
    if ! netstat -tln 2>/dev/null | grep -q ':9999 '; then
        echo "[看门狗 $WATCH] 9999 掉了，重新拉起 $(date)"
        [ -x $P/bin/rootsvc ] && $P/bin/rootsvc &
    fi

    # 两个挂载点（注意：不再补挂 /system/xbin）
    mount | grep -q ' /system/build.prop ' || { echo "[看门狗 $WATCH] 补挂 build.prop $(date)"; mount --bind $P/bin/build.prop /system/build.prop; }
    mount | grep -q ' /system/xbin ' && { echo "[看门狗 $WATCH] 发现 xbin 挂载，卸掉 $(date)"; umount /system/xbin 2>/dev/null; }

    # 日志裁剪
    if [ $((WATCH % 60)) -eq 0 ]; then
        sz=$(wc -c < $LOG 2>/dev/null)
        [ -n "$sz" ] && [ "$sz" -gt 1048576 ] && tail -c 200000 $LOG > $LOG.tmp && mv $LOG.tmp $LOG
    fi
done
