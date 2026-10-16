# AVB（Android Verified Boot）重签要点

装 Magisk 的前提是：**你能自己给改过的 boot 生成一个合法的 vbmeta**。
如果厂商用的是 **AOSP 公开测试密钥**，这件事就成立。

## 1. 先判断厂商用的是不是 AOSP testkey

```bash
# 从原厂 vbmeta 里取公钥，和 AOSP 的 testkey 公钥比对
python3 ../tools/parse_vbmeta.py vbmeta.img | grep -i algorithm
# 期望: SHA256_RSA4096

# 公钥比对：AOSP 的公开公钥在
#   platform/external/avb/test/data/testkey_rsa4096_pub.pem
# 自己从 vbmeta 里解出公钥做 DER 比对即可
```

**命中就继续；不命中说明厂商用了自己的密钥，本方案不适用。**

## 2. vbmeta header 结构（关键偏移）

```
offset  size  field
0       4     magic "AVB0"
4       4     required_libavb_version_major
8       4     required_libavb_version_minor
12      8     authentication_data_block_size   ← auth 块大小
20      8     auxiliary_data_block_size        ← aux 块大小
28      4     algorithm_type
32      4     hash_offset        ★ 相对【认证块】起点（= 文件偏移 256 + 该值）
36      4     hash_size
40      4     signature_offset   ★ 相对【认证块】起点
44      4     signature_size
48      4     public_key_offset  ★ 相对【辅助块】起点（= 文件偏移 256 + auth_size + 该值）
52      4     public_key_size
56      4     public_key_metadata_offset
60      4     public_key_metadata_size
64      4     descriptors_offset ★ 相对【辅助块】起点
68      4     descriptors_size
72      8     rollback_index
80      4     flags
84      4     rollback_index_location
88      4     release_string[47]
135     1     reserved[80]
```

### ⚠️ 踩过的两个坑（都曾导致「看起来对、其实全错」）

1. **偏移基准不同** —— `hash_offset` / `signature_offset` 相对**认证块**，
   而 `public_key_offset` / `descriptors_offset` 相对**辅助块**。
   基准搞错时，读出来的签名会是全 0，很容易误判成「厂商没签名」。
2. **`AvbHashDescriptor` 里有一个 60 字节的 `reserved`** ——
   ```
   image_size(0, u64) | hash_algorithm[32](8) | partition_name_len(40, u32) |
   salt_len(44) | digest_len(48) | flags(52) | reserved[60](56) |
   partition_name(116) | salt | digest
   ```
   `partition_name` 在偏移 **116**，不是 56。漏掉 `reserved` 会读到乱码。

## 3. 签名怎么算

```
hash = SHA256( header[0:256]（其中 hash 字段置零） ‖ aux_block )
signature = RSA_PKCS1v15_SHA256_sign(hash, testkey_rsa4096)
```

写回时注意：`image_size` 填**真实镜像大小**（页对齐的各段之和），
**不是分区大小**；分区尾部是补零填充。

```bash
python3 resign_vbmeta.py <原厂 vbmeta> <改过的 boot> <输出的 vbmeta>
```

脚本会做三重自检：
1. 用原厂 boot 复算 digest，确认能匹配原厂 vbmeta 里的值（证明偏移理解正确）
2. 用公开私钥重签后，确认能**逐字节复现原厂的原始签名**（证明算法/填充完全一致）
3. 对自己的输出再验一遍签名与哈希字段

**没有这三步自检就别刷** —— 刷错 vbmeta 会导致设备不进系统。

## 4. 刷入前的检查清单

- [ ] 备份原厂 `boot_a` / `vbmeta_a`（`dd` 到 /sdcard 再拉回电脑）
- [ ] **确认 B 槽是可启动的完整系统**（兜底用；本项目 B 槽保留了上一版固件）
- [ ] `verifiedbootstate` 刷后应为 `green`
- [ ] 绝不碰 `xbl` / `xbl_config` / `abl`（PBL 校验，写坏 = 永久砖）

## 5. 需要的依赖

```bash
pip install cryptography
```

官方 `avbtool.py` 来自 AOSP `external/avb/`，可用于第三方复核
（脚本里 `AVBTOOL` 环境变量指定路径即可）。
