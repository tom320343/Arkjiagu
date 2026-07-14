#include "GuardDexLoader.h"

#include <jni.h>
#include <android/log.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include "GuardSelfHash.h"

#define LOG_TAG "GuardVMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ================================================================
 * 防调试检测
 * ================================================================ */
static bool s_anti_debug_enabled = true;

static bool check_tracer_pid() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        return true;
    }

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) {
        return true;
    }

    buf[n] = '\0';

    const char *needle = "TracerPid:";
    char *pos = strstr(buf, needle);
    if (pos == NULL) {
        return true;
    }

    pos += strlen(needle);

    while (*pos == ' ' || *pos == '\t') {
        pos++;
    }

    int tracer_pid = (int)strtol(pos, NULL, 10);

    if (tracer_pid != 0) {
        LOGE("[GuardDexLoader] 检测到调试器, TracerPid=%d", tracer_pid);
        return false;
    }

    return true;
}

/* ================================================================
 * 三层解密函数 — 对应 GuardTool 的三层加密
 *
 * 加密顺序 (GuardTool 端): Layer1(XOR) -> Layer2(分块) -> Layer3(字节混淆)
 * 解密顺序 (这里):         Layer3(逆混淆) -> Layer2(逆分块) -> Layer1(逆XOR)
 * ================================================================ */

/*
 * decryptLayer3: 解除第三层字节混淆
 * 混淆方式: 每个字节进行 NOT + ROL3 + XOR 0xA5 操作
 * 解密: 反向操作 XOR 0xA5 -> ROR3 -> NOT
 */
static void decrypt_layer3(unsigned char *data, size_t len) {
    if (data == NULL || len == 0) return;

    for (size_t i = 0; i < len; i++) {
        unsigned char v = data[i];

        v ^= 0xA5;

        v = (unsigned char)((v >> 3) | (v << 5));

        v = (unsigned char)(~v);

        data[i] = v;
    }
}

/*
 * decryptLayer2: 解除第二层 AES 分块加密
 * 使用 256-bit (32字节) 密钥进行分块解密
 * 每块 16 字节，进行多轮替换/置换/异或操作
 *
 * key: 32 字节 AES-256 密钥（由签名 SHA256 派生）
 */
static void decrypt_layer2(unsigned char *data, size_t len,
                            const unsigned char key[32]) {
    if (data == NULL || len == 0 || key == NULL) return;
    if (len % 16 != 0) return;

    static const unsigned char sbox[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
        0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
        0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
        0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
        0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
        0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
        0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    /* 密钥扩展: 从 32 字节生成 176 字节的轮密钥 (AES-256: 15 轮) */
    unsigned char round_keys[240];
    memset(round_keys, 0, sizeof(round_keys));

    memcpy(round_keys, key, 32);

    for (int i = 8; i < 60; i++) {
        unsigned char temp[4];
        memcpy(temp, round_keys + (i - 1) * 4, 4);

        if (i % 8 == 0) {
            unsigned char t = temp[0];
            temp[0] = sbox[temp[1]] ^ ((i / 8) | 0x00);
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
        }

        for (int j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = (unsigned char)(round_keys[(i - 8) * 4 + j] ^ temp[j]);
        }
    }

    size_t num_blocks = len / 16;
    unsigned char block[16];

    for (size_t blk = 0; blk < num_blocks; blk++) {
        memcpy(block, data + blk * 16, 16);

        /* 初始 AddRoundKey */
        for (int j = 0; j < 16; j++) {
            block[j] ^= round_keys[224 + j];  /* 最后一轮密钥先加 */
        }

        /* 13 轮逆向解密 (AES-256 共 14 轮, 第 0 轮只做 AddRoundKey) */
        for (int round = 13; round >= 1; round--) {
            /* InvShiftRows */
            unsigned char tmp[16];
            tmp[0]  = block[0];
            tmp[1]  = block[13];
            tmp[2]  = block[10];
            tmp[3]  = block[7];
            tmp[4]  = block[4];
            tmp[5]  = block[1];
            tmp[6]  = block[14];
            tmp[7]  = block[11];
            tmp[8]  = block[8];
            tmp[9]  = block[5];
            tmp[10] = block[2];
            tmp[11] = block[15];
            tmp[12] = block[12];
            tmp[13] = block[9];
            tmp[14] = block[6];
            tmp[15] = block[3];

            /* InvSubBytes */
            for (int j = 0; j < 16; j++) {
                block[j] = sbox[tmp[j]];
            }

            /* AddRoundKey */
            for (int j = 0; j < 16; j++) {
                block[j] ^= round_keys[round * 16 + j];
            }

            /* InvMixColumns */
            for (int col = 0; col < 4; col++) {
                int idx = col * 4;
                unsigned char a[4];
                memcpy(a, block + idx, 4);

                block[idx + 0] = (unsigned char)(
                    (unsigned char)(a[0] * 0x0E) ^ (unsigned char)(a[1] * 0x0B)
                  ^ (unsigned char)(a[2] * 0x0D) ^ (unsigned char)(a[3] * 0x09)
                );
                block[idx + 1] = (unsigned char)(
                    (unsigned char)(a[0] * 0x09) ^ (unsigned char)(a[1] * 0x0E)
                  ^ (unsigned char)(a[2] * 0x0B) ^ (unsigned char)(a[3] * 0x0D)
                );
                block[idx + 2] = (unsigned char)(
                    (unsigned char)(a[0] * 0x0D) ^ (unsigned char)(a[1] * 0x09)
                  ^ (unsigned char)(a[2] * 0x0E) ^ (unsigned char)(a[3] * 0x0B)
                );
                block[idx + 3] = (unsigned char)(
                    (unsigned char)(a[0] * 0x0B) ^ (unsigned char)(a[1] * 0x0D)
                  ^ (unsigned char)(a[2] * 0x09) ^ (unsigned char)(a[3] * 0x0E)
                );
            }
        }

        /* 最后一轮 (round 0): InvShiftRows + InvSubBytes + AddRoundKey (无 MixColumns) */
        unsigned char tmp2[16];
        tmp2[0]  = block[0];
        tmp2[1]  = block[13];
        tmp2[2]  = block[10];
        tmp2[3]  = block[7];
        tmp2[4]  = block[4];
        tmp2[5]  = block[1];
        tmp2[6]  = block[14];
        tmp2[7]  = block[11];
        tmp2[8]  = block[8];
        tmp2[9]  = block[5];
        tmp2[10] = block[2];
        tmp2[11] = block[15];
        tmp2[12] = block[12];
        tmp2[13] = block[9];
        tmp2[14] = block[6];
        tmp2[15] = block[3];

        for (int j = 0; j < 16; j++) {
            block[j] = sbox[tmp2[j]];
        }

        for (int j = 0; j < 16; j++) {
            block[j] ^= round_keys[j];
        }

        memcpy(data + blk * 16, block, 16);
    }

    memset(round_keys, 0, sizeof(round_keys));
    memset(block, 0, sizeof(block));
}

/*
 * decryptLayer1: 解除第一层 XOR 加密
 * 使用 64 字节密钥进行逐字节 XOR
 */
static void decrypt_layer1(unsigned char *data, size_t len,
                            const unsigned char key[64],
                            size_t key_len) {
    if (data == NULL || len == 0 || key == NULL || key_len == 0) return;

    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/*
 * 组合三层解密:
 *   1. Layer3 字节逆混淆
 *   2. Layer2 AES-256 逆分块
 *   3. Layer1 XOR 解密
 *
 * 返回解密后的数据 vector，调用者负责释放
 */
static std::vector<unsigned char> decrypt_three_layers(
        const unsigned char *cipher_data,
        size_t cipher_len,
        const unsigned char aes_key[32],
        const unsigned char xor_key[64],
        size_t xor_key_len) {

    std::vector<unsigned char> result;
    if (cipher_data == NULL || cipher_len == 0) return result;

    result.resize(cipher_len);
    memcpy(result.data(), cipher_data, cipher_len);

    LOGI("[GuardDexLoader] 开始三层解密, 数据大小=%zu", cipher_len);

    /* Layer 3: 字节混淆逆操作 */
    decrypt_layer3(result.data(), cipher_len);
    LOGI("[GuardDexLoader] Layer3 字节混淆解除完成");

    /* Layer 2: AES-256 分块逆解密 */
    /* 将数据填充到 16 字节对齐 */
    size_t padded_len = ((cipher_len + 15) / 16) * 16;
    if (padded_len > cipher_len) {
        result.resize(padded_len);
        memset(result.data() + cipher_len, 0, padded_len - cipher_len);
    }

    decrypt_layer2(result.data(), padded_len, aes_key);
    LOGI("[GuardDexLoader] Layer2 AES 分块解密完成");

    /* Layer 1: XOR 解密 */
    decrypt_layer1(result.data(), cipher_len, xor_key, xor_key_len);
    LOGI("[GuardDexLoader] Layer1 XOR 解密完成");

    return result;
}

/* ================================================================
 * 原有代码 — 协议常量、结构体、工具函数
 * ================================================================ */
static const int GUARD_BLOCK_TYPE_DEX = 1;
static const int GUARD_BLOCK_TYPE_APP = 2;
static const int GUARD_BLOCK_TYPE_INDEX = 3;
static const int GUARD_BLOCK_TYPE_FACTORY = 4;

static const int GUARD_BLOCK_FLAG_RANDOM_KEY = 1;
static const int GUARD_BLOCK_FLAG_SIGN_KEY = 2;

struct GuardPayloadFooter {
    size_t payloadOff;
    size_t payloadLen;
    size_t indexOff;
    size_t indexLen;
};

static const unsigned char GUARD_BLOCK_USE_SIGN_KEY_FLAG[4] = {
    0x41, 0x52, 0x4B, 0x53
};

static uint32_t readLe32(const unsigned char *p) {
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

struct GuardDexBlockInfo {
    size_t dataOffset;
    size_t plainLen;
    size_t cipherLen;
    unsigned char key[64];
};

static std::vector<unsigned char> xorData(
        const unsigned char *data,
        size_t len,
        const unsigned char *key,
        size_t keyLen) {
    std::vector<unsigned char> out;
    out.resize(len);
    for (size_t i = 0; i < len; i++) {
        out[i] = data[i] ^ key[i % keyLen];
    }
    return out;
}

struct GuardPayloadIndexEntry {
    int type;
    int index;
    size_t offset;
    size_t size;
    int flags;
};

static bool readLe32FromVector(
        const std::vector<unsigned char> &data,
        size_t &pos,
        uint32_t &out
) {
    if (pos + 4 > data.size()) return false;
    out = readLe32(data.data() + pos);
    pos += 4;
    return true;
}

static void deriveDexKeyFromSignKey64(
        const unsigned char inKey[64],
        unsigned char outKey[64]
) {
    static const unsigned char salt[64] = {
        0x41, 0x72, 0x6B, 0x56, 0x4D, 0x50, 0x23, 0x19,
        0x8A, 0xC3, 0x55, 0x21, 0x7D, 0xE1, 0x39, 0xB6,
        0x10, 0x92, 0xFA, 0x66, 0x2C, 0xD8, 0x73, 0x4F,
        0xA7, 0x05, 0x31, 0xCB, 0x98, 0x44, 0xE9, 0x12,
        0x6D, 0x81, 0x3A, 0xFE, 0x57, 0x20, 0xBC, 0x09,
        0xD1, 0x64, 0x2E, 0xA9, 0x7B, 0xC0, 0x16, 0x5F,
        0xE3, 0x38, 0x91, 0x0C, 0xB2, 0x75, 0x4A, 0xDD,
        0x27, 0xF8, 0x60, 0x9E, 0x13, 0xAC, 0x52, 0x87
    };

    for (int i = 0; i < 64; i++) {
        unsigned char v = inKey[i];
        v ^= salt[i];
        v = static_cast<unsigned char>((v << 3) | (v >> 5));
        v ^= static_cast<unsigned char>(i * 17 + 0x5A);
        v = static_cast<unsigned char>((v >> 2) | (v << 6));
        v ^= salt[(i * 7) & 63];
        outKey[i] = v;
    }

    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < 64; i++) {
            unsigned char a = outKey[i];
            unsigned char b = outKey[(i + 13) & 63];
            unsigned char c = outKey[(i + 37) & 63];
            outKey[i] = static_cast<unsigned char>(
                ((a ^ b) + c + salt[(i + round * 11) & 63]) & 0xff
            );
        }
    }
}

static bool parsePayloadFooterFromTail(
        const std::vector<unsigned char> &allData,
        GuardPayloadFooter &outFooter
) {
    memset(&outFooter, 0, sizeof(outFooter));
    const size_t footerSize = 36;

    if (allData.size() < footerSize) return false;

    size_t pos = allData.size() - footerSize;
    const unsigned char *p = allData.data() + pos;

    if (!(p[0] == 0x5C && p[1] == 0xE1 && p[2] == 0x38 && p[3] == 0x90)) {
        return false;
    }

    pos += 4;
    uint32_t version = readLe32(allData.data() + pos); pos += 4;
    uint32_t flags = readLe32(allData.data() + pos); pos += 4;
    uint32_t payloadOff = readLe32(allData.data() + pos); pos += 4;
    uint32_t payloadLen = readLe32(allData.data() + pos); pos += 4;
    uint32_t indexOff = readLe32(allData.data() + pos); pos += 4;
    uint32_t indexLen = readLe32(allData.data() + pos); pos += 4;

    if (version != 1) return false;
    if (payloadLen == 0 || indexLen == 0) return false;
    if ((size_t)payloadOff + (size_t)payloadLen > allData.size() - footerSize) return false;
    if ((size_t)indexOff + (size_t)indexLen > (size_t)payloadLen) return false;

    outFooter.payloadOff = static_cast<size_t>(payloadOff);
    outFooter.payloadLen = static_cast<size_t>(payloadLen);
    outFooter.indexOff = static_cast<size_t>(indexOff);
    outFooter.indexLen = static_cast<size_t>(indexLen);

    return true;
}

static bool parsePayloadIndexPlainBytes(
        const std::vector<unsigned char> &plain,
        std::vector<GuardPayloadIndexEntry> &outEntries
) {
    outEntries.clear();

    if (plain.size() < 12) return false;

    if (!(plain[0] == 0x71 && plain[1] == 0x32 && plain[2] == 0xA6 && plain[3] == 0x4D)) {
        return false;
    }

    size_t pos = 4;
    uint32_t version = 0;
    uint32_t entryCount = 0;

    if (!readLe32FromVector(plain, pos, version)) return false;
    if (version != 1) return false;
    if (!readLe32FromVector(plain, pos, entryCount)) return false;
    if (entryCount == 0 || entryCount > 256) return false;
    if (pos + entryCount * 20 > plain.size()) return false;

    for (uint32_t i = 0; i < entryCount; i++) {
        uint32_t type = 0, index = 0, offset = 0, size = 0, flags = 0;
        if (!readLe32FromVector(plain, pos, type)) return false;
        if (!readLe32FromVector(plain, pos, index)) return false;
        if (!readLe32FromVector(plain, pos, offset)) return false;
        if (!readLe32FromVector(plain, pos, size)) return false;
        if (!readLe32FromVector(plain, pos, flags)) return false;
        if (size == 0) return false;

        GuardPayloadIndexEntry entry;
        entry.type = static_cast<int>(type);
        entry.index = static_cast<int>(index);
        entry.offset = static_cast<size_t>(offset);
        entry.size = static_cast<size_t>(size);
        entry.flags = static_cast<int>(flags);
        outEntries.push_back(entry);
    }

    return true;
}

static bool parseEncryptedBlockInfoByIndex(
        const std::vector<unsigned char> &allData,
        size_t blockOffset,
        size_t blockSize,
        GuardDexBlockInfo &outInfo,
        const unsigned char *signKey64
) {
    memset(&outInfo, 0, sizeof(outInfo));

    if (blockSize < 28) return false;
    if (blockOffset + blockSize > allData.size()) return false;

    const unsigned char *block = allData.data() + blockOffset;
    if (!(block[0] == 0x63 && block[1] == 0x19 && block[2] == 0xB7 && block[3] == 0x52)) {
        return false;
    }

    size_t pos = blockOffset + 4;
    uint32_t type = readLe32(allData.data() + pos); pos += 4;
    uint32_t index = readLe32(allData.data() + pos); pos += 4;
    uint32_t flags = readLe32(allData.data() + pos); pos += 4;
    uint32_t plainLen = readLe32(allData.data() + pos); pos += 4;
    uint32_t cipherLen = readLe32(allData.data() + pos); pos += 4;
    uint32_t keyLen = readLe32(allData.data() + pos); pos += 4;

    if (plainLen == 0 || cipherLen == 0) return false;
    if (plainLen != cipherLen) return false;

    if (flags == GUARD_BLOCK_FLAG_RANDOM_KEY) {
        if (keyLen != 64) return false;
        if (28 + cipherLen + keyLen != blockSize) return false;

        outInfo.dataOffset = pos;
        outInfo.plainLen = plainLen;
        outInfo.cipherLen = cipherLen;
        memcpy(outInfo.key, allData.data() + pos + cipherLen, 64);
        return true;
    }

    if (flags == GUARD_BLOCK_FLAG_SIGN_KEY) {
        if (keyLen != 0) return false;
        if (signKey64 == NULL) return false;
        if (28 + cipherLen != blockSize) return false;

        outInfo.dataOffset = pos;
        outInfo.plainLen = plainLen;
        outInfo.cipherLen = cipherLen;
        deriveDexKeyFromSignKey64(signKey64, outInfo.key);
        return true;
    }

    return false;
}

static bool decryptStringBlockByEntry(
        const std::vector<unsigned char> &shellDex,
        const GuardPayloadFooter &footer,
        const GuardPayloadIndexEntry &entry,
        std::string &outText
) {
    outText.clear();

    size_t absOffset = footer.payloadOff + entry.offset;
    if (absOffset + entry.size > shellDex.size()) return false;

    GuardDexBlockInfo info;
    memset(&info, 0, sizeof(info));

    if (!parseEncryptedBlockInfoByIndex(shellDex, absOffset, entry.size, info, NULL)) {
        return false;
    }

    std::vector<unsigned char> data = xorData(
        shellDex.data() + info.dataOffset,
        info.plainLen,
        info.key,
        64
    );

    data.push_back('\0');
    outText = reinterpret_cast<const char *>(data.data());
    std::vector<unsigned char>().swap(data);

    return !outText.empty();
}

static std::string gRealApplicationName;
static std::string gRealAppComponentFactoryName;
static std::vector<void *> gDexMemoryList;
static bool gGuardDexLoaded = false;

static bool checkException(JNIEnv *env, const char *msg) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

static int getSdkInt(JNIEnv *env) {
    jclass clsBuildVersion = env->FindClass("android/os/Build$VERSION");
    jfieldID fidSdkInt = env->GetStaticFieldID(clsBuildVersion, "SDK_INT", "I");
    return env->GetStaticIntField(clsBuildVersion, fidSdkInt);
}

static bool getSelfSignKey64(JNIEnv *env, unsigned char outKey[64]) {
    if (env == NULL || outKey == NULL) return false;

    jbyteArray sha32Array = env->NewByteArray(32);
    if (sha32Array == NULL) return false;

    if (!ark_get_self_cert_sha256(env, sha32Array)) {
        env->DeleteLocalRef(sha32Array);
        return false;
    }

    unsigned char sha32[32];
    memset(sha32, 0, sizeof(sha32));
    env->GetByteArrayRegion(sha32Array, 0, 32, reinterpret_cast<jbyte *>(sha32));
    env->DeleteLocalRef(sha32Array);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    static const char hexTable[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        outKey[i * 2] = hexTable[(sha32[i] >> 4) & 0x0F];
        outKey[i * 2 + 1] = hexTable[sha32[i] & 0x0F];
    }

    return true;
}

static bool isValidDexData(const std::vector<unsigned char> &data) {
    return data.size() >= 0x70
        && data[0] == 'd'
        && data[1] == 'e'
        && data[2] == 'x'
        && data[3] == '\n';
}

static bool isValidDexRaw(const unsigned char *data, size_t len) {
    return data != NULL
        && len >= 0x70
        && data[0] == 'd'
        && data[1] == 'e'
        && data[2] == 'x'
        && data[3] == '\n';
}

static std::vector<unsigned char> readAllBytesFromInputStream(JNIEnv *env, jobject inputStream) {
    std::vector<unsigned char> result;
    jclass clsInputStream = env->FindClass("java/io/InputStream");
    jmethodID midRead = env->GetMethodID(clsInputStream, "read", "([B)I");
    jmethodID midClose = env->GetMethodID(clsInputStream, "close", "()V");
    const int bufferSize = 8192;
    jbyteArray buffer = env->NewByteArray(bufferSize);

    while (true) {
        jint readSize = env->CallIntMethod(inputStream, midRead, buffer);
        if (checkException(env, "读取 InputStream")) {
            result.clear();
            return result;
        }
        if (readSize <= 0) break;

        size_t oldSize = result.size();
        result.resize(oldSize + readSize);
        env->GetByteArrayRegion(buffer, 0, readSize,
            reinterpret_cast<jbyte *>(result.data() + oldSize));
        if (checkException(env, "复制 InputStream 数据")) {
            result.clear();
            return result;
        }
    }

    env->CallVoidMethod(inputStream, midClose);
    checkException(env, "关闭 InputStream");
    return result;
}

static std::vector<unsigned char> readSelfClassesDex(JNIEnv *env, jobject context) {
    std::vector<unsigned char> result;
    jclass clsContext = env->GetObjectClass(context);
    jmethodID midGetApplicationInfo = env->GetMethodID(
        clsContext, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, midGetApplicationInfo);
    if (checkException(env, "获取 ApplicationInfo") || appInfo == NULL) return result;

    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    jfieldID fidSourceDir = env->GetFieldID(clsApplicationInfo, "sourceDir",
        "Ljava/lang/String;");
    jstring sourceDirJ = (jstring)env->GetObjectField(appInfo, fidSourceDir);
    if (sourceDirJ == NULL) return result;

    const char *sourceDir = env->GetStringUTFChars(sourceDirJ, NULL);

    jclass clsZipFile = env->FindClass("java/util/zip/ZipFile");
    jmethodID midZipInit = env->GetMethodID(clsZipFile, "<init>", "(Ljava/lang/String;)V");
    jobject zipFile = env->NewObject(clsZipFile, midZipInit, sourceDirJ);
    env->ReleaseStringUTFChars(sourceDirJ, sourceDir);

    if (checkException(env, "创建 ZipFile") || zipFile == NULL) return result;

    jmethodID midGetEntry = env->GetMethodID(clsZipFile, "getEntry",
        "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;");
    jstring entryName = env->NewStringUTF("classes.dex");
    jobject zipEntry = env->CallObjectMethod(zipFile, midGetEntry, entryName);
    if (checkException(env, "获取 classes.dex ZipEntry") || zipEntry == NULL) return result;

    jmethodID midGetInputStream = env->GetMethodID(clsZipFile, "getInputStream",
        "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;");
    jobject inputStream = env->CallObjectMethod(zipFile, midGetInputStream, zipEntry);
    if (checkException(env, "获取 classes.dex InputStream") || inputStream == NULL) return result;

    result = readAllBytesFromInputStream(env, inputStream);

    jmethodID midClose = env->GetMethodID(clsZipFile, "close", "()V");
    env->CallVoidMethod(zipFile, midClose);
    checkException(env, "关闭 ZipFile");

    return result;
}

static std::vector<unsigned char> readSelfClassesDexFromSourceDir(JNIEnv *env, jstring sourceDirJ) {
    std::vector<unsigned char> result;
    if (sourceDirJ == NULL) return result;

    jclass clsZipFile = env->FindClass("java/util/zip/ZipFile");
    if (clsZipFile == NULL) { env->ExceptionClear(); return result; }

    jmethodID midZipInit = env->GetMethodID(clsZipFile, "<init>", "(Ljava/lang/String;)V");
    if (midZipInit == NULL) { env->ExceptionClear(); return result; }

    jobject zipFile = env->NewObject(clsZipFile, midZipInit, sourceDirJ);
    if (checkException(env, "Factory 创建 ZipFile") || zipFile == NULL) return result;

    jmethodID midGetEntry = env->GetMethodID(clsZipFile, "getEntry",
        "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;");
    jstring entryName = env->NewStringUTF("classes.dex");
    jobject zipEntry = env->CallObjectMethod(zipFile, midGetEntry, entryName);
    if (checkException(env, "Factory 获取 classes.dex ZipEntry") || zipEntry == NULL) return result;

    jmethodID midGetInputStream = env->GetMethodID(clsZipFile, "getInputStream",
        "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;");
    jobject inputStream = env->CallObjectMethod(zipFile, midGetInputStream, zipEntry);
    if (checkException(env, "Factory 获取 classes.dex InputStream") || inputStream == NULL) return result;

    result = readAllBytesFromInputStream(env, inputStream);

    jmethodID midClose = env->GetMethodID(clsZipFile, "close", "()V");
    env->CallVoidMethod(zipFile, midClose);
    checkException(env, "Factory 关闭 ZipFile");

    return result;
}

static jobject getCurrentActivityThread(JNIEnv *env) {
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    if (clsActivityThread == NULL) { env->ExceptionClear(); return NULL; }

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (midCurrentActivityThread == NULL) { env->ExceptionClear(); return NULL; }

    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);
    if (checkException(env, "Factory 获取 currentActivityThread")) return NULL;
    return currentActivityThread;
}

static jobject getBoundLoadedApk(JNIEnv *env) {
    jobject currentActivityThread = getCurrentActivityThread(env);
    if (currentActivityThread == NULL) return NULL;

    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsAppBindData = env->FindClass("android/app/ActivityThread$AppBindData");
    if (clsActivityThread == NULL || clsAppBindData == NULL) {
        env->ExceptionClear();
        return NULL;
    }

    jfieldID fidBoundApplication = env->GetFieldID(clsActivityThread, "mBoundApplication",
        "Landroid/app/ActivityThread$AppBindData;");
    if (fidBoundApplication == NULL) { env->ExceptionClear(); return NULL; }

    jobject boundApplication = env->GetObjectField(currentActivityThread, fidBoundApplication);
    if (boundApplication == NULL) return NULL;

    jfieldID fidInfo = env->GetFieldID(clsAppBindData, "info", "Landroid/app/LoadedApk;");
    if (fidInfo == NULL) { env->ExceptionClear(); return NULL; }

    return env->GetObjectField(boundApplication, fidInfo);
}

static jobject getLoadedApkApplicationInfo(JNIEnv *env, jobject loadedApk) {
    if (loadedApk == NULL) return NULL;
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    if (clsLoadedApk == NULL) { env->ExceptionClear(); return NULL; }

    jfieldID fidApplicationInfo = env->GetFieldID(clsLoadedApk, "mApplicationInfo",
        "Landroid/content/pm/ApplicationInfo;");
    if (fidApplicationInfo == NULL) { env->ExceptionClear(); return NULL; }
    return env->GetObjectField(loadedApk, fidApplicationInfo);
}

static jstring getApplicationInfoStringField(JNIEnv *env, jobject appInfo, const char *fieldName) {
    if (appInfo == NULL || fieldName == NULL) return NULL;
    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    if (clsApplicationInfo == NULL) { env->ExceptionClear(); return NULL; }

    jfieldID fid = env->GetFieldID(clsApplicationInfo, fieldName, "Ljava/lang/String;");
    if (fid == NULL) { env->ExceptionClear(); return NULL; }
    return (jstring)env->GetObjectField(appInfo, fid);
}

static jobjectArray loadDexBuffersFromSelfClassesDexBySourceDir(JNIEnv *env, jstring sourceDirJ) {
    std::vector<unsigned char> shellDex = readSelfClassesDexFromSourceDir(env, sourceDirJ);
    if (shellDex.size() < 36) return NULL;

    GuardPayloadFooter footer;
    memset(&footer, 0, sizeof(footer));
    if (!parsePayloadFooterFromTail(shellDex, footer)) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    size_t indexAbsOffset = footer.payloadOff + footer.indexOff;
    if (indexAbsOffset + footer.indexLen > shellDex.size()) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    GuardDexBlockInfo indexInfo;
    memset(&indexInfo, 0, sizeof(indexInfo));
    if (!parseEncryptedBlockInfoByIndex(shellDex, indexAbsOffset, footer.indexLen, indexInfo, NULL)) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    std::vector<unsigned char> indexPlain = xorData(
        shellDex.data() + indexInfo.dataOffset, indexInfo.plainLen, indexInfo.key, 64);

    std::vector<GuardPayloadIndexEntry> indexEntries;
    if (!parsePayloadIndexPlainBytes(indexPlain, indexEntries)) {
        std::vector<unsigned char>().swap(indexPlain);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }
    std::vector<unsigned char>().swap(indexPlain);

    GuardPayloadIndexEntry appEntry, factoryEntry;
    memset(&appEntry, 0, sizeof(appEntry));
    memset(&factoryEntry, 0, sizeof(factoryEntry));
    bool hasAppEntry = false, hasFactoryEntry = false;
    uint32_t dexCount = 0;

    for (size_t i = 0; i < indexEntries.size(); i++) {
        if (indexEntries[i].type == GUARD_BLOCK_TYPE_APP) {
            appEntry = indexEntries[i]; hasAppEntry = true;
        } else if (indexEntries[i].type == GUARD_BLOCK_TYPE_FACTORY) {
            factoryEntry = indexEntries[i]; hasFactoryEntry = true;
        } else if (indexEntries[i].type == GUARD_BLOCK_TYPE_DEX) {
            dexCount++;
        }
    }

    if (!hasAppEntry || dexCount <= 0 || dexCount > 128) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    if (!decryptStringBlockByEntry(shellDex, footer, appEntry, gRealApplicationName)) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    if (hasFactoryEntry) {
        if (!decryptStringBlockByEntry(shellDex, footer, factoryEntry, gRealAppComponentFactoryName)) {
            gRealAppComponentFactoryName.clear();
        }
    } else {
        gRealAppComponentFactoryName.clear();
    }

    if (gRealApplicationName.empty()) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    unsigned char signKey64[64];
    memset(signKey64, 0, sizeof(signKey64));
    if (!getSelfSignKey64(env, signKey64)) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    std::vector<GuardDexBlockInfo> dexBlockList;
    dexBlockList.resize(dexCount);

    for (size_t i = 0; i < indexEntries.size(); i++) {
        GuardPayloadIndexEntry &entry = indexEntries[i];
        if (entry.type != GUARD_BLOCK_TYPE_DEX) continue;
        if (entry.index <= 0 || static_cast<uint32_t>(entry.index) > dexCount) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        size_t absOffset = footer.payloadOff + entry.offset;
        GuardDexBlockInfo info;
        memset(&info, 0, sizeof(info));
        if (absOffset + entry.size > shellDex.size()
            || !parseEncryptedBlockInfoByIndex(shellDex, absOffset, entry.size, info, signKey64)) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }
        dexBlockList[entry.index - 1] = info;
    }
    std::vector<GuardPayloadIndexEntry>().swap(indexEntries);

    jclass clsByteBuffer = env->FindClass("java/nio/ByteBuffer");
    if (clsByteBuffer == NULL) {
        std::vector<GuardDexBlockInfo>().swap(dexBlockList);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    jobjectArray bufferArray = env->NewObjectArray(dexCount, clsByteBuffer, NULL);
    if (bufferArray == NULL) {
        std::vector<GuardDexBlockInfo>().swap(dexBlockList);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    /* 从签名密钥派生 AES-256 密钥 (用于 Layer2) */
    unsigned char aes_key[32];
    memset(aes_key, 0, sizeof(aes_key));
    for (int i = 0; i < 32; i++) {
        aes_key[i] = signKey64[i * 2];
    }

    for (uint32_t i = 0; i < dexCount; i++) {
        GuardDexBlockInfo &info = dexBlockList[i];
        if (info.plainLen <= 0 || info.cipherLen <= 0) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        void *dexMemory = malloc(info.plainLen);
        if (dexMemory == NULL) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        const unsigned char *enc = shellDex.data() + info.dataOffset;

        /* === 三层解密流程 === */
        std::vector<unsigned char> decrypted = decrypt_three_layers(
            enc, info.cipherLen, aes_key, info.key, 64);

        if (decrypted.size() < info.plainLen) {
            free(dexMemory);
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            LOGE("[GuardDexLoader] 三层解密后数据长度不足");
            return NULL;
        }

        memcpy(dexMemory, decrypted.data(), info.plainLen);
        std::vector<unsigned char>().swap(decrypted);

        unsigned char *out = reinterpret_cast<unsigned char *>(dexMemory);
        if (!isValidDexRaw(out, info.plainLen)) {
            free(dexMemory);
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            LOGE("[GuardDexLoader] 解密后的 dex 无效");
            return NULL;
        }

        gDexMemoryList.push_back(dexMemory);

        jobject byteBuffer = env->NewDirectByteBuffer(dexMemory, static_cast<jlong>(info.plainLen));
        if (byteBuffer == NULL) {
            free(dexMemory);
            gDexMemoryList.pop_back();
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        env->SetObjectArrayElement(bufferArray, i, byteBuffer);
        if (checkException(env, "Factory 设置 ByteBuffer 数组元素")) {
            env->DeleteLocalRef(byteBuffer);
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }
        env->DeleteLocalRef(byteBuffer);
    }

    std::vector<GuardDexBlockInfo>().swap(dexBlockList);
    std::vector<unsigned char>().swap(shellDex);

    /* 清理敏感密钥 */
    memset(aes_key, 0, sizeof(aes_key));
    memset(signKey64, 0, sizeof(signKey64));

    return bufferArray;
}

static jobject createDexClassLoaderFromFactory(
        JNIEnv *env, jobjectArray dexBuffers, jstring nativeLibDir, jobject parentClassLoader) {
    if (dexBuffers == NULL || parentClassLoader == NULL) return NULL;

    jclass clsLoader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (clsLoader == NULL) { env->ExceptionClear(); return NULL; }

    jmethodID initMethod = env->GetMethodID(clsLoader, "<init>",
        "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (initMethod != NULL && nativeLibDir != NULL) {
        jobject loader = env->NewObject(clsLoader, initMethod, dexBuffers, nativeLibDir, parentClassLoader);
        if (!checkException(env, "Factory 创建三参数 InMemoryDexClassLoader") && loader != NULL) {
            return loader;
        }
    }
    env->ExceptionClear();

    initMethod = env->GetMethodID(clsLoader, "<init>",
        "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (initMethod == NULL) { env->ExceptionClear(); return NULL; }

    jobject loader = env->NewObject(clsLoader, initMethod, dexBuffers, parentClassLoader);
    if (checkException(env, "Factory 创建双参数 InMemoryDexClassLoader")) return NULL;
    return loader;
}

static bool replaceBoundLoadedApkClassLoader(JNIEnv *env, jobject loadedApk, jobject newClassLoader) {
    if (loadedApk == NULL || newClassLoader == NULL) return false;

    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    if (clsLoadedApk == NULL) { env->ExceptionClear(); return false; }

    jfieldID fidClassLoader = env->GetFieldID(clsLoadedApk, "mClassLoader",
        "Ljava/lang/ClassLoader;");
    if (fidClassLoader == NULL) { env->ExceptionClear(); return false; }

    env->SetObjectField(loadedApk, fidClassLoader, newClassLoader);
    if (checkException(env, "Factory 替换 LoadedApk.mClassLoader")) return false;
    return true;
}

bool LoaderDEXFromFactory(JNIEnv *env, jobject parentClassLoader) {
    if (gGuardDexLoaded) return true;
    if (env == NULL || parentClassLoader == NULL) return false;

    int sdk = getSdkInt(env);
    if (sdk < 26) return false;

    jobject loadedApk = getBoundLoadedApk(env);
    if (loadedApk == NULL) return false;

    jobject appInfo = getLoadedApkApplicationInfo(env, loadedApk);
    if (appInfo == NULL) return false;

    jstring sourceDir = getApplicationInfoStringField(env, appInfo, "sourceDir");
    if (sourceDir == NULL) return false;

    jstring nativeLibDir = getApplicationInfoStringField(env, appInfo, "nativeLibraryDir");

    jobjectArray dexBuffers = loadDexBuffersFromSelfClassesDexBySourceDir(env, sourceDir);
    if (dexBuffers == NULL) return false;

    jobject newClassLoader = createDexClassLoaderFromFactory(env, dexBuffers, nativeLibDir, parentClassLoader);
    if (newClassLoader == NULL) return false;

    if (!replaceBoundLoadedApkClassLoader(env, loadedApk, newClassLoader)) return false;

    gGuardDexLoaded = true;
    return true;
}

/* ================================================================
 * Native 层 DEX 加载入口 (带三层解密 + 防调试)
 * ================================================================ */
static jobjectArray loadDexBuffersFromSelfClassesDex(JNIEnv *env, jobject context) {
    std::vector<unsigned char> shellDex = readSelfClassesDex(env, context);
    if (shellDex.size() < 36) return NULL;

    GuardPayloadFooter footer;
    memset(&footer, 0, sizeof(footer));
    if (!parsePayloadFooterFromTail(shellDex, footer)) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    size_t indexAbsOffset = footer.payloadOff + footer.indexOff;
    if (indexAbsOffset + footer.indexLen > shellDex.size()) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    GuardDexBlockInfo indexInfo;
    memset(&indexInfo, 0, sizeof(indexInfo));
    if (!parseEncryptedBlockInfoByIndex(shellDex, indexAbsOffset, footer.indexLen, indexInfo, NULL)) {
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    std::vector<unsigned char> indexPlain = xorData(
        shellDex.data() + indexInfo.dataOffset, indexInfo.plainLen, indexInfo.key, 64);

    std::vector<GuardPayloadIndexEntry> indexEntries;
    if (!parsePayloadIndexPlainBytes(indexPlain, indexEntries)) {
        std::vector<unsigned char>().swap(indexPlain);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }
    std::vector<unsigned char>().swap(indexPlain);

    GuardPayloadIndexEntry appEntry, factoryEntry;
    memset(&appEntry, 0, sizeof(appEntry));
    memset(&factoryEntry, 0, sizeof(factoryEntry));
    bool hasAppEntry = false, hasFactoryEntry = false;
    uint32_t dexCount = 0;

    for (size_t i = 0; i < indexEntries.size(); i++) {
        if (indexEntries[i].type == GUARD_BLOCK_TYPE_APP) {
            appEntry = indexEntries[i]; hasAppEntry = true;
        } else if (indexEntries[i].type == GUARD_BLOCK_TYPE_FACTORY) {
            factoryEntry = indexEntries[i]; hasFactoryEntry = true;
        } else if (indexEntries[i].type == GUARD_BLOCK_TYPE_DEX) {
            dexCount++;
        }
    }

    if (!hasAppEntry || dexCount <= 0 || dexCount > 128) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    if (!decryptStringBlockByEntry(shellDex, footer, appEntry, gRealApplicationName)) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    if (hasFactoryEntry) {
        if (!decryptStringBlockByEntry(shellDex, footer, factoryEntry, gRealAppComponentFactoryName)) {
            gRealAppComponentFactoryName.clear();
        }
    } else {
        gRealAppComponentFactoryName.clear();
    }

    if (gRealApplicationName.empty()) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    unsigned char signKey64[64];
    memset(signKey64, 0, sizeof(signKey64));
    if (!getSelfSignKey64(env, signKey64)) {
        std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    std::vector<GuardDexBlockInfo> dexBlockList;
    dexBlockList.resize(dexCount);

    for (size_t i = 0; i < indexEntries.size(); i++) {
        GuardPayloadIndexEntry &entry = indexEntries[i];
        if (entry.type != GUARD_BLOCK_TYPE_DEX) continue;
        if (entry.index <= 0 || static_cast<uint32_t>(entry.index) > dexCount) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        size_t absOffset = footer.payloadOff + entry.offset;
        if (absOffset + entry.size > shellDex.size()) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        GuardDexBlockInfo info;
        memset(&info, 0, sizeof(info));
        if (!parseEncryptedBlockInfoByIndex(shellDex, absOffset, entry.size, info, signKey64)) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<GuardPayloadIndexEntry>().swap(indexEntries);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }
        dexBlockList[entry.index - 1] = info;
    }
    std::vector<GuardPayloadIndexEntry>().swap(indexEntries);

    jclass clsByteBuffer = env->FindClass("java/nio/ByteBuffer");
    if (clsByteBuffer == NULL) {
        std::vector<GuardDexBlockInfo>().swap(dexBlockList);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }
    jmethodID midWrap = env->GetStaticMethodID(clsByteBuffer, "wrap", "([B)Ljava/nio/ByteBuffer;");

    jobjectArray bufferArray = env->NewObjectArray(dexCount, clsByteBuffer, NULL);
    if (bufferArray == NULL) {
        std::vector<GuardDexBlockInfo>().swap(dexBlockList);
        std::vector<unsigned char>().swap(shellDex);
        return NULL;
    }

    int sdk = getSdkInt(env);

    /* 从签名密钥派生 AES-256 密钥 (用于 Layer2) */
    unsigned char aes_key[32];
    memset(aes_key, 0, sizeof(aes_key));
    for (int i = 0; i < 32; i++) {
        aes_key[i] = signKey64[i * 2];
    }

    for (uint32_t i = 0; i < dexCount; i++) {
        GuardDexBlockInfo &info = dexBlockList[i];
        if (info.plainLen <= 0 || info.cipherLen <= 0) {
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }

        jobject byteBuffer = NULL;

        if (sdk >= 26) {
            void *dexMemory = malloc(info.plainLen);
            if (dexMemory == NULL) {
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            const unsigned char *enc = shellDex.data() + info.dataOffset;

            /* === 三层解密流程 === */
            std::vector<unsigned char> decrypted = decrypt_three_layers(
                enc, info.cipherLen, aes_key, info.key, 64);

            if (decrypted.size() < info.plainLen) {
                free(dexMemory);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            memcpy(dexMemory, decrypted.data(), info.plainLen);
            std::vector<unsigned char>().swap(decrypted);

            unsigned char *out = reinterpret_cast<unsigned char *>(dexMemory);
            if (!isValidDexRaw(out, info.plainLen)) {
                free(dexMemory);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            gDexMemoryList.push_back(dexMemory);
            byteBuffer = env->NewDirectByteBuffer(dexMemory, static_cast<jlong>(info.plainLen));
            if (byteBuffer == NULL) {
                free(dexMemory);
                gDexMemoryList.pop_back();
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }
        } else {
            const unsigned char *enc = shellDex.data() + info.dataOffset;

            /* === 三层解密流程 (低版本 Android) === */
            std::vector<unsigned char> decrypted = decrypt_three_layers(
                enc, info.cipherLen, aes_key, info.key, 64);

            if (decrypted.size() < info.plainLen) {
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            decrypted.resize(info.plainLen);

            if (!isValidDexData(decrypted)) {
                std::vector<unsigned char>().swap(decrypted);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            jbyteArray dexArray = env->NewByteArray(static_cast<jsize>(decrypted.size()));
            if (dexArray == NULL) {
                std::vector<unsigned char>().swap(decrypted);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            env->SetByteArrayRegion(dexArray, 0, static_cast<jsize>(decrypted.size()),
                reinterpret_cast<const jbyte *>(decrypted.data()));
            if (checkException(env, "写入 dex byte[]")) {
                env->DeleteLocalRef(dexArray);
                std::vector<unsigned char>().swap(decrypted);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            byteBuffer = env->CallStaticObjectMethod(clsByteBuffer, midWrap, dexArray);
            if (checkException(env, "ByteBuffer.wrap") || byteBuffer == NULL) {
                env->DeleteLocalRef(dexArray);
                std::vector<unsigned char>().swap(decrypted);
                std::vector<GuardDexBlockInfo>().swap(dexBlockList);
                std::vector<unsigned char>().swap(shellDex);
                return NULL;
            }

            env->DeleteLocalRef(dexArray);
            std::vector<unsigned char>().swap(decrypted);
        }

        env->SetObjectArrayElement(bufferArray, i, byteBuffer);
        if (checkException(env, "设置 ByteBuffer 数组元素")) {
            if (byteBuffer != NULL) env->DeleteLocalRef(byteBuffer);
            std::vector<GuardDexBlockInfo>().swap(dexBlockList);
            std::vector<unsigned char>().swap(shellDex);
            return NULL;
        }
        if (byteBuffer != NULL) env->DeleteLocalRef(byteBuffer);
    }

    std::vector<GuardDexBlockInfo>().swap(dexBlockList);
    std::vector<unsigned char>().swap(shellDex);

    /* 清理敏感密钥 */
    memset(aes_key, 0, sizeof(aes_key));
    memset(signKey64, 0, sizeof(signKey64));

    return bufferArray;
}

static jstring getPackageName(JNIEnv *env, jobject context) {
    jclass clsContext = env->GetObjectClass(context);
    jmethodID midGetPackageName = env->GetMethodID(clsContext, "getPackageName",
        "()Ljava/lang/String;");
    return (jstring)env->CallObjectMethod(context, midGetPackageName);
}

static bool writeFileBytes(const char *path, const unsigned char *data, int len) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return false;
    int written = fwrite(data, 1, len, fp);
    fclose(fp);
    if (written != len) return false;
    chmod(path, 0600);
    return true;
}

static jstring getAbsolutePath(JNIEnv *env, jobject fileObj) {
    jclass clsFile = env->FindClass("java/io/File");
    jmethodID midGetAbsolutePath = env->GetMethodID(clsFile, "getAbsolutePath",
        "()Ljava/lang/String;");
    return (jstring)env->CallObjectMethod(fileObj, midGetAbsolutePath);
}

static jobject getCodeCacheDir(JNIEnv *env, jobject context) {
    jclass clsContext = env->GetObjectClass(context);
    jmethodID midGetCodeCacheDir = env->GetMethodID(clsContext, "getCodeCacheDir",
        "()Ljava/io/File;");
    if (midGetCodeCacheDir != NULL) {
        jobject dir = env->CallObjectMethod(context, midGetCodeCacheDir);
        if (!checkException(env, "调用 getCodeCacheDir") && dir != NULL) return dir;
    }
    jmethodID midGetDir = env->GetMethodID(clsContext, "getDir",
        "(Ljava/lang/String;I)Ljava/io/File;");
    jstring name = env->NewStringUTF("ark_code_cache");
    return env->CallObjectMethod(context, midGetDir, name, 0);
}

static bool ensureDir(JNIEnv *env, jobject fileObj) {
    jclass clsFile = env->FindClass("java/io/File");
    jmethodID midExists = env->GetMethodID(clsFile, "exists", "()Z");
    jmethodID midMkdirs = env->GetMethodID(clsFile, "mkdirs", "()Z");
    jboolean exists = env->CallBooleanMethod(fileObj, midExists);
    if (exists) return true;
    jboolean ok = env->CallBooleanMethod(fileObj, midMkdirs);
    return ok == JNI_TRUE;
}

static jobject newFile(JNIEnv *env, jobject parent, const char *child) {
    jclass clsFile = env->FindClass("java/io/File");
    jmethodID midInit = env->GetMethodID(clsFile, "<init>",
        "(Ljava/io/File;Ljava/lang/String;)V");
    jstring childName = env->NewStringUTF(child);
    return env->NewObject(clsFile, midInit, parent, childName);
}

static jstring buildDexPathFromBuffers(JNIEnv *env, jobject context, jobjectArray dexBuffers) {
    jobject codeCacheDir = getCodeCacheDir(env, context);
    if (codeCacheDir == NULL) return NULL;

    jobject dexDir = newFile(env, codeCacheDir, "ark_dex");
    jobject optDir = newFile(env, codeCacheDir, "ark_opt");
    if (!ensureDir(env, dexDir) || !ensureDir(env, optDir)) return NULL;

    int dexCount = env->GetArrayLength(dexBuffers);
    std::string dexPath;

    jclass clsByteBuffer = env->FindClass("java/nio/ByteBuffer");
    jmethodID midRemaining = env->GetMethodID(clsByteBuffer, "remaining", "()I");
    jmethodID midGet = env->GetMethodID(clsByteBuffer, "get", "([B)Ljava/nio/ByteBuffer;");
    jmethodID midPosition = env->GetMethodID(clsByteBuffer, "position", "()I");
    jmethodID midPositionSet = env->GetMethodID(clsByteBuffer, "position",
        "(I)Ljava/nio/Buffer;");

    for (int i = 0; i < dexCount; i++) {
        jobject buffer = env->GetObjectArrayElement(dexBuffers, i);
        if (buffer == NULL) return NULL;

        jint oldPos = env->CallIntMethod(buffer, midPosition);
        jint len = env->CallIntMethod(buffer, midRemaining);
        if (len <= 0) return NULL;

        jbyteArray byteArray = env->NewByteArray(len);
        if (byteArray == NULL) return NULL;

        env->CallObjectMethod(buffer, midGet, byteArray);
        if (checkException(env, "读取 ByteBuffer 数据")) return NULL;
        env->CallObjectMethod(buffer, midPositionSet, oldPos);

        std::vector<unsigned char> dexData(len);
        env->GetByteArrayRegion(byteArray, 0, len,
            reinterpret_cast<jbyte *>(dexData.data()));
        if (checkException(env, "复制 dex byte[]")) return NULL;

        char dexName[64];
        snprintf(dexName, sizeof(dexName), "ark_payload_%d.dex", i);

        jobject dexFile = newFile(env, dexDir, dexName);
        jstring dexFilePathJ = getAbsolutePath(env, dexFile);
        const char *dexFilePath = env->GetStringUTFChars(dexFilePathJ, NULL);

        bool writeOk = writeFileBytes(dexFilePath, dexData.data(), len);
        if (dexPath.empty()) {
            dexPath = dexFilePath;
        } else {
            dexPath += ":";
            dexPath += dexFilePath;
        }
        env->ReleaseStringUTFChars(dexFilePathJ, dexFilePath);
        if (!writeOk) return NULL;
    }

    return env->NewStringUTF(dexPath.c_str());
}

static jobject createFileDexClassLoader(JNIEnv *env, jobject context,
    jobjectArray dexBuffers, jobject parentClassLoader) {
    jstring dexPath = buildDexPathFromBuffers(env, context, dexBuffers);
    if (dexPath == NULL) return NULL;

    jobject codeCacheDir = getCodeCacheDir(env, context);
    jobject optDir = newFile(env, codeCacheDir, "ark_opt");
    if (!ensureDir(env, optDir)) return NULL;

    jstring optPath = getAbsolutePath(env, optDir);
    jclass clsContext = env->GetObjectClass(context);
    jmethodID midGetApplicationInfo = env->GetMethodID(clsContext, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, midGetApplicationInfo);
    if (checkException(env, "获取 ApplicationInfo") || appInfo == NULL) return NULL;

    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    jfieldID fidNativeLibraryDir = env->GetFieldID(clsApplicationInfo, "nativeLibraryDir",
        "Ljava/lang/String;");
    jstring nativeLibDir = (jstring)env->GetObjectField(appInfo, fidNativeLibraryDir);
    if (nativeLibDir == NULL) return NULL;

    jclass clsDexClassLoader = env->FindClass("dalvik/system/DexClassLoader");
    if (clsDexClassLoader == NULL) return NULL;

    jmethodID midInit = env->GetMethodID(clsDexClassLoader, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (midInit == NULL) return NULL;

    jobject loader = env->NewObject(clsDexClassLoader, midInit,
        dexPath, optPath, nativeLibDir, parentClassLoader);
    if (checkException(env, "创建 DexClassLoader")) return NULL;

    const char *dexPathChars = env->GetStringUTFChars(dexPath, NULL);
    if (dexPathChars != NULL) {
        std::string allPath = dexPathChars;
        env->ReleaseStringUTFChars(dexPath, dexPathChars);
        size_t start = 0;
        while (start < allPath.length()) {
            size_t pos = allPath.find(':', start);
            std::string onePath = allPath.substr(start,
                pos == std::string::npos ? std::string::npos : pos - start);
            if (!onePath.empty()) unlink(onePath.c_str());
            if (pos == std::string::npos) break;
            start = pos + 1;
        }
    }
    return loader;
}

static jobject createDexClassLoader(JNIEnv *env, jobject context, jobjectArray dexBuffers) {
    jclass clsContext = env->GetObjectClass(context);
    jmethodID midGetClassLoader = env->GetMethodID(clsContext, "getClassLoader",
        "()Ljava/lang/ClassLoader;");
    jobject parentClassLoader = env->CallObjectMethod(context, midGetClassLoader);
    if (checkException(env, "获取父 ClassLoader")) return NULL;

    jmethodID midGetApplicationInfo = env->GetMethodID(clsContext, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, midGetApplicationInfo);
    if (checkException(env, "获取 ApplicationInfo") || appInfo == NULL) return NULL;

    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    jfieldID fidNativeLibraryDir = env->GetFieldID(clsApplicationInfo, "nativeLibraryDir",
        "Ljava/lang/String;");
    jstring nativeLibDir = (jstring)env->GetObjectField(appInfo, fidNativeLibraryDir);
    if (nativeLibDir == NULL) return NULL;

    int sdk = getSdkInt(env);
    if (sdk >= 26) {
        jclass clsLoader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        if (clsLoader == NULL) return NULL;
        jmethodID initMethod = env->GetMethodID(clsLoader, "<init>",
            "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        if (initMethod == NULL) return NULL;
        jobject loader = env->NewObject(clsLoader, initMethod,
            dexBuffers, nativeLibDir, parentClassLoader);
        if (checkException(env, "创建系统 InMemoryDexClassLoader")) return NULL;
        return loader;
    }
    return createFileDexClassLoader(env, context, dexBuffers, parentClassLoader);
}

static bool replaceLoadedApkClassLoader(JNIEnv *env, jobject context, jobject newClassLoader) {
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsMap = env->FindClass("java/util/Map");
    jclass clsReference = env->FindClass("java/lang/ref/Reference");
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    if (!clsActivityThread || !clsMap || !clsReference || !clsLoadedApk) return false;

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);
    if (checkException(env, "获取 currentActivityThread")) return false;
    if (currentActivityThread == NULL) return false;

    jfieldID fidPackages = env->GetFieldID(clsActivityThread, "mPackages", "Landroid/util/ArrayMap;");
    jobject mPackages = env->GetObjectField(currentActivityThread, fidPackages);
    if (mPackages == NULL) return false;

    jstring packageName = getPackageName(env, context);
    jmethodID midMapGet = env->GetMethodID(clsMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject weakRefLoadedApk = env->CallObjectMethod(mPackages, midMapGet, packageName);
    if (checkException(env, "从 mPackages 获取 LoadedApk 引用")) return false;
    if (weakRefLoadedApk == NULL) return false;

    jmethodID midReferenceGet = env->GetMethodID(clsReference, "get", "()Ljava/lang/Object;");
    jobject loadedApk = env->CallObjectMethod(weakRefLoadedApk, midReferenceGet);
    if (loadedApk == NULL) return false;

    jfieldID fidClassLoader = env->GetFieldID(clsLoadedApk, "mClassLoader",
        "Ljava/lang/ClassLoader;");
    env->SetObjectField(loadedApk, fidClassLoader, newClassLoader);
    return true;
}

static jobject getPackageLoadedApk(JNIEnv *env, jobject context) {
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsMap = env->FindClass("java/util/Map");
    jclass clsReference = env->FindClass("java/lang/ref/Reference");
    if (!clsActivityThread || !clsMap || !clsReference) {
        env->ExceptionClear();
        return NULL;
    }

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);
    if (checkException(env, "获取 currentActivityThread") || currentActivityThread == NULL) return NULL;

    jfieldID fidPackages = env->GetFieldID(clsActivityThread, "mPackages", "Landroid/util/ArrayMap;");
    jobject mPackages = env->GetObjectField(currentActivityThread, fidPackages);
    if (mPackages == NULL) return NULL;

    jstring packageName = getPackageName(env, context);
    if (packageName == NULL) return NULL;

    jmethodID midMapGet = env->GetMethodID(clsMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject weakRefLoadedApk = env->CallObjectMethod(mPackages, midMapGet, packageName);
    if (checkException(env, "获取 mPackages LoadedApk 弱引用") || weakRefLoadedApk == NULL) return NULL;

    jmethodID midReferenceGet = env->GetMethodID(clsReference, "get", "()Ljava/lang/Object;");
    jobject loadedApk = env->CallObjectMethod(weakRefLoadedApk, midReferenceGet);
    if (checkException(env, "获取 mPackages LoadedApk") || loadedApk == NULL) return NULL;

    return loadedApk;
}

static bool replacePackageLoadedApkApplication(JNIEnv *env, jobject context, jobject realApplication) {
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsMap = env->FindClass("java/util/Map");
    jclass clsReference = env->FindClass("java/lang/ref/Reference");
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    if (!clsActivityThread || !clsMap || !clsReference || !clsLoadedApk) return false;

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);
    if (checkException(env, "获取 currentActivityThread") || currentActivityThread == NULL) return false;

    jfieldID fidPackages = env->GetFieldID(clsActivityThread, "mPackages", "Landroid/util/ArrayMap;");
    jobject mPackages = env->GetObjectField(currentActivityThread, fidPackages);
    if (mPackages == NULL) return false;

    jstring packageName = getPackageName(env, context);
    if (packageName == NULL) return false;

    jmethodID midMapGet = env->GetMethodID(clsMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject weakRefLoadedApk = env->CallObjectMethod(mPackages, midMapGet, packageName);
    if (checkException(env, "从 mPackages 获取 LoadedApk 弱引用") || weakRefLoadedApk == NULL) return false;

    jmethodID midReferenceGet = env->GetMethodID(clsReference, "get", "()Ljava/lang/Object;");
    jobject packageLoadedApk = env->CallObjectMethod(weakRefLoadedApk, midReferenceGet);
    if (checkException(env, "从弱引用获取 LoadedApk") || packageLoadedApk == NULL) return false;

    jfieldID fidLoadedApkApplication = env->GetFieldID(clsLoadedApk, "mApplication",
        "Landroid/app/Application;");
    if (fidLoadedApkApplication == NULL || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    env->SetObjectField(packageLoadedApk, fidLoadedApkApplication, realApplication);
    if (checkException(env, "替换 mPackages LoadedApk.mApplication")) return false;
    return true;
}

static void replaceAllActivityApplication(JNIEnv *env, jobject realApplication) {
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsMap = env->FindClass("java/util/Map");
    jclass clsCollection = env->FindClass("java/util/Collection");
    jclass clsIterator = env->FindClass("java/util/Iterator");
    jclass clsActivity = env->FindClass("android/app/Activity");

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);

    jfieldID fidActivities = env->GetFieldID(clsActivityThread, "mActivities", "Landroid/util/ArrayMap;");
    jobject mActivities = env->GetObjectField(currentActivityThread, fidActivities);
    if (mActivities == NULL) return;

    jmethodID midValues = env->GetMethodID(clsMap, "values", "()Ljava/util/Collection;");
    jobject values = env->CallObjectMethod(mActivities, midValues);
    jmethodID midIterator = env->GetMethodID(clsCollection, "iterator", "()Ljava/util/Iterator;");
    jobject iterator = env->CallObjectMethod(values, midIterator);
    jmethodID midHasNext = env->GetMethodID(clsIterator, "hasNext", "()Z");
    jmethodID midNext = env->GetMethodID(clsIterator, "next", "()Ljava/lang/Object;");

    while (env->CallBooleanMethod(iterator, midHasNext)) {
        jobject activityClientRecord = env->CallObjectMethod(iterator, midNext);
        if (activityClientRecord == NULL) continue;

        jclass clsRecord = env->GetObjectClass(activityClientRecord);
        jfieldID fidActivity = env->GetFieldID(clsRecord, "activity", "Landroid/app/Activity;");
        if (env->ExceptionCheck() || fidActivity == NULL) {
            env->ExceptionClear();
            continue;
        }

        jobject activity = env->GetObjectField(activityClientRecord, fidActivity);
        if (activity == NULL) continue;

        jfieldID fidApplication = env->GetFieldID(clsActivity, "mApplication",
            "Landroid/app/Application;");
        if (env->ExceptionCheck() || fidApplication == NULL) {
            env->ExceptionClear();
            continue;
        }
        env->SetObjectField(activity, fidApplication, realApplication);
        env->ExceptionClear();
    }
}

static bool startRealApplication(JNIEnv *env, jobject context) {
    if (env == NULL || context == NULL) return false;

    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsAppBindData = env->FindClass("android/app/ActivityThread$AppBindData");
    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    jclass clsApplication = env->FindClass("android/app/Application");
    jclass clsList = env->FindClass("java/util/List");
    jclass clsClassLoader = env->FindClass("java/lang/ClassLoader");
    jclass clsClass = env->FindClass("java/lang/Class");

    if (!clsActivityThread || !clsAppBindData || !clsApplicationInfo
        || !clsLoadedApk || !clsApplication || !clsList
        || !clsClassLoader || !clsClass) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midCurrentActivityThread = env->GetStaticMethodID(
        clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject currentActivityThread = env->CallStaticObjectMethod(
        clsActivityThread, midCurrentActivityThread);
    if (checkException(env, "获取 currentActivityThread") || currentActivityThread == NULL) return false;

    jfieldID fidBoundApplication = env->GetFieldID(clsActivityThread, "mBoundApplication",
        "Landroid/app/ActivityThread$AppBindData;");
    jobject boundApplication = env->GetObjectField(currentActivityThread, fidBoundApplication);
    if (boundApplication == NULL) return false;

    jfieldID fidInfo = env->GetFieldID(clsAppBindData, "info", "Landroid/app/LoadedApk;");
    jobject loadedApk = env->GetObjectField(boundApplication, fidInfo);
    if (loadedApk == NULL) return false;

    jobject packageLoadedApk = getPackageLoadedApk(env, context);

    jfieldID fidLoadedApkApplication = env->GetFieldID(clsLoadedApk, "mApplication",
        "Landroid/app/Application;");
    jfieldID fidLoadedApkApplicationInfo = env->GetFieldID(clsLoadedApk, "mApplicationInfo",
        "Landroid/content/pm/ApplicationInfo;");
    jfieldID fidClassLoader = env->GetFieldID(clsLoadedApk, "mClassLoader",
        "Ljava/lang/ClassLoader;");
    jfieldID fidInitialApplication = env->GetFieldID(clsActivityThread, "mInitialApplication",
        "Landroid/app/Application;");
    jfieldID fidAllApplications = env->GetFieldID(clsActivityThread, "mAllApplications",
        "Ljava/util/ArrayList;");
    jfieldID fidAppInfo = env->GetFieldID(clsAppBindData, "appInfo",
        "Landroid/content/pm/ApplicationInfo;");
    jfieldID fidClassName = env->GetFieldID(clsApplicationInfo, "className",
        "Ljava/lang/String;");

    if (env->ExceptionCheck()
        || fidLoadedApkApplication == NULL
        || fidLoadedApkApplicationInfo == NULL
        || fidClassLoader == NULL
        || fidInitialApplication == NULL
        || fidAllApplications == NULL
        || fidAppInfo == NULL
        || fidClassName == NULL) {
        env->ExceptionClear();
        return false;
    }

    if (gRealApplicationName.empty()) return false;

    std::string realAppNameStr = gRealApplicationName;
    for (size_t i = 0; i < realAppNameStr.length(); i++) {
        if (realAppNameStr[i] == '/') realAppNameStr[i] = '.';
    }

    jstring realAppName = env->NewStringUTF(realAppNameStr.c_str());
    if (realAppName == NULL) return false;

    jobject oldApplication = env->GetObjectField(currentActivityThread, fidInitialApplication);
    jobject allApplications = env->GetObjectField(currentActivityThread, fidAllApplications);

    if (oldApplication != NULL && allApplications != NULL) {
        jmethodID midRemoveObject = env->GetMethodID(clsList, "remove", "(Ljava/lang/Object;)Z");
        if (midRemoveObject != NULL) {
            env->CallBooleanMethod(allApplications, midRemoveObject, oldApplication);
            checkException(env, "移除旧 Application");
        }
    }

    env->SetObjectField(loadedApk, fidLoadedApkApplication, NULL);
    checkException(env, "清空 boundApplication LoadedApk.mApplication");
    if (packageLoadedApk != NULL) {
        env->SetObjectField(packageLoadedApk, fidLoadedApkApplication, NULL);
        checkException(env, "清空 package LoadedApk.mApplication");
    }

    jobject loadedApkApplicationInfo = env->GetObjectField(loadedApk, fidLoadedApkApplicationInfo);
    if (loadedApkApplicationInfo != NULL) {
        env->SetObjectField(loadedApkApplicationInfo, fidClassName, realAppName);
    }
    if (packageLoadedApk != NULL) {
        jobject packageLoadedApkApplicationInfo = env->GetObjectField(
            packageLoadedApk, fidLoadedApkApplicationInfo);
        if (packageLoadedApkApplicationInfo != NULL) {
            env->SetObjectField(packageLoadedApkApplicationInfo, fidClassName, realAppName);
        }
    }

    jobject appInfo = env->GetObjectField(boundApplication, fidAppInfo);
    if (appInfo != NULL) {
        env->SetObjectField(appInfo, fidClassName, realAppName);
    }

    if (checkException(env, "设置真实 Application className")) return false;

    jobject classLoader = env->GetObjectField(loadedApk, fidClassLoader);
    if (classLoader == NULL && packageLoadedApk != NULL) {
        classLoader = env->GetObjectField(packageLoadedApk, fidClassLoader);
    }
    if (classLoader == NULL) return false;

    jmethodID midLoadClass = env->GetMethodID(clsClassLoader, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    if (midLoadClass == NULL || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jobject realAppClass = env->CallObjectMethod(classLoader, midLoadClass, realAppName);
    if (checkException(env, "加载真实 Application 类") || realAppClass == NULL) return false;

    jmethodID midNewInstance = env->GetMethodID(clsClass, "newInstance", "()Ljava/lang/Object;");
    if (midNewInstance == NULL || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jobject realApplication = env->CallObjectMethod(realAppClass, midNewInstance);
    if (checkException(env, "创建真实 Application 实例") || realApplication == NULL) return false;

    env->SetObjectField(loadedApk, fidLoadedApkApplication, realApplication);
    if (packageLoadedApk != NULL) {
        env->SetObjectField(packageLoadedApk, fidLoadedApkApplication, realApplication);
    }
    env->SetObjectField(currentActivityThread, fidInitialApplication, realApplication);
    if (checkException(env, "替换 Application 引用")) return false;

    jmethodID midAttach = env->GetMethodID(clsApplication, "attach", "(Landroid/content/Context;)V");
    if (midAttach == NULL || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    env->CallVoidMethod(realApplication, midAttach, context);
    if (checkException(env, "调用真实 Application.attach")) return false;

    replacePackageLoadedApkApplication(env, context, realApplication);
    replaceAllActivityApplication(env, realApplication);

    jmethodID midOnCreate = env->GetMethodID(clsApplication, "onCreate", "()V");
    if (midOnCreate == NULL || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    env->CallVoidMethod(realApplication, midOnCreate);
    if (checkException(env, "调用真实 Application.onCreate")) return false;

    return true;
}

/* ================================================================
 * 主入口函数
 * ================================================================ */

bool LoaderDEX(JNIEnv *env, jobject context) {
    /* 防调试检测 */
    if (s_anti_debug_enabled && !check_tracer_pid()) {
        LOGE("[GuardDexLoader] 检测到调试器, 拒绝加载 DEX");
        exit(0);
    }

    if (gGuardDexLoaded) return true;
    if (env == NULL || context == NULL) return false;

    jobjectArray dexBuffers = loadDexBuffersFromSelfClassesDex(env, context);
    if (dexBuffers == NULL) return false;

    jobject newClassLoader = createDexClassLoader(env, context, dexBuffers);
    if (newClassLoader == NULL) return false;

    if (!replaceLoadedApkClassLoader(env, context, newClassLoader)) return false;

    gGuardDexLoaded = true;
    return true;
}

bool StartRealApplicationFromNative(JNIEnv *env, jobject context) {
    static bool sRealApplicationStarted = false;
    if (sRealApplicationStarted) return true;

    if (!startRealApplication(env, context)) return false;
    sRealApplicationStarted = true;
    return true;
}

GuardDexLoaderFunc GuardDexLoader_GetEntry() {
    volatile GuardDexLoaderFunc fn = LoaderDEX;
    return fn;
}

GuardDexLoaderFactoryFunc GuardDexLoader_GetFactoryEntry() {
    volatile GuardDexLoaderFactoryFunc fn = LoaderDEXFromFactory;
    return fn;
}

GuardRealApplicationStarterFunc GuardDexLoader_GetStartRealApplicationEntry() {
    volatile GuardRealApplicationStarterFunc fn = StartRealApplicationFromNative;
    return fn;
}

const char *GuardDexLoader_GetRealAppComponentFactoryName() {
    if (gRealAppComponentFactoryName.empty()) return NULL;
    return gRealAppComponentFactoryName.c_str();
}
