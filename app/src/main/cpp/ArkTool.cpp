#include "ArkTool.h"

#include <jni.h>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <unistd.h>
#include <stdint.h>
#include <string>

#if __has_include(<sys/random.h>)
#include <sys/random.h>
#endif

static bool fillRandomBytes(unsigned char *buffer, int len);

static const int ARK_BLOCK_TYPE_DEX = 1;
static const int ARK_BLOCK_TYPE_APP = 2;
static const int ARK_BLOCK_TYPE_INDEX = 3;
static const int ARK_BLOCK_TYPE_FACTORY = 4;

static const int ARK_BLOCK_FLAG_RANDOM_KEY = 1;
static const int ARK_BLOCK_FLAG_SIGN_KEY = 2;

static const int ARK_BLOCK_FLAG_LAYER_1 = 0x100;
static const int ARK_BLOCK_FLAG_LAYER_2 = 0x200;
static const int ARK_BLOCK_FLAG_LAYER_3 = 0x400;
static const int ARK_BLOCK_FLAG_MULTI_LAYER = ARK_BLOCK_FLAG_LAYER_1 | ARK_BLOCK_FLAG_LAYER_2 | ARK_BLOCK_FLAG_LAYER_3;

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

struct DisguiseMagic {
    const char *name;
    unsigned char magic[8];
    int magicLen;
};

static const DisguiseMagic DISGUISE_TABLE[] = {
    {"360jiagu",       {0x33, 0x36, 0x30, 0x4A, 0x69, 0x61, 0x47, 0x75}, 8},
    {"tencent_legu",   {0x54, 0x58, 0x4C, 0x47, 0x00, 0x01, 0x02, 0x03}, 8},
    {"ijiami",         {0x49, 0x4A, 0x49, 0x41, 0x4D, 0x49, 0x00, 0x00}, 8},
    {"wangyi_yidun",   {0x4E, 0x45, 0x54, 0x45, 0x41, 0x53, 0x45, 0x00}, 8},
    {"bangcle",        {0x42, 0x61, 0x6E, 0x67, 0x63, 0x6C, 0x65, 0x00}, 8},
    {"alibaba",        {0x41, 0x4C, 0x49, 0x50, 0x41, 0x59, 0x00, 0x01}, 8},
};

static const int DISGUISE_COUNT = sizeof(DISGUISE_TABLE) / sizeof(DISGUISE_TABLE[0]);

static const unsigned char ARK_INDEX_MAGIC[4] = {0x71, 0x32, 0xA6, 0x4D};
static const unsigned char ARK_BLOCK_MAGIC[4] = {0x63, 0x19, 0xB7, 0x52};
static const unsigned char ARK_FOOTER_MAGIC[4] = {0x5C, 0xE1, 0x38, 0x90};

static void intToLe4Bytes(int value, unsigned char out[4]) {
    out[0] = static_cast<unsigned char>(value & 0xff);
    out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[3] = static_cast<unsigned char>((value >> 24) & 0xff);
}

struct ArkPayloadIndexEntry {
    int type;
    int index;
    int offset;
    int size;
    int flags;
};

static void appendIntLE(std::vector<unsigned char> &out, int value) {
    unsigned char buf[4];
    intToLe4Bytes(value, buf);
    out.insert(out.end(), buf, buf + 4);
}

static std::vector<unsigned char> buildPayloadIndexPlainBytes(
        const std::vector<ArkPayloadIndexEntry> &entries
) {
    std::vector<unsigned char> out;

    out.push_back(ARK_INDEX_MAGIC[0]);
    out.push_back(ARK_INDEX_MAGIC[1]);
    out.push_back(ARK_INDEX_MAGIC[2]);
    out.push_back(ARK_INDEX_MAGIC[3]);

    appendIntLE(out, 1);
    appendIntLE(out, static_cast<int>(entries.size()));

    for (size_t i = 0; i < entries.size(); i++) {
        appendIntLE(out, entries[i].type);
        appendIntLE(out, entries[i].index);
        appendIntLE(out, entries[i].offset);
        appendIntLE(out, entries[i].size);
        appendIntLE(out, entries[i].flags);
    }

    return out;
}

static void addPayloadIndexEntry(
        std::vector<ArkPayloadIndexEntry> &indexTable,
        int type,
        int index,
        int offset,
        int size,
        int flags
) {
    ArkPayloadIndexEntry entry;
    entry.type = type;
    entry.index = index;
    entry.offset = offset;
    entry.size = size;
    entry.flags = flags;
    indexTable.push_back(entry);
}

static bool hideArkFeaturesEnabled() {
    const char *envVal = getenv("ARK_HIDE_FEATURES");
    if (envVal == nullptr) return false;
    return strcmp(envVal, "1") == 0 || strcmp(envVal, "true") == 0;
}

static void maskArray(unsigned char *arr, int len) {
    if (!hideArkFeaturesEnabled()) return;
    unsigned char xorKey = static_cast<unsigned char>(time(nullptr) & 0xFF);
    for (int i = 0; i < len; i++) {
        arr[i] ^= xorKey;
        arr[i] = static_cast<unsigned char>((arr[i] << 3) | (arr[i] >> 5));
        arr[i] ^= static_cast<unsigned char>(i * 0x3D + 0x17);
    }
}

static void unmaskArray(unsigned char *arr, int len) {
    if (!hideArkFeaturesEnabled()) return;
    unsigned char xorKey = static_cast<unsigned char>(time(nullptr) & 0xFF);
    for (int i = len - 1; i >= 0; i--) {
        arr[i] ^= static_cast<unsigned char>(i * 0x3D + 0x17);
        arr[i] = static_cast<unsigned char>((arr[i] >> 3) | (arr[i] << 5));
        arr[i] ^= xorKey;
    }
}

static void deriveSecondLayerKey(
        const unsigned char signKey[64],
        unsigned char outKey[AES_KEY_SIZE]
) {
    unsigned char md5Buf[16];
    unsigned int a0 = 0x67452301;
    unsigned int b0 = 0xEFCDAB89;
    unsigned int c0 = 0x98BADCFE;
    unsigned int d0 = 0x10325476;

    for (int round = 0; round < 4; round++) {
        int offset = round * 16;
        unsigned int a = a0;
        unsigned int b = b0;
        unsigned int c = c0;
        unsigned int d = d0;

        auto F = [](unsigned int x, unsigned int y, unsigned int z) -> unsigned int {
            return (x & y) | ((~x) & z);
        };

        auto FF = [&](unsigned int &a, unsigned int b, unsigned int c, unsigned int d,
                     unsigned int x, unsigned int s, unsigned int ac) {
            a += F(b, c, d) + x + ac;
            a = (a << s) | (a >> (32 - s));
            a += b;
        };

        unsigned int x[16];
        for (int i = 0; i < 16; i++) {
            x[i] = signKey[offset + i] | (static_cast<unsigned int>(signKey[offset + (i + 1) % 16]) << 8)
                   | (static_cast<unsigned int>(signKey[offset + (i + 3) % 16]) << 16)
                   | (static_cast<unsigned int>(signKey[offset + (i + 7) % 16]) << 24);
        }

        FF(a, b, c, d, x[0], 7, 0xD76AA478);
        FF(d, a, b, c, x[1], 12, 0xE8C7B756);
        FF(c, d, a, b, x[2], 17, 0x242070DB);
        FF(b, c, d, a, x[3], 22, 0xC1BDCEEE);

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    unsigned int h[4] = {a0, b0, c0, d0};
    for (int i = 0; i < 4; i++) {
        outKey[i * 4] = static_cast<unsigned char>(h[i] & 0xff);
        outKey[i * 4 + 1] = static_cast<unsigned char>((h[i] >> 8) & 0xff);
        outKey[i * 4 + 2] = static_cast<unsigned char>((h[i] >> 16) & 0xff);
        outKey[i * 4 + 3] = static_cast<unsigned char>((h[i] >> 24) & 0xff);
    }
}

static void encryptBlockSecondLayer(
        const unsigned char *data,
        int dataLen,
        const unsigned char signKey[64],
        std::vector<unsigned char> &out
) {
    out.clear();

    unsigned char aesKey[AES_KEY_SIZE];
    deriveSecondLayerKey(signKey, aesKey);

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, signKey, AES_BLOCK_SIZE);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] ^= aesKey[i];
        iv[i] = static_cast<unsigned char>((iv[i] << 5) | (iv[i] >> 3));
        iv[i] ^= static_cast<unsigned char>(i * 0x7B + 0x2F);
    }

    unsigned char keySchedule[11][AES_BLOCK_SIZE];
    memcpy(keySchedule[0], aesKey, AES_BLOCK_SIZE);

    for (int round = 0; round < 10; round++) {
        keySchedule[round + 1][0] = keySchedule[round][0] ^ keySchedule[round][13]
                                    ^ static_cast<unsigned char>((keySchedule[round][7] << 2) | (keySchedule[round][7] >> 6))
                                    ^ static_cast<unsigned char>(round * 0x1B + 0x01);
        for (int j = 1; j < AES_BLOCK_SIZE; j++) {
            keySchedule[round + 1][j] = keySchedule[round][j]
                                        ^ static_cast<unsigned char>((keySchedule[round][(j + 11) % AES_BLOCK_SIZE] << 3)
                                                                     | (keySchedule[round][(j + 11) % AES_BLOCK_SIZE] >> 5))
                                        ^ static_cast<unsigned char>((round + j) * 0x36 + 0x5B);
        }
    }

    int paddedLen = ((dataLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    std::vector<unsigned char> padded(paddedLen);
    memcpy(padded.data(), data, dataLen);

    unsigned char paddingVal = static_cast<unsigned char>(AES_BLOCK_SIZE - (dataLen % AES_BLOCK_SIZE));
    if (paddingVal == 0) paddingVal = AES_BLOCK_SIZE;
    for (int i = dataLen; i < paddedLen; i++) {
        padded[i] = paddingVal;
    }

    std::vector<unsigned char> currentIv(iv, iv + AES_BLOCK_SIZE);
    out.resize(paddedLen);

    for (int blockIdx = 0; blockIdx < paddedLen; blockIdx += AES_BLOCK_SIZE) {
        unsigned char block[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            block[i] = padded[blockIdx + i] ^ currentIv[i];
        }

        unsigned char state[AES_BLOCK_SIZE];
        memcpy(state, block, AES_BLOCK_SIZE);

        for (int round = 1; round <= 10; round++) {
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] ^= keySchedule[round][i];
            }

            unsigned char tmp[AES_BLOCK_SIZE];
            memcpy(tmp, state, AES_BLOCK_SIZE);
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] = tmp[(i * 5 + 3) % AES_BLOCK_SIZE];
                state[i] = static_cast<unsigned char>((state[i] << 4) | (state[i] >> 4));
                state[i] ^= static_cast<unsigned char>((i * 0xAD + round * 0x11) & 0xFF);
            }
        }

        memcpy(out.data() + blockIdx, state, AES_BLOCK_SIZE);
        memcpy(currentIv.data(), state, AES_BLOCK_SIZE);
    }
}

static void decryptBlockSecondLayer(
        const unsigned char *data,
        int dataLen,
        const unsigned char signKey[64],
        std::vector<unsigned char> &out
) {
    out.clear();

    if (dataLen % AES_BLOCK_SIZE != 0 || dataLen == 0) {
        return;
    }

    unsigned char aesKey[AES_KEY_SIZE];
    deriveSecondLayerKey(signKey, aesKey);

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, signKey, AES_BLOCK_SIZE);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] ^= aesKey[i];
        iv[i] = static_cast<unsigned char>((iv[i] << 5) | (iv[i] >> 3));
        iv[i] ^= static_cast<unsigned char>(i * 0x7B + 0x2F);
    }

    unsigned char keySchedule[11][AES_BLOCK_SIZE];
    memcpy(keySchedule[0], aesKey, AES_BLOCK_SIZE);

    for (int round = 0; round < 10; round++) {
        keySchedule[round + 1][0] = keySchedule[round][0] ^ keySchedule[round][13]
                                    ^ static_cast<unsigned char>((keySchedule[round][7] << 2) | (keySchedule[round][7] >> 6))
                                    ^ static_cast<unsigned char>(round * 0x1B + 0x01);
        for (int j = 1; j < AES_BLOCK_SIZE; j++) {
            keySchedule[round + 1][j] = keySchedule[round][j]
                                        ^ static_cast<unsigned char>((keySchedule[round][(j + 11) % AES_BLOCK_SIZE] << 3)
                                                                     | (keySchedule[round][(j + 11) % AES_BLOCK_SIZE] >> 5))
                                        ^ static_cast<unsigned char>((round + j) * 0x36 + 0x5B);
        }
    }

    std::vector<unsigned char> currentIv(iv, iv + AES_BLOCK_SIZE);
    std::vector<unsigned char> decrypted(dataLen);

    for (int blockIdx = 0; blockIdx < dataLen; blockIdx += AES_BLOCK_SIZE) {
        unsigned char state[AES_BLOCK_SIZE];
        memcpy(state, data + blockIdx, AES_BLOCK_SIZE);

        for (int round = 10; round >= 1; round--) {
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] ^= static_cast<unsigned char>((i * 0xAD + round * 0x11) & 0xFF);
                state[i] = static_cast<unsigned char>((state[i] >> 4) | (state[i] << 4));
            }

            unsigned char tmp[AES_BLOCK_SIZE];
            memcpy(tmp, state, AES_BLOCK_SIZE);
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                int srcIdx = (i * 5 + 3) % AES_BLOCK_SIZE;
                int dstIdx;
                for (dstIdx = 0; dstIdx < AES_BLOCK_SIZE; dstIdx++) {
                    if ((dstIdx * 5 + 3) % AES_BLOCK_SIZE == srcIdx) break;
                }
                state[dstIdx] = tmp[i];
            }

            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] ^= keySchedule[round][i];
            }
        }

        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            decrypted[blockIdx + i] = state[i] ^ currentIv[i];
        }

        memcpy(currentIv.data(), data + blockIdx, AES_BLOCK_SIZE);
    }

    unsigned char paddingVal = decrypted[dataLen - 1];
    int unpaddedLen = dataLen - paddingVal;
    if (paddingVal > 0 && paddingVal <= AES_BLOCK_SIZE) {
        bool validPadding = true;
        for (int i = dataLen - paddingVal; i < dataLen; i++) {
            if (decrypted[i] != paddingVal) {
                validPadding = false;
                break;
            }
        }
        if (validPadding) {
            out.assign(decrypted.begin(), decrypted.begin() + unpaddedLen);
            return;
        }
    }

    out = decrypted;
}

static void encryptBlockThirdLayer(
        const unsigned char *data,
        int dataLen,
        std::vector<unsigned char> &out
) {
    out.clear();

    unsigned char seed[4];
    fillRandomBytes(seed, 4);
    unsigned int pseudoSeed = (static_cast<unsigned int>(seed[0]))
                              | (static_cast<unsigned int>(seed[1]) << 8)
                              | (static_cast<unsigned int>(seed[2]) << 16)
                              | (static_cast<unsigned int>(seed[3]) << 24);

    int prefixLen = 1 + (pseudoSeed % 16);
    int suffixLen = 1 + ((pseudoSeed >> 4) % 16);

    std::vector<unsigned char> prefix;
    prefix.resize(prefixLen);
    fillRandomBytes(prefix.data(), prefixLen);

    std::vector<unsigned char> suffix;
    suffix.resize(suffixLen);
    fillRandomBytes(suffix.data(), suffixLen);

    std::vector<unsigned char> inverted(dataLen);
    for (int i = 0; i < dataLen; i++) {
        inverted[i] = static_cast<unsigned char>(~data[i]);
    }

    unsigned int lcgState = pseudoSeed;
    for (int i = 0; i < dataLen; i++) {
        lcgState = lcgState * 1103515245U + 12345U;
        unsigned char keyByte = static_cast<unsigned char>((lcgState >> 16) & 0xFF);
        inverted[i] ^= keyByte;
    }

    out.reserve(4 + prefixLen + dataLen + suffixLen);
    out.resize(4);
    out[0] = static_cast<unsigned char>(prefixLen);
    out[1] = static_cast<unsigned char>(suffixLen);
    out[2] = seed[0];
    out[3] = seed[1];
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), inverted.begin(), inverted.end());
    out.insert(out.end(), suffix.begin(), suffix.end());
}

static void decryptBlockThirdLayer(
        const unsigned char *data,
        int dataLen,
        std::vector<unsigned char> &out
) {
    out.clear();

    if (dataLen < 4) {
        return;
    }

    int prefixLen = static_cast<int>(data[0]);
    int suffixLen = static_cast<int>(data[1]);

    if (dataLen < 4 + prefixLen + suffixLen) {
        return;
    }

    int contentLen = dataLen - 4 - prefixLen - suffixLen;
    if (contentLen <= 0) {
        return;
    }

    unsigned int pseudoSeed = (static_cast<unsigned int>(data[2]))
                              | (static_cast<unsigned int>(data[3]) << 8)
                              | (static_cast<unsigned int>(prefixLen & 0xF) << 16)
                              | (static_cast<unsigned int>(suffixLen & 0xF) << 24);

    out.resize(contentLen);
    memcpy(out.data(), data + 4 + prefixLen, contentLen);

    unsigned int lcgState = pseudoSeed;
    for (int i = 0; i < contentLen; i++) {
        lcgState = lcgState * 1103515245U + 12345U;
        unsigned char keyByte = static_cast<unsigned char>((lcgState >> 16) & 0xFF);
        out[i] ^= keyByte;
    }

    for (int i = 0; i < contentLen; i++) {
        out[i] = static_cast<unsigned char>(~out[i]);
    }
}

static const DisguiseMagic *getDisguiseConfig() {
    const char *envVal = getenv("ARK_DISGUISE_TYPE");
    if (envVal == nullptr) return nullptr;
    if (strlen(envVal) == 0) return nullptr;

    for (int i = 0; i < DISGUISE_COUNT; i++) {
        if (strcmp(envVal, DISGUISE_TABLE[i].name) == 0) {
            return &DISGUISE_TABLE[i];
        }
    }
    return nullptr;
}

static void disguiseAsEnterpriseGuard(
        std::vector<unsigned char> &block,
        int type
) {
    const DisguiseMagic *cfg = getDisguiseConfig();
    if (cfg == nullptr) return;

    std::vector<unsigned char> disguised;
    disguised.reserve(block.size() + cfg->magicLen + 8);

    disguised.insert(disguised.end(), cfg->magic, cfg->magic + cfg->magicLen);

    unsigned char typeBytes[4];
    intToLe4Bytes(type, typeBytes);
    disguised.insert(disguised.end(), typeBytes, typeBytes + 4);

    unsigned char lenBytes[4];
    intToLe4Bytes(static_cast<int>(block.size()), lenBytes);
    disguised.insert(disguised.end(), lenBytes, lenBytes + 4);

    disguised.insert(disguised.end(), block.begin(), block.end());

    block = disguised;
}

static bool readOptionalByteArray(
        JNIEnv *env,
        jbyteArray array,
        std::vector<unsigned char> &out
) {
    out.clear();

    if (array == nullptr) {
        return true;
    }

    jsize len = env->GetArrayLength(array);
    if (len != 64) {
        return false;
    }

    out.resize(64);

    env->GetByteArrayRegion(
            array,
            0,
            64,
            reinterpret_cast<jbyte *>(out.data())
    );

    return !env->ExceptionCheck();
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

static jbyteArray makeByteArray(JNIEnv *env, const unsigned char *data, int len) {
    if (data == nullptr || len < 0) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(len);
    if (out == nullptr) {
        return nullptr;
    }

    if (len > 0) {
        env->SetByteArrayRegion(
                out,
                0,
                len,
                reinterpret_cast<const jbyte *>(data)
        );
    }

    return out;
}

static bool readByteArray(JNIEnv *env, jbyteArray array, std::vector<unsigned char> &out) {
    if (array == nullptr) {
        return false;
    }

    jsize len = env->GetArrayLength(array);
    if (len <= 0) {
        return false;
    }

    out.resize(len);

    env->GetByteArrayRegion(
            array,
            0,
            len,
            reinterpret_cast<jbyte *>(out.data())
    );

    return !env->ExceptionCheck();
}


static void xorBytes(
        const unsigned char *data,
        int dataLen,
        const unsigned char *key,
        int keyLen,
        std::vector<unsigned char> &out
) {
    out.resize(dataLen);

    for (int i = 0; i < dataLen; i++) {
        out[i] = data[i] ^ key[i % keyLen];
    }
}

static bool fillRandomBytes(unsigned char *buffer, int len) {
    if (buffer == nullptr || len <= 0) {
        return false;
    }

#if defined(SYS_getrandom)
    ssize_t n = getrandom(buffer, len, 0);
    if (n == len) {
        return true;
    }
#endif

    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp != nullptr) {
        size_t n = fread(buffer, 1, len, fp);
        fclose(fp);

        if (n == static_cast<size_t>(len)) {
            return true;
        }
    }

    srand(static_cast<unsigned int>(time(nullptr) ^ getpid()));

    for (int i = 0; i < len; i++) {
        buffer[i] = static_cast<unsigned char>(rand() & 0xff);
    }

    return true;
}

static uint32_t leftRotate(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

static void sha1Bytes(const unsigned char *data, size_t len, unsigned char out[20]) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    uint64_t bitLen = static_cast<uint64_t>(len) * 8;

    size_t newLen = len + 1;
    while ((newLen % 64) != 56) {
        newLen++;
    }

    std::vector<unsigned char> msg(newLen + 8);
    memcpy(msg.data(), data, len);
    msg[len] = 0x80;

    for (int i = 0; i < 8; i++) {
        msg[newLen + i] = static_cast<unsigned char>((bitLen >> ((7 - i) * 8)) & 0xff);
    }

    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t w[80];

        for (int i = 0; i < 16; i++) {
            size_t j = offset + i * 4;
            w[i] = (static_cast<uint32_t>(msg[j]) << 24)
                   | (static_cast<uint32_t>(msg[j + 1]) << 16)
                   | (static_cast<uint32_t>(msg[j + 2]) << 8)
                   | static_cast<uint32_t>(msg[j + 3]);
        }

        for (int i = 16; i < 80; i++) {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int i = 0; i < 80; i++) {
            uint32_t f;
            uint32_t k;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    uint32_t h[5] = {h0, h1, h2, h3, h4};

    for (int i = 0; i < 5; i++) {
        out[i * 4] = static_cast<unsigned char>((h[i] >> 24) & 0xff);
        out[i * 4 + 1] = static_cast<unsigned char>((h[i] >> 16) & 0xff);
        out[i * 4 + 2] = static_cast<unsigned char>((h[i] >> 8) & 0xff);
        out[i * 4 + 3] = static_cast<unsigned char>(h[i] & 0xff);
    }
}

static uint32_t adler32Bytes(const unsigned char *data, size_t len) {
    const uint32_t MOD_ADLER = 65521;

    uint32_t a = 1;
    uint32_t b = 0;

    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}
static void shuffleIndexTable(std::vector<ArkPayloadIndexEntry> &items) {
    if (items.size() <= 1) {
        return;
    }

    unsigned char seedBytes[4];
    fillRandomBytes(seedBytes, 4);

    uint32_t seed =
            ((uint32_t) seedBytes[0])
            | ((uint32_t) seedBytes[1] << 8)
            | ((uint32_t) seedBytes[2] << 16)
            | ((uint32_t) seedBytes[3] << 24);

    srand(seed);

    for (int i = static_cast<int>(items.size()) - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        std::swap(items[i], items[j]);
    }
}
static jbyteArray native_buildEncryptedBlock(JNIEnv *env, jobject thiz, jbyteArray plainData) {
    std::vector<unsigned char> plain;

    if (!readByteArray(env, plainData, plain)) {
        return nullptr;
    }

    unsigned char key[64];
    if (!fillRandomBytes(key, sizeof(key))) {
        return nullptr;
    }

    std::vector<unsigned char> encryptedData;
    xorBytes(
            plain.data(),
            static_cast<int>(plain.size()),
            key,
            sizeof(key),
            encryptedData
    );

    unsigned char lenBytes[4];
    intToLe4Bytes(static_cast<int>(plain.size()), lenBytes);

    std::vector<unsigned char> encryptedLen;
    xorBytes(
            lenBytes,
            4,
            key,
            sizeof(key),
            encryptedLen
    );

    std::vector<unsigned char> result;
    result.reserve(encryptedData.size() + encryptedLen.size() + sizeof(key));

    result.insert(result.end(), encryptedData.begin(), encryptedData.end());
    result.insert(result.end(), encryptedLen.begin(), encryptedLen.end());
    result.insert(result.end(), key, key + sizeof(key));

    return makeByteArray(env, result.data(), static_cast<int>(result.size()));
}

static jbyteArray native_fixDexHeader(JNIEnv *env, jobject thiz, jbyteArray dexData) {
    std::vector<unsigned char> dex;

    if (!readByteArray(env, dexData, dex)) {
        return nullptr;
    }

    if (dex.size() < 0x70) {
        return nullptr;
    }

    int fileSize = static_cast<int>(dex.size());

    unsigned char fileSizeBytes[4];
    intToLe4Bytes(fileSize, fileSizeBytes);
    memcpy(dex.data() + 32, fileSizeBytes, 4);

    unsigned char signature[20];
    sha1Bytes(dex.data() + 32, dex.size() - 32, signature);
    memcpy(dex.data() + 12, signature, 20);

    uint32_t checksum = adler32Bytes(dex.data() + 12, dex.size() - 12);

    unsigned char checksumBytes[4];
    intToLe4Bytes(static_cast<int>(checksum), checksumBytes);
    memcpy(dex.data() + 8, checksumBytes, 4);

    return makeByteArray(env, dex.data(), static_cast<int>(dex.size()));
}

static jboolean native_isValidDex(JNIEnv *env, jobject thiz, jbyteArray data) {
    if (data == nullptr) {
        return JNI_FALSE;
    }

    jsize len = env->GetArrayLength(data);
    if (len < 0x70) {
        return JNI_FALSE;
    }

    unsigned char magic[4];

    env->GetByteArrayRegion(
            data,
            0,
            4,
            reinterpret_cast<jbyte *>(magic)
    );

    if (env->ExceptionCheck()) {
        return JNI_FALSE;
    }

    if (magic[0] == 'd'
        && magic[1] == 'e'
        && magic[2] == 'x'
        && magic[3] == '\n') {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

static jbyteArray native_intToLe4(JNIEnv *env, jobject thiz, jint value) {
    unsigned char out[4];
    intToLe4Bytes(value, out);
    return makeByteArray(env, out, 4);
}

static void throwRuntimeException(JNIEnv *env, const char *msg) {
    jclass cls = env->FindClass("java/lang/RuntimeException");
    if (cls != nullptr) {
        env->ThrowNew(cls, msg);
    }
}

static jstring getFileAbsolutePath(JNIEnv *env, jobject fileObj) {
    jclass clsFile = env->FindClass("java/io/File");
    jmethodID midGetAbsolutePath = env->GetMethodID(
            clsFile,
            "getAbsolutePath",
            "()Ljava/lang/String;"
    );

    return (jstring) env->CallObjectMethod(fileObj, midGetAbsolutePath);
}

static std::vector<unsigned char> readAllBytesFromInputStream(JNIEnv *env, jobject inputStream) {
    std::vector<unsigned char> result;

    jclass clsInputStream = env->FindClass("java/io/InputStream");
    jmethodID midRead = env->GetMethodID(clsInputStream, "read", "([B)I");
    jmethodID midClose = env->GetMethodID(clsInputStream, "close", "()V");

    jbyteArray buffer = env->NewByteArray(8192);

    while (true) {
        jint len = env->CallIntMethod(inputStream, midRead, buffer);
        if (env->ExceptionCheck()) {
            result.clear();
            return result;
        }

        if (len <= 0) {
            break;
        }

        size_t oldSize = result.size();
        result.resize(oldSize + len);

        env->GetByteArrayRegion(
                buffer,
                0,
                len,
                reinterpret_cast<jbyte *>(result.data() + oldSize)
        );

        if (env->ExceptionCheck()) {
            result.clear();
            return result;
        }
    }

    env->CallVoidMethod(inputStream, midClose);
    return result;
}

static std::vector<unsigned char> readAllBytesFromFile(JNIEnv *env, jobject fileObj) {
    std::vector<unsigned char> result;

    jclass clsFileInputStream = env->FindClass("java/io/FileInputStream");
    jmethodID midInit = env->GetMethodID(
            clsFileInputStream,
            "<init>",
            "(Ljava/io/File;)V"
    );

    jobject fis = env->NewObject(clsFileInputStream, midInit, fileObj);
    if (env->ExceptionCheck() || fis == nullptr) {
        result.clear();
        return result;
    }

    return readAllBytesFromInputStream(env, fis);
}

static bool writeAllBytesToFile(JNIEnv *env, jobject fileObj, const std::vector<unsigned char> &data) {
    jclass clsFileOutputStream = env->FindClass("java/io/FileOutputStream");
    jmethodID midInit = env->GetMethodID(
            clsFileOutputStream,
            "<init>",
            "(Ljava/io/File;)V"
    );

    jobject fos = env->NewObject(clsFileOutputStream, midInit, fileObj);
    if (env->ExceptionCheck() || fos == nullptr) {
        return false;
    }

    jmethodID midWrite = env->GetMethodID(clsFileOutputStream, "write", "([B)V");
    jmethodID midFlush = env->GetMethodID(clsFileOutputStream, "flush", "()V");
    jmethodID midClose = env->GetMethodID(clsFileOutputStream, "close", "()V");

    jbyteArray arr = makeByteArray(
            env,
            data.data(),
            static_cast<int>(data.size())
    );

    env->CallVoidMethod(fos, midWrite, arr);
    if (env->ExceptionCheck()) {
        return false;
    }

    env->CallVoidMethod(fos, midFlush);
    env->CallVoidMethod(fos, midClose);

    return !env->ExceptionCheck();
}

static void appendLogOnUiNative(JNIEnv *env, jobject thiz, const char *msg) {
    jclass cls = env->GetObjectClass(thiz);
    jmethodID mid = env->GetMethodID(
            cls,
            "appendLogOnUi",
            "(Ljava/lang/String;)V"
    );

    if (mid == nullptr) {
        env->ExceptionClear();
        return;
    }

    jstring text = env->NewStringUTF(msg);
    env->CallVoidMethod(thiz, mid, text);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static bool isValidDexBytes(const std::vector<unsigned char> &data) {
    return data.size() >= 0x70
           && data[0] == 'd'
           && data[1] == 'e'
           && data[2] == 'x'
           && data[3] == '\n';
}

static std::vector<unsigned char> buildEncryptedBlockBytes(
        int type,
        int index,
        const unsigned char *data,
        int len,
        const unsigned char *externalKey,
        int externalKeyLen,
        int *outFlags
) {
    std::vector<unsigned char> result;

    if (data == nullptr || len <= 0) {
        return result;
    }

    bool useExternalKey = externalKey != nullptr && externalKeyLen == 64;

    unsigned char randomKey[64];
    const unsigned char *key = nullptr;
    int keyLen = 64;
    int flags = 0;

    if (useExternalKey) {
        key = externalKey;
        flags = ARK_BLOCK_FLAG_SIGN_KEY;
    } else {
        if (!fillRandomBytes(randomKey, sizeof(randomKey))) {
            return result;
        }
        key = randomKey;
        flags = ARK_BLOCK_FLAG_RANDOM_KEY;
    }

    flags |= ARK_BLOCK_FLAG_MULTI_LAYER;

    std::vector<unsigned char> currentData;
    currentData.assign(data, data + len);

    std::vector<unsigned char> afterThird;
    encryptBlockThirdLayer(currentData.data(), static_cast<int>(currentData.size()), afterThird);
    currentData = afterThird;

    if (useExternalKey) {
        std::vector<unsigned char> afterSecond;
        encryptBlockSecondLayer(
                currentData.data(),
                static_cast<int>(currentData.size()),
                externalKey,
                afterSecond
        );
        currentData = afterSecond;
    }

    std::vector<unsigned char> encryptedData;
    xorBytes(
            currentData.data(),
            static_cast<int>(currentData.size()),
            key,
            keyLen,
            encryptedData
    );

    int plainLen = len;
    int cipherLen = static_cast<int>(encryptedData.size());

    int savedKeyLen = useExternalKey ? 0 : 64;

    result.reserve(
            4 + 4 + 4 + 4 + 4 + 4 + 4
            + cipherLen
            + savedKeyLen
    );

    result.push_back(ARK_BLOCK_MAGIC[0]);
    result.push_back(ARK_BLOCK_MAGIC[1]);
    result.push_back(ARK_BLOCK_MAGIC[2]);
    result.push_back(ARK_BLOCK_MAGIC[3]);

    appendIntLE(result, type);
    appendIntLE(result, index);
    appendIntLE(result, flags);
    appendIntLE(result, plainLen);
    appendIntLE(result, cipherLen);
    appendIntLE(result, savedKeyLen);

    result.insert(result.end(), encryptedData.begin(), encryptedData.end());

    if (!useExternalKey) {
        result.insert(result.end(), randomKey, randomKey + sizeof(randomKey));
    }

    if (getDisguiseConfig() != nullptr) {
        disguiseAsEnterpriseGuard(result, type);
    }

    if (outFlags != nullptr) {
        *outFlags = flags;
    }

    return result;
}
static std::vector<unsigned char> buildPayloadFooterBytes(
        int payloadOff,
        int payloadLen,
        int indexOff,
        int indexLen
) {
    std::vector<unsigned char> out;

    out.push_back(ARK_FOOTER_MAGIC[0]);
    out.push_back(ARK_FOOTER_MAGIC[1]);
    out.push_back(ARK_FOOTER_MAGIC[2]);
    out.push_back(ARK_FOOTER_MAGIC[3]);

    appendIntLE(out, 1);
    appendIntLE(out, 0);
    appendIntLE(out, payloadOff);
    appendIntLE(out, payloadLen);
    appendIntLE(out, indexOff);
    appendIntLE(out, indexLen);
    appendIntLE(out, 0);
    appendIntLE(out, 0);

    return out;
}

static std::vector<unsigned char> fixDexHeaderBytes(std::vector<unsigned char> dex) {
    if (dex.size() < 0x70) {
        dex.clear();
        return dex;
    }

    unsigned char fileSizeBytes[4];
    intToLe4Bytes(static_cast<int>(dex.size()), fileSizeBytes);
    memcpy(dex.data() + 32, fileSizeBytes, 4);

    unsigned char signature[20];
    sha1Bytes(dex.data() + 32, dex.size() - 32, signature);
    memcpy(dex.data() + 12, signature, 20);

    uint32_t checksum = adler32Bytes(dex.data() + 12, dex.size() - 12);

    unsigned char checksumBytes[4];
    intToLe4Bytes(static_cast<int>(checksum), checksumBytes);
    memcpy(dex.data() + 8, checksumBytes, 4);

    return dex;
}

static void native_buildEncryptedShellDex(
        JNIEnv *env,
        jobject thiz,
        jobject dexDir,
        jobject shellDexFile,
        jstring realApplicationName,
        jstring realappComponentFactory,
        jbyteArray signHash64
) {
    if (dexDir == nullptr || shellDexFile == nullptr || realApplicationName == nullptr) {
        throwRuntimeException(env, "参数为空");
        return;
    }

    std::vector<unsigned char> signKey;

    if (!readOptionalByteArray(env, signHash64, signKey)) {
        throwRuntimeException(env, "签名密钥必须为空或64字节");
        return;
    }

    unsigned char derivedSignKey[64];
    memset(derivedSignKey, 0, sizeof(derivedSignKey));

    const unsigned char *dexKey = nullptr;
    int dexKeyLen = 0;

    if (!signKey.empty()) {
        deriveDexKeyFromSignKey64(signKey.data(), derivedSignKey);

        dexKey = derivedSignKey;
        dexKeyLen = 64;

        memset(signKey.data(), 0, signKey.size());
    }

    std::vector<unsigned char> shellDex = readAllBytesFromFile(env, shellDexFile);
    if (env->ExceptionCheck()) {
        return;
    }

    if (!isValidDexBytes(shellDex)) {
        throwRuntimeException(env, "壳 dex 非法");
        return;
    }

    jstring dexDirPathJ = getFileAbsolutePath(env, dexDir);
    if (dexDirPathJ == nullptr) {
        throwRuntimeException(env, "获取 dex 目录失败");
        return;
    }

    const char *dexDirPath = env->GetStringUTFChars(dexDirPathJ, nullptr);
    if (dexDirPath == nullptr) {
        throwRuntimeException(env, "读取 dex 目录路径失败");
        return;
    }

    jclass clsFile = env->FindClass("java/io/File");
    if (clsFile == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "找不到 File 类");
        return;
    }

    jmethodID midFileInit = env->GetMethodID(
            clsFile,
            "<init>",
            "(Ljava/lang/String;Ljava/lang/String;)V"
    );

    if (midFileInit == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "获取 File 构造方法失败");
        return;
    }

    jmethodID midExists = env->GetMethodID(
            clsFile,
            "exists",
            "()Z"
    );

    if (midExists == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "获取 File.exists 失败");
        return;
    }

    std::vector<unsigned char> payload;
    std::vector<ArkPayloadIndexEntry> indexTable;

    int dexCount = 0;

    for (int i = 1; ; i++) {
        char dexName[64];

        if (i == 1) {
            snprintf(dexName, sizeof(dexName), "classes.dex");
        } else {
            snprintf(dexName, sizeof(dexName), "classes%d.dex", i);
        }

        jstring parentJ = env->NewStringUTF(dexDirPath);
        jstring nameJ = env->NewStringUTF(dexName);

        jobject dexFileObj = env->NewObject(
                clsFile,
                midFileInit,
                parentJ,
                nameJ
        );

        if (env->ExceptionCheck() || dexFileObj == nullptr) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        jboolean exists = env->CallBooleanMethod(dexFileObj, midExists);

        if (env->ExceptionCheck()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        if (!exists) {
            break;
        }

        std::vector<unsigned char> dexData = readAllBytesFromFile(env, dexFileObj);
        if (env->ExceptionCheck()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        if (!isValidDexBytes(dexData)) {
            char logText[160];
            snprintf(logText, sizeof(logText), "发现非法 dex，停止处理：%s", dexName);
            appendLogOnUiNative(env, thiz, logText);
            break;
        }

        int blockFlags = 0;

        std::vector<unsigned char> block = buildEncryptedBlockBytes(
                ARK_BLOCK_TYPE_DEX,
                i,
                dexData.data(),
                static_cast<int>(dexData.size()),
                dexKey,
                dexKeyLen,
                &blockFlags
        );

        if (block.empty()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            throwRuntimeException(env, "dex 加密失败");
            return;
        }

        int blockOffset = static_cast<int>(payload.size());
        int blockSize = static_cast<int>(block.size());

        payload.insert(payload.end(), block.begin(), block.end());

        addPayloadIndexEntry(
                indexTable,
                ARK_BLOCK_TYPE_DEX,
                i,
                blockOffset,
                blockSize,
                blockFlags
        );

        dexCount++;

        char logText[160];
        snprintf(logText, sizeof(logText), "已加密：%s", dexName);
        appendLogOnUiNative(env, thiz, logText);
    }

    env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);

    if (dexCount <= 0) {
        throwRuntimeException(env, "dex目录中没有找到合法 dex");
        return;
    }

    const char *appNameChars = env->GetStringUTFChars(realApplicationName, nullptr);
    if (appNameChars == nullptr) {
        throwRuntimeException(env, "获取入口类名失败");
        return;
    }

    int appNameLen = static_cast<int>(strlen(appNameChars));
    int appBlockFlags = 0;

    std::vector<unsigned char> appBlock = buildEncryptedBlockBytes(
            ARK_BLOCK_TYPE_APP,
            0,
            reinterpret_cast<const unsigned char *>(appNameChars),
            appNameLen,
            nullptr,
            0,
            &appBlockFlags
    );

    char appLog[256];
    snprintf(appLog, sizeof(appLog), "已加密入口：%s", appNameChars);
    appendLogOnUiNative(env, thiz, appLog);

    env->ReleaseStringUTFChars(realApplicationName, appNameChars);

    if (appBlock.empty()) {
        throwRuntimeException(env, "入口类名加密失败");
        return;
    }

    int appBlockOffset = static_cast<int>(payload.size());
    int appBlockSize = static_cast<int>(appBlock.size());

    payload.insert(payload.end(), appBlock.begin(), appBlock.end());

    addPayloadIndexEntry(
            indexTable,
            ARK_BLOCK_TYPE_APP,
            0,
            appBlockOffset,
            appBlockSize,
            appBlockFlags
    );

    if (realappComponentFactory != nullptr) {
        const char *factoryChars = env->GetStringUTFChars(realappComponentFactory, nullptr);

        if (factoryChars != nullptr && strlen(factoryChars) > 0) {
            int factoryLen = static_cast<int>(strlen(factoryChars));
            int factoryBlockFlags = 0;

            std::vector<unsigned char> factoryBlock = buildEncryptedBlockBytes(
                    ARK_BLOCK_TYPE_FACTORY,
                    0,
                    reinterpret_cast<const unsigned char *>(factoryChars),
                    factoryLen,
                    nullptr,
                    0,
                    &factoryBlockFlags
            );

            char factoryLog[256];
            snprintf(factoryLog, sizeof(factoryLog), "已加密原Factory：%s", factoryChars);
            appendLogOnUiNative(env, thiz, factoryLog);

            env->ReleaseStringUTFChars(realappComponentFactory, factoryChars);

            if (factoryBlock.empty()) {
                throwRuntimeException(env, "原Factory类名加密失败");
                return;
            }

            int factoryBlockOffset = static_cast<int>(payload.size());
            int factoryBlockSize = static_cast<int>(factoryBlock.size());

            payload.insert(payload.end(), factoryBlock.begin(), factoryBlock.end());

            addPayloadIndexEntry(
                    indexTable,
                    ARK_BLOCK_TYPE_FACTORY,
                    0,
                    factoryBlockOffset,
                    factoryBlockSize,
                    factoryBlockFlags
            );
        } else {
            if (factoryChars != nullptr) {
                env->ReleaseStringUTFChars(realappComponentFactory, factoryChars);
            }

            appendLogOnUiNative(env, thiz, "原Factory为空，跳过加密");
        }
    } else {
        appendLogOnUiNative(env, thiz, "原Factory为空，跳过加密");
    }
    shuffleIndexTable(indexTable);
    std::vector<unsigned char> indexPlain = buildPayloadIndexPlainBytes(indexTable);

    int indexBlockFlags = 0;
    std::vector<unsigned char> indexBlock = buildEncryptedBlockBytes(
            ARK_BLOCK_TYPE_INDEX,
            0,
            indexPlain.data(),
            static_cast<int>(indexPlain.size()),
            nullptr,
            0,
            &indexBlockFlags
    );

    if (indexBlock.empty()) {
        throwRuntimeException(env, "索引表加密失败");
        return;
    }

    int indexBlockOffset = static_cast<int>(payload.size());
    int indexBlockSize = static_cast<int>(indexBlock.size());

    payload.insert(payload.end(), indexBlock.begin(), indexBlock.end());

    int payloadOff = static_cast<int>(shellDex.size());
    int payloadLen = static_cast<int>(payload.size());

    std::vector<unsigned char> footer = buildPayloadFooterBytes(
            payloadOff,
            payloadLen,
            indexBlockOffset,
            indexBlockSize
    );

    std::vector<unsigned char> finalDex;
    finalDex.reserve(shellDex.size() + payload.size() + footer.size());

    finalDex.insert(finalDex.end(), shellDex.begin(), shellDex.end());
    finalDex.insert(finalDex.end(), payload.begin(), payload.end());
    finalDex.insert(finalDex.end(), footer.begin(), footer.end());

    std::vector<unsigned char> fixedDex = fixDexHeaderBytes(finalDex);
    if (fixedDex.empty()) {
        throwRuntimeException(env, "修复 dex 头失败");
        return;
    }

    if (!writeAllBytesToFile(env, shellDexFile, fixedDex)) {
        throwRuntimeException(env, "写入壳 dex 失败");
        return;
    }

    char doneLog[256];
    snprintf(
            doneLog,
            sizeof(doneLog),
            "已写入加密数据，dex数量：%d",
            dexCount
    );
    appendLogOnUiNative(env, thiz, doneLog);
}








static jint native_getRealDexOpcodeValue(
        JNIEnv *env,
        jclass clazz,
        jstring opcodeName_
) {
    if (opcodeName_ == nullptr) {
        return -1;
    }

    const char *opcodeName = env->GetStringUTFChars(opcodeName_, nullptr);
    if (opcodeName == nullptr) {
        return -1;
    }

    jint value = -1;

#define OP(name, code) \
    if (strcmp(opcodeName, name) == 0) { \
        value = code; \
        goto finish; \
    }
    OP("NOP", 0x00)
    OP("MOVE", 0x01)
    OP("MOVE_FROM16", 0x02)
    OP("MOVE_16", 0x03)
    OP("MOVE_WIDE", 0x04)
    OP("MOVE_WIDE_FROM16", 0x05)
    OP("MOVE_WIDE_16", 0x06)
    OP("MOVE_OBJECT", 0x07)
    OP("MOVE_OBJECT_FROM16", 0x08)
    OP("MOVE_OBJECT_16", 0x09)
    OP("MOVE_RESULT", 0x0a)
    OP("MOVE_RESULT_WIDE", 0x0b)
    OP("MOVE_RESULT_OBJECT", 0x0c)
    OP("MOVE_EXCEPTION", 0x0d)
    OP("RETURN_VOID", 0x0e)
    OP("RETURN", 0x0f)
    OP("RETURN_WIDE", 0x10)
    OP("RETURN_OBJECT", 0x11)
    OP("CONST_4", 0x12)
    OP("CONST_16", 0x13)
    OP("CONST", 0x14)
    OP("CONST_HIGH16", 0x15)
    OP("CONST_WIDE_16", 0x16)
    OP("CONST_WIDE_32", 0x17)
    OP("CONST_WIDE", 0x18)
    OP("CONST_WIDE_HIGH16", 0x19)
    OP("CONST_STRING", 0x1a)
    OP("CONST_STRING_JUMBO", 0x1b)
    OP("CONST_CLASS", 0x1c)
    OP("MONITOR_ENTER", 0x1d)
    OP("MONITOR_EXIT", 0x1e)
    OP("CHECK_CAST", 0x1f)
    OP("INSTANCE_OF", 0x20)
    OP("ARRAY_LENGTH", 0x21)
    OP("NEW_INSTANCE", 0x22)
    OP("NEW_ARRAY", 0x23)
    OP("FILLED_NEW_ARRAY", 0x24)
    OP("FILLED_NEW_ARRAY_RANGE", 0x25)
    OP("FILL_ARRAY_DATA", 0x26)
    OP("THROW", 0x27)
    OP("GOTO", 0x28)
    OP("GOTO_16", 0x29)
    OP("GOTO_32", 0x2a)
    OP("PACKED_SWITCH", 0x2b)
    OP("SPARSE_SWITCH", 0x2c)
    OP("CMPL_FLOAT", 0x2d)
    OP("CMPG_FLOAT", 0x2e)
    OP("CMPL_DOUBLE", 0x2f)
    OP("CMPG_DOUBLE", 0x30)
    OP("CMP_LONG", 0x31)
    OP("IF_EQ", 0x32)
    OP("IF_NE", 0x33)
    OP("IF_LT", 0x34)
    OP("IF_GE", 0x35)
    OP("IF_GT", 0x36)
    OP("IF_LE", 0x37)
    OP("IF_EQZ", 0x38)
    OP("IF_NEZ", 0x39)
    OP("IF_LTZ", 0x3a)
    OP("IF_GEZ", 0x3b)
    OP("IF_GTZ", 0x3c)
    OP("IF_LEZ", 0x3d)

    OP("AGET", 0x44)
    OP("AGET_WIDE", 0x45)
    OP("AGET_OBJECT", 0x46)
    OP("AGET_BOOLEAN", 0x47)
    OP("AGET_BYTE", 0x48)
    OP("AGET_CHAR", 0x49)
    OP("AGET_SHORT", 0x4a)
    OP("APUT", 0x4b)
    OP("APUT_WIDE", 0x4c)
    OP("APUT_OBJECT", 0x4d)
    OP("APUT_BOOLEAN", 0x4e)
    OP("APUT_BYTE", 0x4f)
    OP("APUT_CHAR", 0x50)
    OP("APUT_SHORT", 0x51)
    OP("IGET", 0x52)
    OP("IGET_WIDE", 0x53)
    OP("IGET_OBJECT", 0x54)
    OP("IGET_BOOLEAN", 0x55)
    OP("IGET_BYTE", 0x56)
    OP("IGET_CHAR", 0x57)
    OP("IGET_SHORT", 0x58)
    OP("IPUT", 0x59)
    OP("IPUT_WIDE", 0x5a)
    OP("IPUT_OBJECT", 0x5b)
    OP("IPUT_BOOLEAN", 0x5c)
    OP("IPUT_BYTE", 0x5d)
    OP("IPUT_CHAR", 0x5e)
    OP("IPUT_SHORT", 0x5f)
    OP("SGET", 0x60)
    OP("SGET_WIDE", 0x61)
    OP("SGET_OBJECT", 0x62)
    OP("SGET_BOOLEAN", 0x63)
    OP("SGET_BYTE", 0x64)
    OP("SGET_CHAR", 0x65)
    OP("SGET_SHORT", 0x66)
    OP("SPUT", 0x67)
    OP("SPUT_WIDE", 0x68)
    OP("SPUT_OBJECT", 0x69)
    OP("SPUT_BOOLEAN", 0x6a)
    OP("SPUT_BYTE", 0x6b)
    OP("SPUT_CHAR", 0x6c)
    OP("SPUT_SHORT", 0x6d)

    OP("INVOKE_VIRTUAL", 0x6e)
    OP("INVOKE_SUPER", 0x6f)
    OP("INVOKE_DIRECT", 0x70)
    OP("INVOKE_STATIC", 0x71)
    OP("INVOKE_INTERFACE", 0x72)
    OP("INVOKE_VIRTUAL_RANGE", 0x74)
    OP("INVOKE_SUPER_RANGE", 0x75)
    OP("INVOKE_DIRECT_RANGE", 0x76)
    OP("INVOKE_STATIC_RANGE", 0x77)
    OP("INVOKE_INTERFACE_RANGE", 0x78)

    OP("NEG_INT", 0x7b)
    OP("NOT_INT", 0x7c)
    OP("NEG_LONG", 0x7d)
    OP("NOT_LONG", 0x7e)
    OP("NEG_FLOAT", 0x7f)
    OP("NEG_DOUBLE", 0x80)
    OP("INT_TO_LONG", 0x81)
    OP("INT_TO_FLOAT", 0x82)
    OP("INT_TO_DOUBLE", 0x83)
    OP("LONG_TO_INT", 0x84)
    OP("LONG_TO_FLOAT", 0x85)
    OP("LONG_TO_DOUBLE", 0x86)
    OP("FLOAT_TO_INT", 0x87)
    OP("FLOAT_TO_LONG", 0x88)
    OP("FLOAT_TO_DOUBLE", 0x89)
    OP("DOUBLE_TO_INT", 0x8a)
    OP("DOUBLE_TO_LONG", 0x8b)
    OP("DOUBLE_TO_FLOAT", 0x8c)
    OP("INT_TO_BYTE", 0x8d)
    OP("INT_TO_CHAR", 0x8e)
    OP("INT_TO_SHORT", 0x8f)

    OP("ADD_INT", 0x90)
    OP("SUB_INT", 0x91)
    OP("MUL_INT", 0x92)
    OP("DIV_INT", 0x93)
    OP("REM_INT", 0x94)
    OP("AND_INT", 0x95)
    OP("OR_INT", 0x96)
    OP("XOR_INT", 0x97)
    OP("SHL_INT", 0x98)
    OP("SHR_INT", 0x99)
    OP("USHR_INT", 0x9a)

    OP("ADD_LONG", 0x9b)
    OP("SUB_LONG", 0x9c)
    OP("MUL_LONG", 0x9d)
    OP("DIV_LONG", 0x9e)
    OP("REM_LONG", 0x9f)
    OP("AND_LONG", 0xa0)
    OP("OR_LONG", 0xa1)
    OP("XOR_LONG", 0xa2)
    OP("SHL_LONG", 0xa3)
    OP("SHR_LONG", 0xa4)
    OP("USHR_LONG", 0xa5)

    OP("ADD_FLOAT", 0xa6)
    OP("SUB_FLOAT", 0xa7)
    OP("MUL_FLOAT", 0xa8)
    OP("DIV_FLOAT", 0xa9)
    OP("REM_FLOAT", 0xaa)

    OP("ADD_DOUBLE", 0xab)
    OP("SUB_DOUBLE", 0xac)
    OP("MUL_DOUBLE", 0xad)
    OP("DIV_DOUBLE", 0xae)
    OP("REM_DOUBLE", 0xaf)

    OP("ADD_INT_2ADDR", 0xb0)
    OP("SUB_INT_2ADDR", 0xb1)
    OP("MUL_INT_2ADDR", 0xb2)
    OP("DIV_INT_2ADDR", 0xb3)
    OP("REM_INT_2ADDR", 0xb4)
    OP("AND_INT_2ADDR", 0xb5)
    OP("OR_INT_2ADDR", 0xb6)
    OP("XOR_INT_2ADDR", 0xb7)
    OP("SHL_INT_2ADDR", 0xb8)
    OP("SHR_INT_2ADDR", 0xb9)
    OP("USHR_INT_2ADDR", 0xba)

    OP("ADD_LONG_2ADDR", 0xbb)
    OP("SUB_LONG_2ADDR", 0xbc)
    OP("MUL_LONG_2ADDR", 0xbd)
    OP("DIV_LONG_2ADDR", 0xbe)
    OP("REM_LONG_2ADDR", 0xbf)
    OP("AND_LONG_2ADDR", 0xc0)
    OP("OR_LONG_2ADDR", 0xc1)
    OP("XOR_LONG_2ADDR", 0xc2)
    OP("SHL_LONG_2ADDR", 0xc3)
    OP("SHR_LONG_2ADDR", 0xc4)
    OP("USHR_LONG_2ADDR", 0xc5)

    OP("ADD_FLOAT_2ADDR", 0xc6)
    OP("SUB_FLOAT_2ADDR", 0xc7)
    OP("MUL_FLOAT_2ADDR", 0xc8)
    OP("DIV_FLOAT_2ADDR", 0xc9)
    OP("REM_FLOAT_2ADDR", 0xca)

    OP("ADD_DOUBLE_2ADDR", 0xcb)
    OP("SUB_DOUBLE_2ADDR", 0xcc)
    OP("MUL_DOUBLE_2ADDR", 0xcd)
    OP("DIV_DOUBLE_2ADDR", 0xce)
    OP("REM_DOUBLE_2ADDR", 0xcf)

    OP("ADD_INT_LIT16", 0xd0)
    OP("RSUB_INT", 0xd1)
    OP("MUL_INT_LIT16", 0xd2)
    OP("DIV_INT_LIT16", 0xd3)
    OP("REM_INT_LIT16", 0xd4)
    OP("AND_INT_LIT16", 0xd5)
    OP("OR_INT_LIT16", 0xd6)
    OP("XOR_INT_LIT16", 0xd7)

    OP("ADD_INT_LIT8", 0xd8)
    OP("RSUB_INT_LIT8", 0xd9)
    OP("MUL_INT_LIT8", 0xda)
    OP("DIV_INT_LIT8", 0xdb)
    OP("REM_INT_LIT8", 0xdc)
    OP("AND_INT_LIT8", 0xdd)
    OP("OR_INT_LIT8", 0xde)
    OP("XOR_INT_LIT8", 0xdf)
    OP("SHL_INT_LIT8", 0xe0)
    OP("SHR_INT_LIT8", 0xe1)
    OP("USHR_INT_LIT8", 0xe2)

    OP("INVOKE_POLYMORPHIC", 0xfa)
    OP("INVOKE_POLYMORPHIC_RANGE", 0xfb)
    OP("INVOKE_CUSTOM", 0xfc)
    OP("INVOKE_CUSTOM_RANGE", 0xfd)
    OP("CONST_METHOD_HANDLE", 0xfe)
    OP("CONST_METHOD_TYPE", 0xff)

#undef OP

    finish:
    env->ReleaseStringUTFChars(opcodeName_, opcodeName);
    return value;
}







static JNINativeMethod gMethods[] = {
        /*{
                const_cast<char *>("buildEncryptedBlock"),
                const_cast<char *>("([B)[B"),
                reinterpret_cast<void *>(native_buildEncryptedBlock)
        },
        {
                const_cast<char *>("fixDexHeader"),
                const_cast<char *>("([B)[B"),
                reinterpret_cast<void *>(native_fixDexHeader)
        },
        {
                const_cast<char *>("isValidDex"),
                const_cast<char *>("([B)Z"),
                reinterpret_cast<void *>(native_isValidDex)
        },
        {
                const_cast<char *>("intToLe4"),
                const_cast<char *>("(I)[B"),
                reinterpret_cast<void *>(native_intToLe4)
        },*/
        {
                const_cast<char *>("b"),
                const_cast<char *>("(Ljava/io/File;Ljava/io/File;Ljava/lang/String;Ljava/lang/String;[B)V"),
                reinterpret_cast<void *>(native_buildEncryptedShellDex)
        },
};

static JNINativeMethod gVmpUtilsMethods[] = {
        {
                const_cast<char *>("a"),
                const_cast<char *>("(Ljava/lang/String;)I"),
                reinterpret_cast<void *>(native_getRealDexOpcodeValue)
        },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;

    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass mainClazz = env->FindClass("com/ark/jiagu/ArkMainActivity");
    if (mainClazz == nullptr) {
        return JNI_ERR;
    }

    if (env->RegisterNatives(
            mainClazz,
            gMethods,
            sizeof(gMethods) / sizeof(gMethods[0])
    ) != JNI_OK) {
        return JNI_ERR;
    }

    jclass vmpUtilsClazz = env->FindClass("com/ark/jiagu/vm/VmpUtils");
    if (vmpUtilsClazz == nullptr) {
        return JNI_ERR;
    }

    if (env->RegisterNatives(
            vmpUtilsClazz,
            gVmpUtilsMethods,
            sizeof(gVmpUtilsMethods) / sizeof(gVmpUtilsMethods[0])
    ) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
