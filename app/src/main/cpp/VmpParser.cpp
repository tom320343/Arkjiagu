#include "VmpParser.h"

#include <android/log.h>
#include <string.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#define LOG_TAG "GuardVMP_VmpParser"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define GUARD_VMP_SECTION_NAME ".gvmp"
static VmpBinContext g_bin;
static bool loadVmpBinFromSelfSoSection(std::vector<unsigned char> &out) {
    out.clear();

    Dl_info info;
    if (dladdr((void *) &loadVmpBinFromSelfSoSection, &info) == 0 || info.dli_fname == nullptr) {
        return false;
    }

    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return false;
    }

    void *map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED || map == nullptr) {
        return false;
    }

    const unsigned char *base = reinterpret_cast<const unsigned char *>(map);
    bool ok = false;

    do {
        if (st.st_size < EI_NIDENT) {
            break;
        }

        if (!(base[0] == ELFMAG0 && base[1] == ELFMAG1 && base[2] == ELFMAG2 && base[3] == ELFMAG3)) {
            break;
        }

        if (base[EI_CLASS] == ELFCLASS64) {
            if (st.st_size < sizeof(Elf64_Ehdr)) {
                break;
            }

            const Elf64_Ehdr *eh = reinterpret_cast<const Elf64_Ehdr *>(base);

            if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx == SHN_UNDEF) {
                break;
            }

            uint64_t shTableEnd = eh->e_shoff + static_cast<uint64_t>(eh->e_shnum) * sizeof(Elf64_Shdr);
            if (shTableEnd > static_cast<uint64_t>(st.st_size)) {
                break;
            }

            const Elf64_Shdr *shdrs = reinterpret_cast<const Elf64_Shdr *>(base + eh->e_shoff);
            const Elf64_Shdr &shStr = shdrs[eh->e_shstrndx];

            if (shStr.sh_offset + shStr.sh_size > static_cast<uint64_t>(st.st_size)) {
                break;
            }

            const char *strtab = reinterpret_cast<const char *>(base + shStr.sh_offset);

            for (int i = 0; i < eh->e_shnum; i++) {
                const Elf64_Shdr &sh = shdrs[i];

                if (sh.sh_name >= shStr.sh_size) {
                    continue;
                }

                const char *name = strtab + sh.sh_name;
                if (strcmp(name, GUARD_VMP_SECTION_NAME) != 0) {
                    continue;
                }

                if (sh.sh_size <= 0 || sh.sh_offset + sh.sh_size > static_cast<uint64_t>(st.st_size)) {
                    break;
                }

                out.assign(base + sh.sh_offset, base + sh.sh_offset + sh.sh_size);
                ok = !out.empty();
                break;
            }

        } else if (base[EI_CLASS] == ELFCLASS32) {
            if (st.st_size < sizeof(Elf32_Ehdr)) {
                break;
            }

            const Elf32_Ehdr *eh = reinterpret_cast<const Elf32_Ehdr *>(base);

            if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx == SHN_UNDEF) {
                break;
            }

            uint64_t shTableEnd = static_cast<uint64_t>(eh->e_shoff) + static_cast<uint64_t>(eh->e_shnum) * sizeof(Elf32_Shdr);
            if (shTableEnd > static_cast<uint64_t>(st.st_size)) {
                break;
            }

            const Elf32_Shdr *shdrs = reinterpret_cast<const Elf32_Shdr *>(base + eh->e_shoff);
            const Elf32_Shdr &shStr = shdrs[eh->e_shstrndx];

            if (static_cast<uint64_t>(shStr.sh_offset) + shStr.sh_size > static_cast<uint64_t>(st.st_size)) {
                break;
            }

            const char *strtab = reinterpret_cast<const char *>(base + shStr.sh_offset);

            for (int i = 0; i < eh->e_shnum; i++) {
                const Elf32_Shdr &sh = shdrs[i];

                if (sh.sh_name >= shStr.sh_size) {
                    continue;
                }

                const char *name = strtab + sh.sh_name;
                if (strcmp(name, GUARD_VMP_SECTION_NAME) != 0) {
                    continue;
                }

                if (sh.sh_size <= 0 ||
                    static_cast<uint64_t>(sh.sh_offset) + sh.sh_size > static_cast<uint64_t>(st.st_size)) {
                    break;
                }

                out.assign(base + sh.sh_offset, base + sh.sh_offset + sh.sh_size);
                ok = !out.empty();
                break;
            }
        }

    } while (false);

    munmap(map, st.st_size);
    return ok;
}
static bool readIntLE(const std::vector<unsigned char> &data, size_t &pos, int &out) {
    if (pos + 4 > data.size()) {
        return false;
    }

    out = static_cast<int>(
            (data[pos] & 0xff)
            | ((data[pos + 1] & 0xff) << 8)
            | ((data[pos + 2] & 0xff) << 16)
            | ((data[pos + 3] & 0xff) << 24)
    );

    pos += 4;
    return true;
}
//读取指定位置 int
static bool readIntLEAt(const std::vector<unsigned char> &data, size_t pos, int &out) {
    if (pos + 4 > data.size()) {
        return false;
    }

    out = static_cast<int>(
            (data[pos] & 0xff)
            | ((data[pos + 1] & 0xff) << 8)
            | ((data[pos + 2] & 0xff) << 16)
            | ((data[pos + 3] & 0xff) << 24)
    );

    return true;
}
//XOR解密方法
static const unsigned char AES_SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char AES_INV_SBOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static bool decryptVmpBinV3(const unsigned char *encryptedData, int encryptedLen,
                            const unsigned char *key, int keyLen,
                            std::vector<unsigned char> &outPlain) {
    outPlain.resize(static_cast<size_t>(encryptedLen));

    int halfLen = keyLen / 2;

    for (int i = 0; i < encryptedLen; i++) {
        outPlain[i] = static_cast<unsigned char>(encryptedData[i] ^ key[(i + halfLen) % keyLen]);
    }

    int shift = (key[0] & 0x7) + 1;
    for (int i = 0; i < encryptedLen; i++) {
        unsigned char b = outPlain[i];
        outPlain[i] = static_cast<unsigned char>(((b << shift) | (b >> (8 - shift))) & 0xFF);
    }

    for (int i = 0; i < encryptedLen; i++) {
        outPlain[i] = AES_INV_SBOX[outPlain[i]];
    }

    for (int i = 0; i < encryptedLen; i++) {
        outPlain[i] = static_cast<unsigned char>(outPlain[i] ^ key[i % keyLen]);
    }

    return true;
}

static bool decryptVmpBinIfNeeded(const std::vector<unsigned char> &input,
                                  std::vector<unsigned char> &outPlain) {
    outPlain.clear();

    if (input.size() < 8) {
        return false;
    }

    if (input[0] == 'A' && input[1] == 'V' && input[2] == 'M' && input[3] == 'P') {
        outPlain = input;
        return true;
    }

    if (!(input[0] == 'A' && input[1] == 'V' && input[2] == 'M' && input[3] == 'X')) {
        return false;
    }

    size_t pos = 4;

    int version = 0;
    if (!readIntLE(input, pos, version)) {
        return false;
    }

    if (version < 2 || version > 3) {
        return false;
    }

    int encryptedLen = 0;
    if (!readIntLE(input, pos, encryptedLen)) {
        return false;
    }

    if (encryptedLen <= 0) {
        return false;
    }

    size_t encryptedOffset = pos;
    size_t encryptedEnd = encryptedOffset + static_cast<size_t>(encryptedLen);

    if (encryptedEnd + 4 > input.size()) {
        return false;
    }

    int keyLen = 0;
    if (!readIntLEAt(input, input.size() - 4, keyLen)) {
        return false;
    }

    if (keyLen <= 0 || keyLen > 1024) {
        return false;
    }

    if (input.size() < static_cast<size_t>(keyLen) + 4) {
        return false;
    }

    size_t keyOffset = input.size() - 4 - static_cast<size_t>(keyLen);

    if (keyOffset < encryptedEnd) {
        return false;
    }

    const unsigned char *encryptedData = input.data() + encryptedOffset;
    const unsigned char *key = input.data() + keyOffset;

    if (version == 3) {
        if (!decryptVmpBinV3(encryptedData, encryptedLen, key, keyLen, outPlain)) {
            outPlain.clear();
            return false;
        }
    } else {
        outPlain.resize(static_cast<size_t>(encryptedLen));

        for (int i = 0; i < encryptedLen; i++) {
            outPlain[i] = static_cast<unsigned char>(
                    encryptedData[i] ^ key[i % keyLen]
            );
        }
    }

    if (outPlain.size() < 8
        || !(outPlain[0] == 'A' && outPlain[1] == 'V'
             && outPlain[2] == 'M' && outPlain[3] == 'P')) {
        outPlain.clear();
        return false;
    }

    return true;
}


static bool readLongLE(const std::vector<unsigned char> &data, size_t &pos, int64_t &out) {
    if (pos + 8 > data.size()) {
        return false;
    }

    uint64_t value = 0;

    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t) data[pos + i] & 0xff) << (i * 8);
    }

    out = static_cast<int64_t>(value);
    pos += 8;
    return true;
}

static bool readStringLE(const std::vector<unsigned char> &data, size_t &pos, std::string &out) {
    int len = 0;

    if (!readIntLE(data, pos, len)) {
        return false;
    }

    if (len == -1) {
        out.clear();
        return true;
    }

    if (len < 0 || pos + static_cast<size_t>(len) > data.size()) {
        return false;
    }

    out.assign(reinterpret_cast<const char *>(data.data() + pos), len);
    pos += len;

    return true;
}

static bool readAllBytesFromInputStream(
        JNIEnv *env,
        jobject inputStream,
        std::vector<unsigned char> &out
) {
    out.clear();

    if (env == nullptr || inputStream == nullptr) {
        return false;
    }

    jclass clsInputStream = env->FindClass("java/io/InputStream");
    if (clsInputStream == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midRead = env->GetMethodID(clsInputStream, "read", "([B)I");
    jmethodID midClose = env->GetMethodID(clsInputStream, "close", "()V");

    if (midRead == nullptr || midClose == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jbyteArray buffer = env->NewByteArray(8192);
    if (buffer == nullptr) {
        return false;
    }

    while (true) {
        jint len = env->CallIntMethod(inputStream, midRead, buffer);

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out.clear();
            return false;
        }

        if (len <= 0) {
            break;
        }

        size_t oldSize = out.size();
        out.resize(oldSize + len);

        env->GetByteArrayRegion(
                buffer,
                0,
                len,
                reinterpret_cast<jbyte *>(out.data() + oldSize)
        );

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out.clear();
            return false;
        }
    }

    env->CallVoidMethod(inputStream, midClose);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    return !out.empty();
}

static bool loadVmpBinFromAssets(
        JNIEnv *env,
        jobject context,
        std::vector<unsigned char> &out
) {
    out.clear();

    jclass clsContext = env->GetObjectClass(context);
    if (clsContext == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midGetAssets = env->GetMethodID(
            clsContext,
            "getAssets",
            "()Landroid/content/res/AssetManager;"
    );

    if (midGetAssets == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject assetManager = env->CallObjectMethod(context, midGetAssets);
    if (env->ExceptionCheck() || assetManager == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jclass clsAssetManager = env->GetObjectClass(assetManager);
    if (clsAssetManager == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midOpen = env->GetMethodID(
            clsAssetManager,
            "open",
            "(Ljava/lang/String;)Ljava/io/InputStream;"
    );

    if (midOpen == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jstring fileName = env->NewStringUTF("vmp.bin");

    jobject inputStream = env->CallObjectMethod(assetManager, midOpen, fileName);
    if (env->ExceptionCheck() || inputStream == nullptr) {
        env->ExceptionClear();
        //LOGE("打开 assets/vmp.bin 失败");
        return false;
    }

    return readAllBytesFromInputStream(env, inputStream, out);
}

static bool parseVmpHeaderAndIndex() {
    const std::vector<unsigned char> &data = g_bin.rawData;

    if (data.size() < 8) {
        //LOGE("vmp.bin长度太短");
        return false;
    }

    if (!(data[0] == 'A' && data[1] == 'V' && data[2] == 'M' && data[3] == 'P')) {
        //LOGE("vmp.bin magic错误");
        return false;
    }

    size_t pos = 4;

    int version = 0;
    if (!readIntLE(data, pos, version)) {
        //LOGE("读取version失败");
        return false;
    }

    if (version != 6) {
        //LOGE("不支持的vmp.bin版本：%d", version);
        return false;
    }

    g_bin.version = version;

    int methodIndexCount = 0;
    if (!readIntLE(data, pos, methodIndexCount)) {
        //LOGE("读取methodIndexCount失败");
        return false;
    }

    if (methodIndexCount < 0) {
        //LOGE("methodIndexCount非法：%d", methodIndexCount);
        return false;
    }

    g_bin.methodIndexMap.clear();

    // 如果结构体里还保留 vmOpcodeMap，这里清空即可，不再解析映射表
    g_bin.vmOpcodeMap.clear();

    //LOGI("开始解析method索引表，数量=%d", methodIndexCount);

    for (int i = 0; i < methodIndexCount; i++) {
        int methodId = 0;
        int64_t offset = 0;
        int size = 0;

        if (!readIntLE(data, pos, methodId)) {
            //LOGE("读取methodId失败 index=%d", i);
            return false;
        }

        if (!readLongLE(data, pos, offset)) {
            //LOGE("读取method offset失败 index=%d", i);
            return false;
        }

        if (!readIntLE(data, pos, size)) {
            //LOGE("读取method size失败 index=%d", i);
            return false;
        }

        if (methodId <= 0 || offset < 0 || size <= 0) {
            //LOGE("method索引非法 methodId=%d offset=%lld size=%d",methodId,static_cast<long long>(offset),size);
            return false;
        }

        if (static_cast<uint64_t>(offset) + static_cast<uint64_t>(size) > data.size()) {
            //LOGE("method索引越界 methodId=%d offset=%lld size=%d binSize=%d",methodId,static_cast<long long>(offset),size,static_cast<int>(data.size()));
            return false;
        }

        VmpMethodIndex index;
        index.methodId = methodId;
        index.offset = static_cast<uint64_t>(offset);
        index.size = static_cast<uint32_t>(size);
        g_bin.methodIndexMap[methodId] = index;
        //LOGI("methodIndex[%d] methodId=%d offset=%lld size=%d",i,methodId,static_cast<long long>(offset),size);
    }
    g_bin.methodCache.clear();
    //LOGI("vmp.bin解析完成 version=%d methodCount=%d，已移除opcode映射表",g_bin.version,static_cast<int>(g_bin.methodIndexMap.size()));

    return true;
}

bool VmpParser_EnsureLoaded(JNIEnv *env, jobject context) {
    if (g_bin.loaded) {
        return true;
    }

    if (env == nullptr || context == nullptr) {
        return false;
    }

    g_bin = VmpBinContext();

    std::vector<unsigned char> fileData;

    bool loadedFromSo = loadVmpBinFromSelfSoSection(fileData);

    if (loadedFromSo) {
        //LOGI("已从当前so的ELF section读取vmp.bin，大小=%d", static_cast<int>(fileData.size()));
    } else {
        //LOGI("当前so未读取到ELF section vmp.bin，准备从assets读取");

        if (!loadVmpBinFromAssets(env, context, fileData)) {
            g_bin = VmpBinContext();
            return false;
        }

        //LOGI("已从assets读取vmp.bin，大小=%d", static_cast<int>(fileData.size()));
    }

    if (!decryptVmpBinIfNeeded(fileData, g_bin.rawData)) {
        if (loadedFromSo) {
            //LOGI("so内置vmp.bin解密失败，尝试回退assets");

            fileData.clear();

            if (!loadVmpBinFromAssets(env, context, fileData)) {
                g_bin = VmpBinContext();
                return false;
            }

            if (!decryptVmpBinIfNeeded(fileData, g_bin.rawData)) {
                g_bin = VmpBinContext();
                return false;
            }
        } else {
            g_bin = VmpBinContext();
            return false;
        }
    }

    if (!parseVmpHeaderAndIndex()) {
        if (loadedFromSo) {
            //LOGI("so内置vmp.bin解析失败，尝试回退assets");

            g_bin = VmpBinContext();
            fileData.clear();

            if (!loadVmpBinFromAssets(env, context, fileData)) {
                return false;
            }

            if (!decryptVmpBinIfNeeded(fileData, g_bin.rawData)) {
                g_bin = VmpBinContext();
                return false;
            }

            if (!parseVmpHeaderAndIndex()) {
                g_bin = VmpBinContext();
                return false;
            }
        } else {
            g_bin = VmpBinContext();
            return false;
        }
    }

    g_bin.loaded = true;
    return true;
}

bool VmpParser_FindMethod(
        JNIEnv *env,
        int methodId,
        VmpMethod &outMethod
) {
    (void) env;

    if (!g_bin.loaded) {
        //LOGE("vmp.bin尚未加载");
        return false;
    }

    auto cacheIt = g_bin.methodCache.find(methodId);
    if (cacheIt != g_bin.methodCache.end()) {
        outMethod = cacheIt->second;
        //LOGI("methodId=%d 命中方法缓存", methodId);
        return true;
    }

    auto it = g_bin.methodIndexMap.find(methodId);
    if (it == g_bin.methodIndexMap.end()) {
        //LOGE("methodId=%d 不存在于索引表", methodId);
        return false;
    }

    const VmpMethodIndex &index = it->second;

    if (index.offset + index.size > g_bin.rawData.size()) {
        //LOGE("methodId=%d 索引越界", methodId);
        return false;
    }

    size_t pos = static_cast<size_t>(index.offset);
    size_t end = static_cast<size_t>(index.offset + index.size);

    VmpMethod method;

    int isStaticValue = 0;
    int parameterTypeCount = 0;
    int instructionCount = 0;

    if (!readIntLE(g_bin.rawData, pos, method.methodId)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.dexName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.className)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.methodName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.methodSignature)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.accessFlags)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.registerCount)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.paramCount)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.returnType)) return false;
    if (!readIntLE(g_bin.rawData, pos, isStaticValue)) return false;

    method.isStatic = isStaticValue != 0;

    if (!readIntLE(g_bin.rawData, pos, parameterTypeCount)) return false;

    if (parameterTypeCount < 0) {
        //LOGE("parameterTypeCount非法 methodId=%d count=%d", methodId, parameterTypeCount);
        return false;
    }

    for (int i = 0; i < parameterTypeCount; i++) {
        std::string type;
        if (!readStringLE(g_bin.rawData, pos, type)) return false;
        method.parameterTypes.push_back(type);
    }

    if (!readIntLE(g_bin.rawData, pos, instructionCount)) return false;

    if (instructionCount < 0) {
        //LOGE("instructionCount非法 methodId=%d count=%d", methodId, instructionCount);
        return false;
    }

    for (int i = 0; i < instructionCount; i++) {
        VmpInstruction insn;

        int registerCount = 0;

        if (!readIntLE(g_bin.rawData, pos, insn.codeUnitOffset)) return false;

        // version=6 开始，vmOpcode字段里直接保存真实dex opcode
        if (!readIntLE(g_bin.rawData, pos, insn.vmOpcode)) return false;

        // 不再查 opcode 映射表，直接把 vmOpcode 当真实 opcode 传给虚拟机
        insn.realOpcode = insn.vmOpcode;
        insn.opcodeName.clear();

        if (!readStringLE(g_bin.rawData, pos, insn.formatName)) return false;
        if (!readIntLE(g_bin.rawData, pos, insn.codeUnits)) return false;

        if (!readIntLE(g_bin.rawData, pos, registerCount)) return false;

        if (registerCount < 0) {
            //LOGE("registerCount非法 methodId=%d instructionIndex=%d count=%d",methodId,i,registerCount);
            return false;
        }

        for (int r = 0; r < registerCount; r++) {
            int reg = 0;
            if (!readIntLE(g_bin.rawData, pos, reg)) return false;
            insn.registers.push_back(reg);
        }

        int64_t literalValue = 0;

        if (!readIntLE(g_bin.rawData, pos, insn.literalType)) return false;
        if (!readLongLE(g_bin.rawData, pos, literalValue)) return false;
        insn.literalValue = literalValue;

        if (!readIntLE(g_bin.rawData, pos, insn.offsetType)) return false;
        if (!readIntLE(g_bin.rawData, pos, insn.offsetValue)) return false;

        if (!readIntLE(g_bin.rawData, pos, insn.referenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.referenceData)) return false;

        if (!readIntLE(g_bin.rawData, pos, insn.extraReferenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.extraReferenceData)) return false;

        method.instructions.push_back(insn);
    }
    int tryBlockCount = 0;
    if (!readIntLE(g_bin.rawData, pos, tryBlockCount)) return false;
    if (tryBlockCount < 0) {
        //LOGE("tryBlockCount非法 methodId=%d count=%d", methodId, tryBlockCount);
        return false;
    }
    for (int i = 0; i < tryBlockCount; i++) {
        VmpTryBlock tryBlock;
        int handlerCount = 0;
        if (!readIntLE(g_bin.rawData, pos, tryBlock.startCodeAddress)) return false;
        if (!readIntLE(g_bin.rawData, pos, tryBlock.codeUnitCount)) return false;
        if (!readIntLE(g_bin.rawData, pos, handlerCount)) return false;
        if (handlerCount < 0) {
            //LOGE("handlerCount非法 methodId=%d tryIndex=%d count=%d",methodId,i,handlerCount);
            return false;
        }
        for (int h = 0; h < handlerCount; h++) {
            VmpExceptionHandler handler;
            if (!readStringLE(g_bin.rawData, pos, handler.exceptionType)) return false;
            if (!readIntLE(g_bin.rawData, pos, handler.handlerCodeAddress)) return false;
            tryBlock.handlers.push_back(handler);
        }
        method.tryBlocks.push_back(tryBlock);
    }
    if (pos > end) {
        //LOGE("methodId=%d 解析越界", methodId);
        return false;
    }
    if (pos != end) {
        //LOGI("methodId=%d 解析完成，但pos和end不完全一致 pos=%d end=%d",methodId,static_cast<int>(pos),static_cast<int>(end));
    }
    g_bin.methodCache[methodId] = method;
    outMethod = method;
    //LOGI("methodId=%d 已从内存bin解析并加入缓存，instruction.vmOpcode已直接作为真实opcode",methodId);
    return true;
}