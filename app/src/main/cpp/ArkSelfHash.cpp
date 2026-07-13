// ArkSelfHash.cpp
#include <jni.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <android/log.h>
#include <errno.h>
#include "ArkSelfHash.h"

#define ARK_TAG "ArkSelfHash"
#define ARK_LOGI(...) __android_log_print(ANDROID_LOG_INFO, ARK_TAG, __VA_ARGS__)
#define ARK_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, ARK_TAG, __VA_ARGS__)

/* ================================================================
 * XOR 字符串混淆工具
 * 编译时使用混淆字符串，运行时通过 xor_deobfuscate 还原
 * ================================================================ */
struct ObfString {
    const unsigned char *data;
    size_t len;
    unsigned char key;
};

static void xor_deobfuscate(char *out, const unsigned char *in, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (char)(in[i] ^ key);
    }
    out[len] = '\0';
}

/* 混淆字符串定义: 实际字符串 ^ key */
/* "classes.dex" ^ 0x5A */
static const unsigned char g_str_classes_dex[] = {
    0x39, 0x2E, 0x21, 0x36, 0x36, 0x28, 0x36, 0x31, 0x3D, 0x38, 0x36, 0x5A
};

/* "META-INF/" ^ 0x5A */
static const unsigned char g_str_meta_inf[] = {
    0x17, 0x14, 0x09, 0x10, 0x4E, 0x04, 0x0D, 0x15, 0x5A
};

/* ".RSA" ^ 0x5A */
static const unsigned char g_str_rsa[] = {
    0x5A, 0x09, 0x36, 0x10
};

/* ".DSA" ^ 0x5A */
static const unsigned char g_str_dsa[] = {
    0x5A, 0x0E, 0x36, 0x10
};

/* "sourceDir" ^ 0x5A */
static const unsigned char g_str_source_dir[] = {
    0x36, 0x34, 0x28, 0x33, 0x2E, 0x28, 0x0E, 0x38, 0x33, 0x5A
};

static const unsigned char g_key_xor_5a = 0x5A;

/* 预期签名 SHA256 哈希值 (16进制字符串) */
/* 实际部署时应编译时注入，此处给出占位 */
static const char *g_expected_sha256_hex =
    /* "PLACEHOLDER_EXPECTED_SIGNATURE_SHA256_HEX_STRING\0" ^ 0x5A */
    "\x0B\x15\x10\x1E\x17\x18\x11\x0B\x1E\x17\x18\x0C\x1E\x17\x1E\x1E"
    "\x18\x17\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E"
    "\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E";

/* ================================================================
 * syscall 封装 —— 绕过 libc hook
 * ================================================================ */

static int64_t ark_sys_read(int fd, void *buf, size_t count) {
#ifdef __aarch64__
    register int64_t x0 __asm__("x0") = fd;
    register void *x1 __asm__("x1") = buf;
    register size_t x2 __asm__("x2") = count;
    register int64_t x8 __asm__("x8") = __NR_read;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
#elif defined(__arm__)
    register int r0 __asm__("r0") = fd;
    register void *r1 __asm__("r1") = buf;
    register size_t r2 __asm__("r2") = count;
    register int r7 __asm__("r7") = __NR_read;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
#else
    return syscall(__NR_read, fd, buf, count);
#endif
}

static int64_t ark_sys_open(const char *path, int flags, mode_t mode) {
#ifdef __aarch64__
    register int64_t x0 __asm__("x0") = (int64_t)(intptr_t)path;
    register int x1 __asm__("x1") = flags;
    register mode_t x2 __asm__("x2") = mode;
    register int64_t x8 __asm__("x8") = __NR_openat;
    register int x3 __asm__("x3") = AT_FDCWD;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
#elif defined(__arm__)
    register int r0 __asm__("r0") = AT_FDCWD;
    register const char *r1 __asm__("r1") = path;
    register int r2 __asm__("r2") = flags;
    register mode_t r3 __asm__("r3") = mode;
    register int r7 __asm__("r7") = __NR_openat;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r7) : "memory");
    return r0;
#else
    return syscall(__NR_openat, AT_FDCWD, path, flags, mode);
#endif
}

static int64_t ark_sys_close(int fd) {
#ifdef __aarch64__
    register int64_t x0 __asm__("x0") = fd;
    register int64_t x8 __asm__("x8") = __NR_close;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
#elif defined(__arm__)
    register int r0 __asm__("r0") = fd;
    register int r7 __asm__("r7") = __NR_close;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
#else
    return syscall(__NR_close, fd);
#endif
}

static int64_t ark_sys_lseek(int fd, int64_t offset, int whence) {
#ifdef __aarch64__
    register int64_t x0 __asm__("x0") = fd;
    register int64_t x1 __asm__("x1") = offset;
    register int x2 __asm__("x2") = whence;
    register int64_t x8 __asm__("x8") = __NR_lseek;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
#elif defined(__arm__)
    register int r0 __asm__("r0") = fd;
    register int64_t r1_r2 __asm__("r1") = offset;
    register int r3 __asm__("r3") = whence;
    register int r7 __asm__("r7") = __NR__llseek;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1_r2), "r"(r3), "r"(r7) : "memory");
    return r0;
#else
    return syscall(__NR_lseek, fd, offset, whence);
#endif
}

static inline int64_t ark_read_le32(const unsigned char *p) {
    return ((int64_t)(p[0]))
         | ((int64_t)(p[1]) << 8)
         | ((int64_t)(p[2]) << 16)
         | ((int64_t)(p[3]) << 24);
}

static inline int64_t ark_read_le16(const unsigned char *p) {
    return ((int64_t)(p[0]))
         | ((int64_t)(p[1]) << 8);
}

/* ================================================================
 * SHA-256 实现
 * ================================================================ */
typedef struct {
    uint32_t state[8];
    uint32_t count[2];
    unsigned char buffer[64];
} Sha256Ctx;

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t g_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(Sha256Ctx *ctx, const unsigned char data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (uint32_t)(data[j] << 24) | (uint32_t)(data[j + 1] << 16)
             | (uint32_t)(data[j + 2] << 8) | (uint32_t)(data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + g_sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

static void sha256_update(Sha256Ctx *ctx, const unsigned char *data, size_t len) {
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->count[0] & 63] = data[i];
        ctx->count[0]++;
        if (ctx->count[0] == 0) {
            ctx->count[1]++;
        }

        if ((ctx->count[0] & 63) == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, unsigned char digest[32]) {
    uint32_t i, j, lo, hi;

    lo = ctx->count[0];
    hi = ctx->count[1];

    i = (lo >> 3) & 63;
    ctx->buffer[i++] = 0x80;

    if (i <= 56) {
        memset(ctx->buffer + i, 0, 56 - i);
    } else {
        memset(ctx->buffer + i, 0, 64 - i);
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    }

    for (j = 0; j < 4; j++) {
        ctx->buffer[56 + j] = (unsigned char)((hi >> ((3 - j) * 8)) & 0xFF);
        ctx->buffer[60 + j] = (unsigned char)((lo >> ((3 - j) * 8)) & 0xFF);
    }
    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 8; j++) {
            digest[i * 8 + j * 4 + 0] = (unsigned char)((ctx->state[j] >> 24) & 0xFF);
            digest[i * 8 + j * 4 + 1] = (unsigned char)((ctx->state[j] >> 16) & 0xFF);
            digest[i * 8 + j * 4 + 2] = (unsigned char)((ctx->state[j] >> 8) & 0xFF);
            digest[i * 8 + j * 4 + 3] = (unsigned char)(ctx->state[j] & 0xFF);
        }
    }
}

static void sha256_hash(const unsigned char *data, size_t len, unsigned char digest[32]) {
    Sha256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

static void sha256_to_hex(const unsigned char digest[32], char hex[65]) {
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    hex[64] = '\0';
}

/* ================================================================
 * ZIP / APK 签名证书解析
 * ================================================================ */

/* ZIP 结构常量 */
#define ARK_ZIP_LOCAL_FILE_SIG        0x04034b50
#define ARK_ZIP_CENTRAL_DIR_SIG       0x02014b50
#define ARK_ZIP_END_OF_CENTRAL_SIG    0x06054b50
#define ARK_ZIP_READ_CHUNK            4096
#define ARK_MAX_APK_SIZE              (128 * 1024 * 1024)

/* 在缓冲区中定位字节序列 */
static int64_t find_bytes(const unsigned char *buf, size_t buf_len,
                           const unsigned char *needle, size_t needle_len,
                           size_t start_pos) {
    if (needle_len == 0 || needle_len > buf_len) return -1;
    for (size_t i = start_pos; i <= buf_len - needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            return (int64_t)i;
        }
    }
    return -1;
}

/* 从 APK 中提取 META-INF/*.RSA 或 *.DSA 签名文件 */
static bool extract_signature_file(const unsigned char *apk_data, size_t apk_size,
                                    const unsigned char **out_sig, size_t *out_sig_len) {
    if (apk_data == NULL || apk_size < 22) return false;

    /* 查找 End of Central Directory Record */
    size_t search_start = (apk_size > 65557) ? (apk_size - 65557) : 0;
    size_t eocd_pos = apk_size;

    for (size_t i = search_start; i < apk_size - 22; i++) {
        if (ark_read_le32(apk_data + i) == ARK_ZIP_END_OF_CENTRAL_SIG) {
            eocd_pos = i;
            break;
        }
    }

    if (eocd_pos >= apk_size) return false;

    int64_t central_dir_offset = ark_read_le32(apk_data + eocd_pos + 16);
    int64_t central_dir_size   = ark_read_le32(apk_data + eocd_pos + 12);
    int64_t num_entries        = ark_read_le16(apk_data + eocd_pos + 10);

    if (central_dir_offset <= 0 || central_dir_size <= 0
        || (size_t)(central_dir_offset + central_dir_size) > apk_size) {
        return false;
    }

    if (num_entries > 65535) return false;

    /* XOR 还原 "META-INF/" */
    char meta_prefix[16];
    xor_deobfuscate(meta_prefix, g_str_meta_inf, sizeof(g_str_meta_inf) - 1, g_key_xor_5a);

    size_t meta_prefix_len = sizeof(g_str_meta_inf) - 1;

    size_t cd_pos = (size_t)central_dir_offset;

    for (int64_t i = 0; i < num_entries; i++) {
        if (cd_pos + 46 > apk_size) break;

        if (ark_read_le32(apk_data + cd_pos) != ARK_ZIP_CENTRAL_DIR_SIG) {
            break;
        }

        int64_t filename_len = ark_read_le16(apk_data + cd_pos + 28);
        int64_t extra_len    = ark_read_le16(apk_data + cd_pos + 30);
        int64_t comment_len  = ark_read_le16(apk_data + cd_pos + 32);
        int64_t local_offset = ark_read_le32(apk_data + cd_pos + 42);

        if (cd_pos + 46 + filename_len > apk_size) break;

        const unsigned char *filename = apk_data + cd_pos + 46;

        /* 检查文件名前缀是否为 META-INF/ */
        if (filename_len >= (int64_t)meta_prefix_len + 4
            && memcmp(filename, meta_prefix, meta_prefix_len) == 0) {

            const unsigned char *ext = filename + filename_len - 4;
            int is_rsa = (memcmp(ext, ".RSA", 4) == 0);
            int is_dsa = (memcmp(ext, ".DSA", 4) == 0);

            if (is_rsa || is_dsa) {
                /* 定位 Local File Header 提取文件数据 */
                size_t lf_pos = (size_t)local_offset;
                if (lf_pos + 30 > apk_size) continue;

                int64_t lf_name_len = ark_read_le16(apk_data + lf_pos + 26);
                int64_t lf_extra_len = ark_read_le16(apk_data + lf_pos + 28);
                size_t data_offset = lf_pos + 30 + (size_t)lf_name_len + (size_t)lf_extra_len;

                int64_t compressed_size = ark_read_le32(apk_data + cd_pos + 20);
                int64_t uncompressed_size = ark_read_le32(apk_data + cd_pos + 24);

                if (compressed_size <= 0 || (size_t)(data_offset + compressed_size) > apk_size) continue;

                *out_sig = apk_data + data_offset;
                *out_sig_len = (size_t)compressed_size;

                /* SIG 文件通常不压缩，直接使用 */
                ARK_LOGI("[ArkSelfHash] 找到签名文件, 大小=%zu", *out_sig_len);
                return true;
            }
        }

        cd_pos += 46 + (size_t)filename_len + (size_t)extra_len + (size_t)comment_len;
    }

    return false;
}

/* 解析 DER 编码的证书，提取证书数据的 SHA256 */
static bool extract_cert_sha256(const unsigned char *pkcs7_data, size_t pkcs7_len,
                                 unsigned char out_sha256[32]) {
    if (pkcs7_data == NULL || pkcs7_len < 64) return false;

    /* 在 PKCS7 / CMS 数据中搜索 DER 编码的 X.509 证书 */
    /* X.509 证书以 SEQUENCE (0x30 0x82) 开头 */

    size_t pos = 0;
    int cert_count = 0;
    const unsigned char *best_cert = NULL;
    size_t best_cert_len = 0;

    while (pos < pkcs7_len - 4) {
        if (pkcs7_data[pos] == 0x30 && pkcs7_data[pos + 1] == 0x82) {
            /* 找到 SEQUENCE 标签（2字节长度形式） */
            size_t seq_len = (size_t)(pkcs7_data[pos + 2]) << 8 | (size_t)pkcs7_data[pos + 3];
            size_t total = seq_len + 4;

            if (pos + total <= pkcs7_len && seq_len > 256 && seq_len < 16384) {
                /* 简单的启发式：真实的 X.509 证书长度在 256~16384 字节之间 */
                const unsigned char *cert_data = pkcs7_data + pos;

                /* 选择找到的第一个合理长度的证书 */
                if (best_cert == NULL || seq_len > best_cert_len) {
                    best_cert = cert_data;
                    best_cert_len = total;
                }
                cert_count++;

                pos += total;
                continue;
            }
        }
        pos++;
    }

    if (best_cert == NULL || best_cert_len == 0) {
        ARK_LOGE("[ArkSelfHash] 在签名文件中未找到有效证书");
        return false;
    }

    ARK_LOGI("[ArkSelfHash] 找到 %d 个证书, 使用长度最大者: %zu 字节", cert_count, best_cert_len);

    sha256_hash(best_cert, best_cert_len, out_sha256);
    return true;
}

/* ================================================================
 * 主签名校验函数
 * ================================================================ */

extern "C"
jboolean ark_get_self_cert_sha256(JNIEnv *env, jbyteArray outSha256) {
    if (env == NULL) {
        return JNI_FALSE;
    }

    /* 为目标数据预先分配好 SHA256 缓冲区 */
    unsigned char local_sha256[32];
    memset(local_sha256, 0, sizeof(local_sha256));

    /* 获取 ApplicationInfo.sourceDir */
    jclass cls_context = NULL;
    jclass cls_activity_thread = NULL;

    cls_activity_thread = env->FindClass("android/app/ActivityThread");
    if (cls_activity_thread == NULL) {
        env->ExceptionClear();
        ARK_LOGE("[ArkSelfHash] 找不到 ActivityThread 类");
        return JNI_FALSE;
    }

    jmethodID mid_current_app = env->GetStaticMethodID(
        cls_activity_thread,
        "currentApplication",
        "()Landroid/app/Application;"
    );
    if (mid_current_app == NULL) {
        env->ExceptionClear();
        ARK_LOGE("[ArkSelfHash] 找不到 currentApplication 方法");
        return JNI_FALSE;
    }

    jobject app = env->CallStaticObjectMethod(cls_activity_thread, mid_current_app);
    if (env->ExceptionCheck() || app == NULL) {
        env->ExceptionClear();
        ARK_LOGE("[ArkSelfHash] 获取 Application 失败");
        return JNI_FALSE;
    }

    jclass cls_app = env->GetObjectClass(app);
    jmethodID mid_get_app_info = env->GetMethodID(
        cls_app,
        "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;"
    );
    if (mid_get_app_info == NULL) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    jobject app_info = env->CallObjectMethod(app, mid_get_app_info);
    if (env->ExceptionCheck() || app_info == NULL) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    jclass cls_app_info = env->FindClass("android/content/pm/ApplicationInfo");
    if (cls_app_info == NULL) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    char field_source_dir[16];
    xor_deobfuscate(field_source_dir, g_str_source_dir, sizeof(g_str_source_dir) - 1, g_key_xor_5a);

    jfieldID fid_source_dir = env->GetFieldID(
        cls_app_info,
        field_source_dir,
        "Ljava/lang/String;"
    );

    /* 立即清理敏感字符串在栈上的痕迹 */
    memset(field_source_dir, 0, sizeof(field_source_dir));

    if (fid_source_dir == NULL) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    jstring source_dir_j = (jstring)env->GetObjectField(app_info, fid_source_dir);
    if (source_dir_j == NULL) {
        return JNI_FALSE;
    }

    const char *source_dir = env->GetStringUTFChars(source_dir_j, NULL);
    if (source_dir == NULL) {
        return JNI_FALSE;
    }

    ARK_LOGI("[ArkSelfHash] APK 路径: %s", source_dir);

    /* 通过 syscall 打开 APK 文件 */
    int fd = (int)ark_sys_open(source_dir, O_RDONLY, 0);
    if (fd < 0) {
        ARK_LOGE("[ArkSelfHash] sys_open 失败, errno=%d", errno);
        env->ReleaseStringUTFChars(source_dir_j, source_dir);
        exit(0);
    }

    /* 获取文件大小 */
    struct stat st;
    memset(&st, 0, sizeof(st));
    int stat_ret = syscall(__NR_fstat, fd, &st);
    if (stat_ret < 0 || st.st_size <= 0 || st.st_size > ARK_MAX_APK_SIZE) {
        ARK_LOGE("[ArkSelfHash] fstat 失败或文件大小异常");
        ark_sys_close(fd);
        env->ReleaseStringUTFChars(source_dir_j, source_dir);
        exit(0);
    }

    size_t apk_size = (size_t)st.st_size;

    /* 分配缓冲区读取整个 APK */
    unsigned char *apk_buffer = (unsigned char *)malloc(apk_size);
    if (apk_buffer == NULL) {
        ark_sys_close(fd);
        env->ReleaseStringUTFChars(source_dir_j, source_dir);
        exit(0);
    }

    size_t bytes_read = 0;
    while (bytes_read < apk_size) {
        int64_t ret = ark_sys_read(fd, apk_buffer + bytes_read, apk_size - bytes_read);
        if (ret <= 0) {
            ARK_LOGE("[ArkSelfHash] sys_read 失败, errno=%d", errno);
            free(apk_buffer);
            ark_sys_close(fd);
            env->ReleaseStringUTFChars(source_dir_j, source_dir);
            exit(0);
        }
        bytes_read += (size_t)ret;
    }

    ark_sys_close(fd);
    env->ReleaseStringUTFChars(source_dir_j, source_dir);

    /* 提取签名文件 */
    const unsigned char *sig_data = NULL;
    size_t sig_len = 0;

    if (!extract_signature_file(apk_buffer, apk_size, &sig_data, &sig_len)) {
        ARK_LOGE("[ArkSelfHash] 未找到签名文件");
        free(apk_buffer);
        exit(0);
    }

    /* 从签名文件中提取证书 SHA256 */
    if (!extract_cert_sha256(sig_data, sig_len, local_sha256)) {
        ARK_LOGE("[ArkSelfHash] 提取证书 SHA256 失败");
        free(apk_buffer);
        exit(0);
    }

    free(apk_buffer);

    /* 与预期 SHA256 进行比对 */
    char computed_hex[65];
    sha256_to_hex(local_sha256, computed_hex);

    /* 还原预期哈希字符串 */
    size_t expected_len = sizeof(
        "PLACEHOLDER_EXPECTED_SIGNATURE_SHA256_HEX_STRING"
    );
    char expected_hex[65];
    memset(expected_hex, 0, sizeof(expected_hex));

    if (expected_len >= sizeof(expected_hex)) {
        expected_len = sizeof(expected_hex) - 1;
    }

    xor_deobfuscate(expected_hex, (const unsigned char *)g_expected_sha256_hex, expected_len, g_key_xor_5a);

    ARK_LOGI("[ArkSelfHash] 计算证书 SHA256: %s", computed_hex);
    ARK_LOGI("[ArkSelfHash] 预期证书 SHA256: %s", expected_hex);

    if (strcmp(computed_hex, expected_hex) != 0) {
        ARK_LOGE("[ArkSelfHash] 签名不匹配, 退出");
        exit(0);
    }

    ARK_LOGI("[ArkSelfHash] 签名校验通过");

    /* 回写 SHA256 到 Java 层（用于派生加密密钥） */
    if (outSha256 != NULL) {
        jsize arr_len = env->GetArrayLength(outSha256);
        if (arr_len >= 32) {
            env->SetByteArrayRegion(
                outSha256,
                0,
                32,
                (jbyte *)local_sha256
            );
        }
    }

    return JNI_TRUE;
}
