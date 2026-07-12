#include "ArkEnvGuard.h"
#include "ArkDexLoader.h"

#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include <vector>
#include <dirent.h>
#include <limits.h>
#include <sys/syscall.h>
#include <cstdio>
#include <sys/system_properties.h>
#include <sys/stat.h>

#define LOG_TAG "ArkEnvGuard"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define XOR_KEY 0x5A
#define DEC(arr) decStr(arr, sizeof(arr))
#define DEBUG_PRINT_MAPS 1

static std::string decStr(const unsigned char *data, size_t len) {
    std::string out;
    out.resize(len);

    for (size_t i = 0; i < len; i++) {
        out[i] = (char) (data[i] ^ XOR_KEY);
    }

    return out;
}

static int safeOpenReadOnly(const char *path) {
    return (int) syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
}

static bool containsIgnoreCase(const std::string &text, const char *key) {
    if (key == nullptr) {
        return false;
    }

    std::string a = text;
    std::string b = key;

    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] >= 'A' && a[i] <= 'Z') {
            a[i] = a[i] - 'A' + 'a';
        }
    }

    for (size_t i = 0; i < b.size(); i++) {
        if (b[i] >= 'A' && b[i] <= 'Z') {
            b[i] = b[i] - 'A' + 'a';
        }
    }

    return a.find(b) != std::string::npos;
}

struct XorStr {
    const unsigned char *data;
    size_t len;
};

static bool fileExists(const char *path) {
    if (path == nullptr) {
        return false;
    }
    return access(path, F_OK) == 0;
}

static bool dirExists(const char *path) {
    if (path == nullptr) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

static bool checkProperty(const char *prop, const char *expected) {
    if (prop == nullptr || expected == nullptr) {
        return false;
    }
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(prop, value);
    if (len <= 0) {
        return false;
    }
    return strstr(value, expected) != nullptr;
}

static bool checkPkgDataDirExists(const unsigned char *pkgData, size_t pkgLen) {
    std::string pkgName = decStr(pkgData, pkgLen);

    std::string prefix("/data/data/");
    std::string fullPath = prefix + pkgName;

    return dirExists(fullPath.c_str());
}

// 明文：/memfd:jit-cache-zygisk_lsposed
static const unsigned char XP_FEATURE_0[] = {
        0x75, 0x37, 0x3F, 0x37, 0x3C, 0x3E, 0x60, 0x30,
        0x33, 0x2E, 0x77, 0x39, 0x3B, 0x39, 0x32, 0x3F,
        0x77, 0x20, 0x23, 0x3D, 0x33, 0x29, 0x31, 0x05,
        0x36, 0x29, 0x2A, 0x35, 0x29, 0x3F, 0x3E
};

// 明文：/data/adb/lspd
static const unsigned char XP_FEATURE_1[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3B,
        0x3E, 0x38, 0x75, 0x36, 0x29, 0x2A, 0x3E
};

// 明文：/data/adb/modules/zygisk_lsposed
static const unsigned char XP_FEATURE_2[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3B, 0x3E,
        0x38, 0x75, 0x37, 0x35, 0x3E, 0x2F, 0x36, 0x3F,
        0x29, 0x75, 0x20, 0x23, 0x3D, 0x33, 0x29, 0x31,
        0x05, 0x36, 0x29, 0x2A, 0x35, 0x29, 0x3F, 0x3E
};

// 明文：/data/adb/riru
static const unsigned char XP_FEATURE_3[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3B,
        0x3E, 0x38, 0x75, 0x28, 0x33, 0x28, 0x2F
};

// 明文：/data/adb/modules/riru
static const unsigned char XP_FEATURE_4[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3B, 0x3E,
        0x38, 0x75, 0x37, 0x35, 0x3E, 0x2F, 0x36, 0x3F,
        0x29, 0x75, 0x28, 0x33, 0x28, 0x2F
};

// 明文：liblsposed
static const unsigned char XP_FEATURE_5[] = {
        0x36, 0x33, 0x38, 0x36, 0x29, 0x2A, 0x35, 0x29, 0x3F, 0x3E
};

// 明文：libxposed
static const unsigned char XP_FEATURE_6[] = {
        0x36, 0x33, 0x38, 0x22, 0x2A, 0x35, 0x29, 0x3F, 0x3E
};

// 明文：libedxp
static const unsigned char XP_FEATURE_7[] = {
        0x36, 0x33, 0x38, 0x3F, 0x3E, 0x22, 0x2A
};

// 明文：libriru
static const unsigned char XP_FEATURE_8[] = {
        0x36, 0x33, 0x38, 0x28, 0x33, 0x28, 0x2F
};

// 明文：libzygisk
static const unsigned char XP_FEATURE_9[] = {
        0x36, 0x33, 0x38, 0x20, 0x23, 0x3D, 0x33, 0x29, 0x31
};



static const XorStr XP_FEATURES[] = {
        //{XP_FEATURE_0, sizeof(XP_FEATURE_0)},
        {XP_FEATURE_1, sizeof(XP_FEATURE_1)},
        {XP_FEATURE_2, sizeof(XP_FEATURE_2)},
        {XP_FEATURE_3, sizeof(XP_FEATURE_3)},
        {XP_FEATURE_4, sizeof(XP_FEATURE_4)},
        {XP_FEATURE_5, sizeof(XP_FEATURE_5)},
        {XP_FEATURE_6, sizeof(XP_FEATURE_6)},
        {XP_FEATURE_7, sizeof(XP_FEATURE_7)},
        {XP_FEATURE_8, sizeof(XP_FEATURE_8)},
        {XP_FEATURE_9, sizeof(XP_FEATURE_9)}
};

// 明文：/proc/self/fd
static const unsigned char STR_PROC_FD[] = {
        0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3F,
        0x36, 0x3C, 0x75, 0x3C, 0x3E
};

// 明文：/proc/self/fd/%s
static const unsigned char STR_PROC_FD_FORMAT[] = {
        0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3F,
        0x36, 0x3C, 0x75, 0x3C, 0x3E, 0x75, 0x7F, 0x29
};

// 明文：/proc/self/maps
static const unsigned char STR_PROC_MAPS[] = {
        0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3F,
        0x36, 0x3C, 0x75, 0x37, 0x3B, 0x2A, 0x29
};

// 明文：/proc/self/status
static const unsigned char STR_PROC_STATUS[] = {
        0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3F,
        0x36, 0x3C, 0x75, 0x29, 0x2E, 0x3B, 0x2E, 0x2F, 0x29
};

// 明文：de/robv/android/xposed/XposedBridge
static const unsigned char STR_XPOSED_BRIDGE[] = {
        0x3E, 0x3F, 0x75, 0x28, 0x35, 0x38, 0x2C, 0x75,
        0x3B, 0x34, 0x3E, 0x28, 0x35, 0x33, 0x3E, 0x75,
        0x22, 0x2A, 0x35, 0x29, 0x3F, 0x3E, 0x75, 0x02,
        0x2A, 0x35, 0x29, 0x3F, 0x3E, 0x18, 0x28, 0x33,
        0x3E, 0x3D, 0x3F
};

// 明文：java/lang/Throwable
static const unsigned char STR_THROWABLE[] = {
        0x30, 0x3B, 0x2C, 0x3B, 0x75, 0x36, 0x3B, 0x34,
        0x3D, 0x75, 0x0E, 0x32, 0x28, 0x35, 0x2D, 0x3B,
        0x38, 0x36, 0x3F
};

// 明文：<init>
static const unsigned char STR_INIT[] = {
        0x66, 0x33, 0x34, 0x33, 0x2E, 0x64
};

// 明文：()V
static const unsigned char STR_SIG_VOID[] = {
        0x72, 0x73, 0x0C
};

// 明文：getStackTrace
static const unsigned char STR_GET_STACK_TRACE[] = {
        0x3D, 0x3F, 0x2E, 0x09, 0x2E, 0x3B, 0x39,
        0x31, 0x0E, 0x28, 0x3B, 0x39, 0x3F
};

// 明文：()[Ljava/lang/StackTraceElement;
static const unsigned char STR_SIG_STACK_TRACE[] = {
        0x72, 0x73, 0x01, 0x16, 0x30, 0x3B, 0x2C, 0x3B,
        0x75, 0x36, 0x3B, 0x34, 0x3D, 0x75, 0x09, 0x2E,
        0x3B, 0x39, 0x31, 0x0E, 0x28, 0x3B, 0x39, 0x3F,
        0x1F, 0x36, 0x3F, 0x37, 0x3F, 0x34, 0x2E, 0x61
};

// 明文：java/lang/StackTraceElement
static const unsigned char STR_STACK_TRACE_ELEMENT[] = {
        0x30, 0x3B, 0x2C, 0x3B, 0x75, 0x36, 0x3B, 0x34,
        0x3D, 0x75, 0x09, 0x2E, 0x3B, 0x39, 0x31, 0x0E,
        0x28, 0x3B, 0x39, 0x3F, 0x1F, 0x36, 0x3F, 0x37,
        0x3F, 0x34, 0x2E
};

// 明文：toString
static const unsigned char STR_TO_STRING[] = {
        0x2E, 0x35, 0x09, 0x2E, 0x28, 0x33, 0x34, 0x3D
};

// 明文：()Ljava/lang/String;
static const unsigned char STR_SIG_STRING[] = {
        0x72, 0x73, 0x16, 0x30, 0x3B, 0x2C, 0x3B, 0x75,
        0x36, 0x3B, 0x34, 0x3D, 0x75, 0x09, 0x2E, 0x28,
        0x33, 0x34, 0x3D, 0x61
};

// 明文：/data/app/
static const unsigned char STR_DATA_APP[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3B, 0x2A, 0x2A, 0x75
};

// 明文：/base.apk
static const unsigned char STR_BASE_APK[] = {
        0x75, 0x38, 0x3B, 0x29, 0x3F, 0x74, 0x3B, 0x2A, 0x31
};

// 明文：getPackageName
static const unsigned char STR_GET_PACKAGE_NAME[] = {
        0x3D, 0x3F, 0x2E, 0x0A, 0x3B, 0x39, 0x31,
        0x3B, 0x3D, 0x3F, 0x14, 0x3B, 0x37, 0x3F
};

// ==================== Root 检测 XOR 字符串 ====================

// 明文：/system/app/Superuser.apk
static const unsigned char ROOT_SU_APK[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x3B, 0x2A, 0x2A, 0x75, 0x09, 0x2F, 0x2A, 0x3F,
        0x28, 0x2F, 0x29, 0x3F, 0x28, 0x74, 0x3B, 0x2A, 0x31
};

// 明文：/sbin/su
static const unsigned char ROOT_SBIN_SU[] = {
        0x75, 0x29, 0x38, 0x33, 0x34, 0x75, 0x29, 0x2F
};

// 明文：/system/bin/su
static const unsigned char ROOT_BIN_SU[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x38, 0x33, 0x34, 0x75, 0x29, 0x2F
};

// 明文：/system/xbin/su
static const unsigned char ROOT_XBIN_SU[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x22, 0x38, 0x33, 0x34, 0x75, 0x29, 0x2F
};

// 明文：/data/local/xbin/su
static const unsigned char ROOT_LOCAL_XBIN_SU[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x36, 0x35,
        0x39, 0x3B, 0x36, 0x75, 0x22, 0x38, 0x33, 0x34,
        0x75, 0x29, 0x2F
};

// 明文：/data/local/bin/su
static const unsigned char ROOT_LOCAL_BIN_SU[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x36, 0x35,
        0x39, 0x3B, 0x36, 0x75, 0x38, 0x33, 0x34, 0x75,
        0x29, 0x2F
};

// 明文：/system/sd/xbin/su
static const unsigned char ROOT_SD_XBIN_SU[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x29, 0x3E, 0x75, 0x22, 0x38, 0x33, 0x34, 0x75,
        0x29, 0x2F
};

// 明文：/system/bin/failsafe/su
static const unsigned char ROOT_FAILSAFE_SU[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x38, 0x33, 0x34, 0x75, 0x3C, 0x3B, 0x33, 0x36,
        0x29, 0x3B, 0x3C, 0x3F, 0x75, 0x29, 0x2F
};

// 明文：/system/usr/we-need-root/
static const unsigned char ROOT_WE_NEED[] = {
        0x75, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x75,
        0x2F, 0x29, 0x28, 0x75, 0x2D, 0x3F, 0x77, 0x34,
        0x3F, 0x3F, 0x3E, 0x77, 0x28, 0x35, 0x35, 0x2E, 0x75
};

// 明文：magisk
static const unsigned char ROOT_MAGISK[] = {
        0x37, 0x3B, 0x3D, 0x33, 0x29, 0x31
};

// 明文：magiskhide
static const unsigned char ROOT_MAGISKHIDE[] = {
        0x37, 0x3B, 0x3D, 0x33, 0x29, 0x31, 0x32, 0x33, 0x3E, 0x3F
};

// 明文：com.noshufou.android.su
static const unsigned char ROOT_PKG_1[] = {
        0x39, 0x35, 0x37, 0x74, 0x34, 0x35, 0x29, 0x32,
        0x2F, 0x3C, 0x35, 0x2F, 0x74, 0x3B, 0x34, 0x3E,
        0x28, 0x35, 0x33, 0x3E, 0x74, 0x29, 0x2F
};

// 明文：com.thirdparty.superuser
static const unsigned char ROOT_PKG_2[] = {
        0x39, 0x35, 0x37, 0x74, 0x2E, 0x32, 0x33, 0x28,
        0x3E, 0x2A, 0x3B, 0x28, 0x2E, 0x23, 0x74, 0x29,
        0x2F, 0x2A, 0x3F, 0x28, 0x2F, 0x29, 0x3F, 0x28
};

// 明文：eu.chainfire.supersu
static const unsigned char ROOT_PKG_3[] = {
        0x3F, 0x2F, 0x74, 0x39, 0x32, 0x3B, 0x33, 0x34,
        0x3C, 0x33, 0x28, 0x3F, 0x74, 0x29, 0x2F, 0x2A,
        0x3F, 0x28, 0x29, 0x2F
};

// 明文：com.koushikdutta.superuser
static const unsigned char ROOT_PKG_4[] = {
        0x39, 0x35, 0x37, 0x74, 0x31, 0x35, 0x2F, 0x29,
        0x32, 0x33, 0x31, 0x3E, 0x2F, 0x2E, 0x2E, 0x3B,
        0x74, 0x29, 0x2F, 0x2A, 0x3F, 0x28, 0x2F, 0x29,
        0x3F, 0x28
};

// 明文：com.topjohnwu.magisk
static const unsigned char ROOT_PKG_5[] = {
        0x39, 0x35, 0x37, 0x74, 0x2E, 0x35, 0x2A, 0x30,
        0x35, 0x32, 0x34, 0x2D, 0x2F, 0x74, 0x37, 0x3B,
        0x3D, 0x33, 0x29, 0x31
};

// ==================== 虚拟环境检测 XOR 字符串 ====================

// 明文：/data/data/com.lbe.parallel.intl
static const unsigned char VIRT_PKG_1[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3E, 0x3B,
        0x2E, 0x3B, 0x75, 0x39, 0x35, 0x37, 0x74, 0x36,
        0x38, 0x3F, 0x74, 0x2A, 0x3B, 0x28, 0x3B, 0x36,
        0x36, 0x3F, 0x36, 0x74, 0x33, 0x34, 0x2E, 0x36
};

// 明文：/data/data/com.excelliance.multiaccounts
static const unsigned char VIRT_PKG_2[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3E, 0x3B,
        0x2E, 0x3B, 0x75, 0x39, 0x35, 0x37, 0x74, 0x3F,
        0x22, 0x39, 0x3F, 0x36, 0x36, 0x33, 0x3B, 0x34,
        0x39, 0x3F, 0x74, 0x37, 0x2F, 0x36, 0x2E, 0x33,
        0x3B, 0x39, 0x39, 0x35, 0x2F, 0x34, 0x2E, 0x29
};

// 明文：/data/data/com.lody.virtual
static const unsigned char VIRT_PKG_3[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x3E, 0x3B,
        0x2E, 0x3B, 0x75, 0x39, 0x35, 0x37, 0x74, 0x36,
        0x35, 0x3E, 0x23, 0x74, 0x2C, 0x33, 0x28, 0x2E,
        0x2F, 0x3B, 0x36
};

// 明文：libva++.so
static const unsigned char VIRT_LIB_1[] = {
        0x36, 0x33, 0x38, 0x2C, 0x3B, 0x71, 0x71, 0x74, 0x29, 0x35
};

// 明文：libva-native.so
static const unsigned char VIRT_LIB_2[] = {
        0x36, 0x33, 0x38, 0x2C, 0x3B, 0x77, 0x34, 0x3B,
        0x2E, 0x33, 0x2C, 0x3F, 0x74, 0x29, 0x35
};

// ==================== 脱壳工具检测 XOR 字符串 ====================

// 明文：/data/local/tmp/frida-server
static const unsigned char FRIDA_SERVER[] = {
        0x75, 0x3E, 0x3B, 0x2E, 0x3B, 0x75, 0x36, 0x35,
        0x39, 0x3B, 0x36, 0x75, 0x2E, 0x37, 0x2A, 0x75,
        0x3C, 0x28, 0x33, 0x3E, 0x3B, 0x77, 0x29, 0x3F,
        0x28, 0x2C, 0x3F, 0x28
};

// 明文：libsubstrate.so
static const unsigned char SUBSTRATE_LIB_1[] = {
        0x36, 0x33, 0x38, 0x29, 0x2F, 0x38, 0x29, 0x2E,
        0x28, 0x3B, 0x2E, 0x3F, 0x74, 0x29, 0x35
};

// 明文：libsubstrate-dvm.so
static const unsigned char SUBSTRATE_LIB_2[] = {
        0x36, 0x33, 0x38, 0x29, 0x2F, 0x38, 0x29, 0x2E,
        0x28, 0x3B, 0x2E, 0x3F, 0x77, 0x3E, 0x2C, 0x37,
        0x74, 0x29, 0x35
};

// ==================== Web 脱壳检测 XOR 字符串 ====================

// 明文：ro.debuggable
static const unsigned char SYS_DEBUGGABLE[] = {
        0x28, 0x35, 0x74, 0x3E, 0x3F, 0x38, 0x2F, 0x3D,
        0x3D, 0x3B, 0x38, 0x36, 0x3F
};

// 明文：init.svc.adbd
static const unsigned char SYS_ADBD[] = {
        0x33, 0x34, 0x33, 0x2E, 0x74, 0x29, 0x2C,
        0x39, 0x74, 0x3B, 0x3E, 0x38, 0x3E
};

// 明文：TracerPid
static const unsigned char STR_TRACER_PID[] = {
        0x0E, 0x28, 0x3B, 0x39, 0x3F, 0x28, 0x0A, 0x33, 0x3E
};

// 明文：setWebContentsDebuggingEnabled
static const unsigned char STR_WEBVIEW_DEBUG_METHOD[] = {
        0x29, 0x3F, 0x2E, 0x0D, 0x3F, 0x38, 0x19, 0x35,
        0x34, 0x2E, 0x3F, 0x34, 0x2E, 0x29, 0x1E, 0x3F,
        0x38, 0x2F, 0x3D, 0x3D, 0x33, 0x34, 0x3D, 0x1F,
        0x34, 0x3B, 0x38, 0x36, 0x3F, 0x3E
};

// 明文：(Z)V
static const unsigned char STR_SIG_ZWEB_V[] = {
        0x72, 0x00, 0x73, 0x0C
};

// 明文：android/webkit/WebView
static const unsigned char STR_WEBVIEW_CLASS[] = {
        0x3B, 0x34, 0x3E, 0x28, 0x35, 0x33, 0x3E, 0x75,
        0x2D, 0x3F, 0x38, 0x31, 0x33, 0x2E, 0x75, 0x0D,
        0x3F, 0x38, 0x0C, 0x33, 0x3F, 0x2D
};

// 明文：isDebuggable
static const unsigned char STR_IS_DEBUGGABLE[] = {
        0x33, 0x29, 0x1E, 0x3F, 0x38, 0x2F, 0x3D, 0x3D,
        0x3B, 0x38, 0x36, 0x3F
};

// 明文：android/os/Process
static const unsigned char STR_PROCESS_CLASS[] = {
        0x3B, 0x34, 0x3E, 0x28, 0x35, 0x33, 0x3E, 0x75,
        0x35, 0x29, 0x75, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29
};

// 明文：myPid
static const unsigned char STR_MY_PID[] = {
        0x37, 0x23, 0x0A, 0x33, 0x3E
};

// 明文：()I
static const unsigned char STR_SIG_I[] = {
        0x72, 0x73, 0x13
};

// 明文：/proc/%d/cmdline
static const unsigned char STR_PROC_CMDLINE_FMT[] = {
        0x75, 0x2A, 0x28, 0x35, 0x39, 0x75, 0x7F, 0x3E,
        0x75, 0x39, 0x37, 0x3E, 0x36, 0x33, 0x34, 0x3F
};

static std::string getCurrentPackageName(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return "";
    }

    jclass clsContext = env->GetObjectClass(context);
    if (clsContext == nullptr) {
        env->ExceptionClear();
        return "";
    }

    std::string methodName = DEC(STR_GET_PACKAGE_NAME);
    std::string methodSig = DEC(STR_SIG_STRING);

    jmethodID midGetPackageName = env->GetMethodID(
            clsContext,
            methodName.c_str(),
            methodSig.c_str()
    );

    if (midGetPackageName == nullptr) {
        env->ExceptionClear();
        return "";
    }

    jstring packageNameJ = (jstring) env->CallObjectMethod(context, midGetPackageName);
    if (env->ExceptionCheck() || packageNameJ == nullptr) {
        env->ExceptionClear();
        return "";
    }

    const char *packageName = env->GetStringUTFChars(packageNameJ, nullptr);
    if (packageName == nullptr) {
        env->DeleteLocalRef(packageNameJ);
        return "";
    }

    std::string result(packageName);

    env->ReleaseStringUTFChars(packageNameJ, packageName);
    env->DeleteLocalRef(packageNameJ);

    return result;
}

static bool checkThirdPartyApkInjected(JNIEnv *env, jobject context, const std::string &line) {
    std::string dataApp = DEC(STR_DATA_APP);
    std::string baseApk = DEC(STR_BASE_APK);

    if (!containsIgnoreCase(line, dataApp.c_str())) {
        return false;
    }

    if (!containsIgnoreCase(line, baseApk.c_str())) {
        return false;
    }

    std::string currentPackage = getCurrentPackageName(env, context);
    if (!currentPackage.empty() && containsIgnoreCase(line, currentPackage.c_str())) {
        return false;
    }

    //LOGE("检测到第三方 APK 注入");
    //LOGE("当前包名：%s", currentPackage.c_str());
    //LOGE("命中maps：%s", line.c_str());

    return true;
}
static std::string findMatchedFeature(const std::string &text) {
    for (size_t i = 0; i < sizeof(XP_FEATURES) / sizeof(XP_FEATURES[0]); i++) {
        std::string feature = decStr(XP_FEATURES[i].data, XP_FEATURES[i].len);

        if (containsIgnoreCase(text, feature.c_str())) {
            return feature;
        }
    }

    return "";
}

static bool checkFdForXp() {
    std::string procFd = DEC(STR_PROC_FD);

    DIR *dir = opendir(procFd.c_str());
    if (dir == nullptr) {
        //LOGE("打开 /proc/self/fd 失败");
        return false;
    }

    struct dirent *entry;
    char linkPath[PATH_MAX];
    char realPath[PATH_MAX];

    std::string procFdFormat = DEC(STR_PROC_FD_FORMAT);

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(linkPath, sizeof(linkPath), procFdFormat.c_str(), entry->d_name);

        ssize_t len = readlink(linkPath, realPath, sizeof(realPath) - 1);
        if (len <= 0) {
            continue;
        }

        realPath[len] = '\0';

        std::string s(realPath);
        std::string matched = findMatchedFeature(s);

        if (!matched.empty()) {
            //LOGE("检测到 fd 特征");
            //LOGE("命中特征：%s", matched.c_str());
            //LOGE("命中fd：%s -> %s", linkPath, realPath);

            closedir(dir);
            return true;
        }
    }

    closedir(dir);
    return false;
}

static bool checkMapsForXp(JNIEnv *env, jobject context) {
    std::string procMaps = DEC(STR_PROC_MAPS);

    int fd = safeOpenReadOnly(procMaps.c_str());
    if (fd < 0) {
        //LOGE("syscall打开 /proc/self/maps 失败");
        return false;
    }

    char buffer[4096];
    std::string cache;

    while (true) {
        ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (readSize <= 0) {
            break;
        }

        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            if (checkThirdPartyApkInjected(env, context, line)) {
                syscall(__NR_close, fd);
                return true;
            }

            #if DEBUG_PRINT_MAPS
                //LOGE("maps行：%s", line.c_str());
            #endif

            std::string matched = findMatchedFeature(line);
            if (!matched.empty()) {
                //LOGE("检测到 maps 特征");
                //LOGE("命中特征：%s", matched.c_str());
                //LOGE("命中maps：%s", line.c_str());

                syscall(__NR_close, fd);
                return true;
            }
        }
    }

    if (!cache.empty()) {
        if (checkThirdPartyApkInjected(env, context, cache)) {
            syscall(__NR_close, fd);
            return true;
        }
        std::string matched = findMatchedFeature(cache);
        if (!matched.empty()) {
            //LOGE("检测到 maps 特征");
            //LOGE("命中特征：%s", matched.c_str());
            //LOGE("命中maps：%s", cache.c_str());

            syscall(__NR_close, fd);
            return true;
        }
    }

    syscall(__NR_close, fd);
    return false;
}

static bool checkXposedBridgeClass(JNIEnv *env) {
    if (env == nullptr) {
        return false;
    }

    std::string xposedBridgeClass = DEC(STR_XPOSED_BRIDGE);

    jclass cls = env->FindClass(xposedBridgeClass.c_str());
    if (cls != nullptr) {
        env->DeleteLocalRef(cls);

        //LOGE("检测到 Java 类特征");
        //LOGE("命中特征：de.robv.android.xposed.XposedBridge");

        return true;
    }

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    return false;
}

static bool checkStackForXp(JNIEnv *env) {
    if (env == nullptr) {
        return false;
    }

    std::string throwableClass = DEC(STR_THROWABLE);
    jclass clsThrowable = env->FindClass(throwableClass.c_str());

    if (clsThrowable == nullptr) {
        env->ExceptionClear();
        return false;
    }

    std::string initName = DEC(STR_INIT);
    std::string sigVoid = DEC(STR_SIG_VOID);

    jmethodID midInit = env->GetMethodID(
            clsThrowable,
            initName.c_str(),
            sigVoid.c_str()
    );

    std::string getStackTraceName = DEC(STR_GET_STACK_TRACE);
    std::string getStackTraceSig = DEC(STR_SIG_STACK_TRACE);

    jmethodID midGetStackTrace = env->GetMethodID(
            clsThrowable,
            getStackTraceName.c_str(),
            getStackTraceSig.c_str()
    );

    if (midInit == nullptr || midGetStackTrace == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject throwable = env->NewObject(clsThrowable, midInit);
    if (throwable == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobjectArray stackArray = (jobjectArray) env->CallObjectMethod(throwable, midGetStackTrace);
    if (env->ExceptionCheck() || stackArray == nullptr) {
        env->ExceptionClear();
        return false;
    }

    std::string stackTraceElementClass = DEC(STR_STACK_TRACE_ELEMENT);
    jclass clsStackTraceElement = env->FindClass(stackTraceElementClass.c_str());

    std::string toStringName = DEC(STR_TO_STRING);
    std::string sigString = DEC(STR_SIG_STRING);

    jmethodID midToString = env->GetMethodID(
            clsStackTraceElement,
            toStringName.c_str(),
            sigString.c_str()
    );

    if (midToString == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jsize count = env->GetArrayLength(stackArray);

    for (jsize i = 0; i < count; i++) {
        jobject item = env->GetObjectArrayElement(stackArray, i);
        if (item == nullptr) {
            continue;
        }

        jstring textJ = (jstring) env->CallObjectMethod(item, midToString);
        if (textJ == nullptr) {
            env->DeleteLocalRef(item);
            continue;
        }

        const char *text = env->GetStringUTFChars(textJ, nullptr);
        if (text != nullptr) {
            std::string s(text);

            env->ReleaseStringUTFChars(textJ, text);

            std::string matched = findMatchedFeature(s);
            if (!matched.empty()) {
                //LOGE("检测到调用栈特征");
                //LOGE("命中特征：%s", matched.c_str());
                //LOGE("命中堆栈：%s", s.c_str());

                env->DeleteLocalRef(textJ);
                env->DeleteLocalRef(item);
                return true;
            }
        }

        env->DeleteLocalRef(textJ);
        env->DeleteLocalRef(item);
    }

    return false;
}

// ==================== 新增：Root 检测 ====================

static bool checkRootSuFiles() {
    static const unsigned char *rootPaths[] = {
            ROOT_SU_APK, ROOT_SBIN_SU, ROOT_BIN_SU, ROOT_XBIN_SU,
            ROOT_LOCAL_XBIN_SU, ROOT_LOCAL_BIN_SU, ROOT_SD_XBIN_SU, ROOT_FAILSAFE_SU
    };
    static const size_t rootPathLens[] = {
            sizeof(ROOT_SU_APK), sizeof(ROOT_SBIN_SU), sizeof(ROOT_BIN_SU), sizeof(ROOT_XBIN_SU),
            sizeof(ROOT_LOCAL_XBIN_SU), sizeof(ROOT_LOCAL_BIN_SU), sizeof(ROOT_SD_XBIN_SU), sizeof(ROOT_FAILSAFE_SU)
    };

    for (size_t i = 0; i < sizeof(rootPaths) / sizeof(rootPaths[0]); i++) {
        std::string path = decStr(rootPaths[i], rootPathLens[i]);
        if (fileExists(path.c_str())) {
            //LOGE("检测到 Root 特征文件: %s", path.c_str());
            return true;
        }
    }

    std::string weNeedRoot = decStr(ROOT_WE_NEED, sizeof(ROOT_WE_NEED));
    if (dirExists(weNeedRoot.c_str())) {
        //LOGE("检测到 Root 特征目录: %s", weNeedRoot.c_str());
        return true;
    }

    return false;
}

static bool checkRootPackages() {
    static const unsigned char *rootPkgs[] = {
            ROOT_PKG_1, ROOT_PKG_2, ROOT_PKG_3, ROOT_PKG_4, ROOT_PKG_5
    };
    static const size_t rootPkgLens[] = {
            sizeof(ROOT_PKG_1), sizeof(ROOT_PKG_2), sizeof(ROOT_PKG_3),
            sizeof(ROOT_PKG_4), sizeof(ROOT_PKG_5)
    };

    for (size_t i = 0; i < sizeof(rootPkgs) / sizeof(rootPkgs[0]); i++) {
        if (checkPkgDataDirExists(rootPkgs[i], rootPkgLens[i])) {
            return true;
        }
    }

    return false;
}

static bool checkMapsForMagisk() {
    std::string procMaps = DEC(STR_PROC_MAPS);

    int fd = safeOpenReadOnly(procMaps.c_str());
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    std::string cache;
    std::string magiskStr = decStr(ROOT_MAGISK, sizeof(ROOT_MAGISK));
    std::string magiskHideStr = decStr(ROOT_MAGISKHIDE, sizeof(ROOT_MAGISKHIDE));

    while (true) {
        ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (readSize <= 0) {
            break;
        }

        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            if (containsIgnoreCase(line, magiskStr.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到 maps 中 magisk 特征: %s", line.c_str());
                return true;
            }

            if (containsIgnoreCase(line, magiskHideStr.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到 maps 中 magiskhide 特征: %s", line.c_str());
                return true;
            }
        }
    }

    if (!cache.empty()) {
        if (containsIgnoreCase(cache, magiskStr.c_str()) ||
            containsIgnoreCase(cache, magiskHideStr.c_str())) {
            syscall(__NR_close, fd);
            return true;
        }
    }

    syscall(__NR_close, fd);
    return false;
}

static bool ArkEnvGuard_DetectRoot(JNIEnv *env) {
    if (env == nullptr) {
        return false;
    }

    if (checkRootSuFiles()) {
        //LOGE("检测到 Root 环境 (su 文件)");
        return true;
    }

    if (checkRootPackages()) {
        //LOGE("检测到 Root 管理应用");
        return true;
    }

    if (checkMapsForMagisk()) {
        //LOGE("检测到 Magisk 特征");
        return true;
    }

    return false;
}

// ==================== 新增：虚拟环境/分身检测 ====================

static bool checkVirtualAppDirs() {
    static const unsigned char *virtPaths[] = {
            VIRT_PKG_1, VIRT_PKG_2, VIRT_PKG_3
    };
    static const size_t virtPathLens[] = {
            sizeof(VIRT_PKG_1), sizeof(VIRT_PKG_2), sizeof(VIRT_PKG_3)
    };

    for (size_t i = 0; i < sizeof(virtPaths) / sizeof(virtPaths[0]); i++) {
        std::string path = decStr(virtPaths[i], virtPathLens[i]);
        if (dirExists(path.c_str())) {
            //LOGE("检测到虚拟环境目录: %s", path.c_str());
            return true;
        }
    }

    return false;
}

static bool checkMapsForVirtualLibs() {
    std::string procMaps = DEC(STR_PROC_MAPS);

    int fd = safeOpenReadOnly(procMaps.c_str());
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    std::string cache;
    std::string libVa1 = decStr(VIRT_LIB_1, sizeof(VIRT_LIB_1));
    std::string libVa2 = decStr(VIRT_LIB_2, sizeof(VIRT_LIB_2));

    while (true) {
        ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (readSize <= 0) {
            break;
        }

        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            if (containsIgnoreCase(line, libVa1.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到虚拟环境库: %s", line.c_str());
                return true;
            }

            if (containsIgnoreCase(line, libVa2.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到虚拟环境库: %s", line.c_str());
                return true;
            }
        }
    }

    if (!cache.empty()) {
        if (containsIgnoreCase(cache, libVa1.c_str()) ||
            containsIgnoreCase(cache, libVa2.c_str())) {
            syscall(__NR_close, fd);
            return true;
        }
    }

    syscall(__NR_close, fd);
    return false;
}

static bool checkSubstrateLibs() {
    std::string procMaps = DEC(STR_PROC_MAPS);

    int fd = safeOpenReadOnly(procMaps.c_str());
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    std::string cache;
    std::string sub1 = decStr(SUBSTRATE_LIB_1, sizeof(SUBSTRATE_LIB_1));
    std::string sub2 = decStr(SUBSTRATE_LIB_2, sizeof(SUBSTRATE_LIB_2));

    while (true) {
        ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (readSize <= 0) {
            break;
        }

        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            if (containsIgnoreCase(line, sub1.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到 Substrate 库: %s", line.c_str());
                return true;
            }

            if (containsIgnoreCase(line, sub2.c_str())) {
                syscall(__NR_close, fd);
                //LOGE("检测到 Substrate 库: %s", line.c_str());
                return true;
            }
        }
    }

    if (!cache.empty()) {
        if (containsIgnoreCase(cache, sub1.c_str()) ||
            containsIgnoreCase(cache, sub2.c_str())) {
            syscall(__NR_close, fd);
            return true;
        }
    }

    syscall(__NR_close, fd);
    return false;
}

static bool checkFridaPresence() {
    std::string fridaPath = decStr(FRIDA_SERVER, sizeof(FRIDA_SERVER));
    if (fileExists(fridaPath.c_str())) {
        //LOGE("检测到 Frida Server: %s", fridaPath.c_str());
        return true;
    }

    std::string procMaps = DEC(STR_PROC_MAPS);
    int fd = safeOpenReadOnly(procMaps.c_str());
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    std::string cache;

    while (true) {
        ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (readSize <= 0) {
            break;
        }
        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            if (containsIgnoreCase(line, "frida") || containsIgnoreCase(line, "gum-js")) {
                syscall(__NR_close, fd);
                //LOGE("检测到 Frida 特征: %s", line.c_str());
                return true;
            }
        }
    }

    if (!cache.empty()) {
        if (containsIgnoreCase(cache, "frida") || containsIgnoreCase(cache, "gum-js")) {
            syscall(__NR_close, fd);
            return true;
        }
    }

    syscall(__NR_close, fd);
    return false;
}

static bool ArkEnvGuard_DetectVirtual() {
    if (checkVirtualAppDirs()) {
        //LOGE("检测到虚拟环境 (应用目录)");
        return true;
    }

    if (checkMapsForVirtualLibs()) {
        //LOGE("检测到虚拟环境 (库特征)");
        return true;
    }

    if (checkSubstrateLibs()) {
        //LOGE("检测到 Substrate 注入");
        return true;
    }

    if (checkFridaPresence()) {
        //LOGE("检测到 Frida");
        return true;
    }

    return false;
}

// ==================== 新增：Web 脱壳检测 ====================

static bool checkDebuggerConnected() {
    std::string procStatus = DEC(STR_PROC_STATUS);

    int fd = safeOpenReadOnly(procStatus.c_str());
    if (fd < 0) {
        return false;
    }

    char buffer[1024];
    ssize_t readSize = syscall(__NR_read, fd, buffer, sizeof(buffer) - 1);
    syscall(__NR_close, fd);

    if (readSize <= 0) {
        return false;
    }

    buffer[readSize] = '\0';
    std::string content(buffer);
    std::string tracerPidKey = DEC(STR_TRACER_PID);

    size_t pos = content.find(tracerPidKey);
    if (pos == std::string::npos) {
        return false;
    }

    pos += tracerPidKey.size();
    while (pos < content.size() && (content[pos] == ':' || content[pos] == '\t' || content[pos] == ' ')) {
        pos++;
    }

    std::string value;
    while (pos < content.size() && content[pos] >= '0' && content[pos] <= '9') {
        value += content[pos];
        pos++;
    }

    if (!value.empty() && value != "0") {
        //LOGE("检测到调试器连接: TracerPid=%s", value.c_str());
        return true;
    }

    return false;
}

static bool checkSystemDebuggable() {
    std::string debuggableProp = DEC(SYS_DEBUGGABLE);
    std::string adbdProp = DEC(SYS_ADBD);

    if (checkProperty(debuggableProp.c_str(), "1")) {
        //LOGE("检测到系统 ro.debuggable=1");
        return true;
    }

    if (checkProperty(adbdProp.c_str(), "running")) {
        //LOGE("检测到 adbd 正在运行");
        return true;
    }

    return false;
}

static bool checkWebViewContext(JNIEnv *env) {
    if (env == nullptr) {
        return false;
    }

    std::string webViewClass = DEC(STR_WEBVIEW_CLASS);
    std::string isDebuggableStr = DEC(STR_IS_DEBUGGABLE);
    std::string sigString = DEC(STR_SIG_STRING);

    jclass clsWebView = env->FindClass(webViewClass.c_str());
    if (clsWebView == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midIsDebuggable = env->GetStaticMethodID(
            clsWebView,
            isDebuggableStr.c_str(),
            sigString.c_str()
    );

    if (midIsDebuggable == nullptr) {
        env->ExceptionClear();
        return false;
    }

    return true;
}

static bool checkAppProcessCmdline() {
    std::string cmdlineFmt = DEC(STR_PROC_CMDLINE_FMT);
    pid_t pid = getpid();

    char cmdlinePath[128];
    snprintf(cmdlinePath, sizeof(cmdlinePath), cmdlineFmt.c_str(), (int) pid);

    int fd = safeOpenReadOnly(cmdlinePath);
    if (fd < 0) {
        return false;
    }

    char cmdlineBuf[512] = {0};
    ssize_t len = syscall(__NR_read, fd, cmdlineBuf, sizeof(cmdlineBuf) - 1);
    syscall(__NR_close, fd);

    if (len <= 0) {
        return false;
    }

    std::string cmdline(cmdlineBuf, len);
    if (containsIgnoreCase(cmdline, "webview") ||
        containsIgnoreCase(cmdline, "chromium") ||
        containsIgnoreCase(cmdline, "sandboxed_process")) {
        //LOGE("检测到 WebView 进程: %s", cmdline.c_str());
        return true;
    }

    return false;
}

static bool ArkEnvGuard_DetectWebUnpack(JNIEnv *env) {
    if (checkDebuggerConnected()) {
        //LOGE("检测到调试器连接");
        return true;
    }

    if (checkSystemDebuggable()) {
        //LOGE("检测到系统调试属性");
        return true;
    }

    if (checkWebViewContext(env)) {
        //LOGE("检测到 WebView isDebuggable 可用");
        return true;
    }

    if (checkAppProcessCmdline()) {
        //LOGE("检测到 WebView 沙箱进程");
        return true;
    }

    return false;
}

// ==================== 原有：XP/LSP 检测 ====================

static bool ArkEnvGuard_DetectXp(JNIEnv *env, jobject context) {
    if (checkMapsForXp(env, context)) {
        //LOGE("检测到 maps 中存在 XP/LSPosed 特征");
        return true;
    }

    if (checkXposedBridgeClass(env)) {
        //LOGE("检测到 XposedBridge 类");
        return true;
    }

    if (checkStackForXp(env)) {
        //LOGE("检测到调用栈中存在 XP/LSPosed 特征");
        return true;
    }

    if (checkFdForXp()) {
        //LOGE("检测到 fd 中存在 XP/LSPosed 特征");
        return true;
    }

    return false;
}

// ==================== 新增：完整环境检测 ====================

static bool ArkEnvGuard_DetectAll(JNIEnv *env, jobject context) {
    if (ArkEnvGuard_DetectRoot(env)) {
        //LOGE("完整检测: Root 环境不通过");
        return true;
    }

    if (ArkEnvGuard_DetectVirtual()) {
        //LOGE("完整检测: 虚拟环境/脱壳不通过");
        return true;
    }

    if (ArkEnvGuard_DetectWebUnpack(env)) {
        //LOGE("完整检测: Web 脱壳环境不通过");
        return true;
    }

    if (ArkEnvGuard_DetectXp(env, context)) {
        //LOGE("完整检测: XP/LSPosed 环境不通过");
        return true;
    }

    return false;
}

// ==================== 修改：CheckAndLoad 集成所有检测 ====================

static bool ArkEnvGuard_CheckAndLoad_Impl(JNIEnv *env, jobject context) {
    //LOGI("进入 ArkEnvGuard_CheckAndLoad_Impl");

    if (env == nullptr || context == nullptr) {
        //LOGE("env或context为空");
        return false;
    }

    ArkDexLoaderFunc loaderFunc = ArkDexLoader_GetEntry();
    if (loaderFunc == nullptr) {
        //LOGE("获取LoaderDEX入口失败");
        return false;
    }

    if (ArkEnvGuard_DetectRoot(env)) {
        //LOGE("环境检测(Root)不通过，停止加载DEX");
        return false;
    }

    if (ArkEnvGuard_DetectVirtual()) {
        //LOGE("环境检测(虚拟/脱壳)不通过，停止加载DEX");
        return false;
    }

    if (ArkEnvGuard_DetectWebUnpack(env)) {
        //LOGE("环境检测(Web脱壳)不通过，停止加载DEX");
        return false;
    }

    if (ArkEnvGuard_DetectXp(env, context)) {
        //LOGE("环境检测(XP/LSP)不通过，停止加载DEX");
        return false;
    }

    //LOGI("开始通过函数指针调用LoaderDEX");
    return loaderFunc(env, context);
}

/**
 * 启动真实 Application 的环境检测入口
 *
 * 【新增修复】
 * 给 StubApp.onCreate 调用。
 */
static bool ArkEnvGuard_StartRealApplication_Impl(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return false;
    }

    if (ArkEnvGuard_DetectRoot(env)) {
        return false;
    }

    if (ArkEnvGuard_DetectVirtual()) {
        return false;
    }

    if (ArkEnvGuard_DetectWebUnpack(env)) {
        return false;
    }

    if (ArkEnvGuard_DetectXp(env, context)) {
        return false;
    }

    ArkRealApplicationStarterFunc starterFunc =
            ArkDexLoader_GetStartRealApplicationEntry();

    if (starterFunc == nullptr) {
        return false;
    }

    return starterFunc(env, context);
}

// ==================== 完整检测入口 ====================

static bool ArkEnvGuard_FullGuard_Impl(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return false;
    }

    if (ArkEnvGuard_DetectAll(env, context)) {
        return false;
    }

    return true;
}

ArkEnvGuardFunc ArkEnvGuard_GetEntry() {
    volatile ArkEnvGuardFunc fn = ArkEnvGuard_CheckAndLoad_Impl;
    return fn;
}

ArkEnvGuardFunc ArkEnvGuard_GetStartRealApplicationEntry() {
    volatile ArkEnvGuardFunc fn = ArkEnvGuard_StartRealApplication_Impl;
    return fn;
}

ArkEnvGuardFunc ArkEnvGuard_GetFullGuardEntry() {
    volatile ArkEnvGuardFunc fn = ArkEnvGuard_FullGuard_Impl;
    return fn;
}
