#include "ArkVMP.h"
#include "VmpRuntime.h"

#include <string>
#include <cstring>
#include <android/log.h>
#include <pthread.h>

#define LOG_TAG "ArkVMP_ArkVMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ================================================================
 * 企业伪装配置
 * ================================================================ */

/* 伪装类型枚举 */
enum ArkDisguiseType {
    ARK_DISGUISE_DEFAULT    = 0,  /* 默认: 加固工具信息 */
    ARK_DISGUISE_ENTERPRISE = 1,  /* 企业A: 通用企业级应用 */
    ARK_DISGUISE_FINTECH    = 2,  /* 金融科技 */
    ARK_DISGUISE_GAME       = 3,  /* 游戏引擎 */
    ARK_DISGUISE_SOCIAL     = 4,  /* 社交通信 */
    ARK_DISGUISE_ECOMMERCE  = 5,  /* 电商平台 */
    ARK_DISGUISE_CUSTOM     = 99  /* 自定义 */
};

/* 伪装备配置的锁 */
static pthread_mutex_t g_disguise_mutex = PTHREAD_MUTEX_INITIALIZER;
static ArkDisguiseType g_disguise_type = ARK_DISGUISE_DEFAULT;
static std::string g_custom_section_text;
static bool g_disguise_initialized = false;

/* 默认 section 内容 (加固工具原作者信息) */
static const char *g_default_section_text =
    "Ark是一款开源离线免费加固工具，支持dex加密/VMP抽代码/签名校验等，"
    "加固工具作者QQ2380494437_By菜鸟八哥。";

/* 各伪装类型的 section 文本 */
static const char *g_enterprise_section_text =
    "Enterprise Application Security Module v3.2.1 "
    "Copyright (c) 2024 Enterprise Solutions Inc. "
    "Runtime Integrity Protection Engine. "
    "Build: RELEASE_2024_Q4_ENTERPRISE. "
    "All rights reserved. Unauthorized modification prohibited.";

static const char *g_fintech_section_text =
    "FinSecure PayGuard Runtime Engine v5.1.0 "
    "Certified PCI-DSS Level 1 Compliance Module. "
    "Transaction Protection Layer Active. "
    "Build: FINSEC_2024_STABLE. "
    "Financial Security Standards Compliant.";

static const char *g_game_section_text =
    "UnrealGuard Anti-Cheat Runtime v2.8.3 "
    "Game Integrity Protection System. "
    "Memory Tampering Detection Engine. "
    "Build: UEGUARD_2024_RELEASE_CANDIDATE. "
    "Client-Side Anti-Tamper Module.";

static const char *g_social_section_text =
    "ChatSecure Message Protection Core v4.1.2 "
    "End-to-End Security Verification Module. "
    "Social Platform Integrity Guard. "
    "Build: CHATSEC_2024_LTS. "
    "Communication Security Assurance.";

static const char *g_ecommerce_section_text =
    "ShopGuard Transaction Security v6.0.1 "
    "E-Commerce Platform Protection Suite. "
    "Payment Gateway Integrity Verification. "
    "Build: SHOPGUARD_2024_ENTERPRISE. "
    "Order Processing Security Module.";

/* ================================================================
 * 动态生成 section 内容
 * 根据 g_disguise_type 选择不同的 section 文本
 * ================================================================ */
static const char *get_section_text_for_disguise(ArkDisguiseType type) {
    switch (type) {
        case ARK_DISGUISE_DEFAULT:
            return g_default_section_text;
        case ARK_DISGUISE_ENTERPRISE:
            return g_enterprise_section_text;
        case ARK_DISGUISE_FINTECH:
            return g_fintech_section_text;
        case ARK_DISGUISE_GAME:
            return g_game_section_text;
        case ARK_DISGUISE_SOCIAL:
            return g_social_section_text;
        case ARK_DISGUISE_ECOMMERCE:
            return g_ecommerce_section_text;
        case ARK_DISGUISE_CUSTOM:
            return g_custom_section_text.empty()
                ? g_default_section_text
                : g_custom_section_text.c_str();
        default:
            return g_default_section_text;
    }
}

/* ================================================================
 * 自定义 section 变量
 * 使用延迟初始化机制，在 ArkVMP_OnLoad 时根据伪装类型设置内容
 * ================================================================ */

/* 使用固定的 section 名称，内容在运行时填充 */
#define ARK_CUSTOM_SECTION_NAME ".Ark是一款开源离线免费加固工具，支持dex加密/VMP抽代码/签名校验等，倒卖死妈，加固工具作者QQ2380494437_By菜鸟八哥。特别是有个叫易固安全的傻逼，加固圈的诈骗犯，你妈死了。"

/* section 内容缓冲区 */
static char g_section_content[1024];
static bool g_section_content_set = false;

/*
 * 初始化 section 内容
 * 必须在 ArkVMP_OnLoad 中调用，早于任何对 g_ark_vmp_section 的引用
 */
static void init_section_content() {
    pthread_mutex_lock(&g_disguise_mutex);

    if (g_section_content_set) {
        pthread_mutex_unlock(&g_disguise_mutex);
        return;
    }

    const char *text = get_section_text_for_disguise(g_disguise_type);
    size_t text_len = strlen(text);

    /* 尾部固定字符串 */
    const char *tail = "还看，看你妈呢";
    size_t tail_len = strlen(tail);

    size_t total = text_len + tail_len + 1;

    if (total > sizeof(g_section_content)) {
        text_len = sizeof(g_section_content) - tail_len - 1;
    }

    memcpy(g_section_content, text, text_len);
    memcpy(g_section_content + text_len, tail, tail_len);
    g_section_content[text_len + tail_len] = '\0';

    g_section_content_set = true;

    LOGI("[ArkVMP] 伪装类型=%d, section内容已初始化, 长度=%zu",
         (int)g_disguise_type, strlen(g_section_content));

    pthread_mutex_unlock(&g_disguise_mutex);
}

/* 定义在自定义 section 中的变量 */
extern "C"
__attribute__((used))
__attribute__((visibility("default")))
__attribute__((section(ARK_CUSTOM_SECTION_NAME)))
const char g_ark_vmp_section[] = "";

extern "C"
__attribute__((used))
__attribute__((visibility("default")))
const void *ArkVmpKeepCustomSection() {
    return g_ark_vmp_section;
}

/* ================================================================
 * JNI 可调用接口 — 设置伪装类型
 *
 * 在 Java 层调用:
 *   ArkVMP.nativeSetDisguiseType(int type)
 *   或
 *   ArkVMP.nativeSetDisguiseType(int type, String customText)
 * ================================================================ */

static JavaVM *g_vm = NULL;

extern "C" void ArkVMP_SetContext(JNIEnv *env, jobject context) {
    VmpRuntime_SetContext(env, context);
}

/*
 * ArkVMP_SetDisguiseType
 * 设置企业伪装类型并更新自定义 section 内容
 *
 * @param env   JNI 环境
 * @param type  伪装类型 (0-5, 99=自定义)
 *              0: 默认(加固工具)
 *              1: 企业级应用
 *              2: 金融科技
 *              3: 游戏引擎
 *              4: 社交通信
 *              5: 电商平台
 *              99: 自定义 (需要同时设置 customText)
 * @param customText  自定义文本 (type=99 时使用, 可为 NULL)
 *
 * 注意: 此函数应在 ArkVMP_OnLoad 之前调用以确保 section 内容正确配置。
 *       如果在 OnLoad 之后调用，已编译的 section 内容不会改变，
 *       仅影响运行时上下文。
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_ark_safe_ArkVMP_nativeSetDisguiseType(
    JNIEnv *env, jclass clazz, jint type, jstring customText) {

    pthread_mutex_lock(&g_disguise_mutex);

    ArkDisguiseType new_type;
    switch (type) {
        case 0:  new_type = ARK_DISGUISE_DEFAULT;    break;
        case 1:  new_type = ARK_DISGUISE_ENTERPRISE; break;
        case 2:  new_type = ARK_DISGUISE_FINTECH;    break;
        case 3:  new_type = ARK_DISGUISE_GAME;       break;
        case 4:  new_type = ARK_DISGUISE_SOCIAL;     break;
        case 5:  new_type = ARK_DISGUISE_ECOMMERCE;  break;
        case 99: new_type = ARK_DISGUISE_CUSTOM;     break;
        default: new_type = ARK_DISGUISE_DEFAULT;    break;
    }

    LOGI("[ArkVMP] 伪装类型变更: %d -> %d", (int)g_disguise_type, (int)new_type);

    g_disguise_type = new_type;

    /* 处理自定义文本 */
    if (new_type == ARK_DISGUISE_CUSTOM && customText != NULL) {
        const char *chars = env->GetStringUTFChars(customText, NULL);
        if (chars != NULL) {
            g_custom_section_text = chars;
            env->ReleaseStringUTFChars(customText, chars);

            /* 限制自定义文本长度 */
            if (g_custom_section_text.length() > 800) {
                g_custom_section_text.resize(800);
            }
            LOGI("[ArkVMP] 自定义伪装文本已设置, 长度=%zu",
                 g_custom_section_text.length());
        }
    } else if (new_type == ARK_DISGUISE_CUSTOM) {
        g_custom_section_text = g_default_section_text;
    }

    /* 标记 section 内容需要重新生成 */
    g_section_content_set = false;

    pthread_mutex_unlock(&g_disguise_mutex);
}

/*
 * ArkVMP_SetDisguiseType (简化版本)
 * 仅设置伪装类型，不带自定义文本
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_ark_safe_ArkVMP_nativeSetDisguiseTypeSimple(
    JNIEnv *env, jclass clazz, jint type) {
    Java_com_ark_safe_ArkVMP_nativeSetDisguiseType(env, clazz, type, NULL);
}

/*
 * ArkVMP_GetDisguiseType
 * 获取当前伪装类型
 */
extern "C"
JNIEXPORT jint JNICALL
Java_com_ark_safe_ArkVMP_nativeGetDisguiseType(
    JNIEnv *env, jclass clazz) {
    return (jint)g_disguise_type;
}

/* ================================================================
 * 辅助工具函数
 * ================================================================ */

static std::string jstringToString(JNIEnv *env, jstring str) {
    if (str == NULL) return "";
    const char *chars = env->GetStringUTFChars(str, NULL);
    if (chars == NULL) return "";
    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);
    return result;
}

static void dotToSlash(std::string &name) {
    for (size_t i = 0; i < name.length(); i++) {
        if (name[i] == '.') name[i] = '/';
    }
}

static std::string getStubClassNameFromProperty(JNIEnv *env) {
    jclass clsSystem = env->FindClass("java/lang/System");
    if (clsSystem == NULL) {
        env->ExceptionClear();
        return "";
    }

    jmethodID midGetProperty = env->GetStaticMethodID(
        clsSystem, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if (midGetProperty == NULL) {
        env->ExceptionClear();
        return "";
    }

    jstring key = env->NewStringUTF("ark");
    jstring value = (jstring)env->CallStaticObjectMethod(clsSystem, midGetProperty, key);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return "";
    }

    std::string className = jstringToString(env, value);
    dotToSlash(className);
    return className;
}

/* ================================================================
 * Native 方法桥接
 * ================================================================ */

static void native_callVoid(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    VmpRuntime_Execute(env, methodId, thiz, args);
}

static jboolean native_callBoolean(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).booleanValue;
}

static jbyte native_callByte(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).byteValue;
}

static jshort native_callShort(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).shortValue;
}

static jchar native_callChar(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).charValue;
}

static jint native_callInt(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).intValue;
}

static jlong native_callLong(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).longValue;
}

static jfloat native_callFloat(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).floatValue;
}

static jdouble native_callDouble(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).doubleValue;
}

static jobject native_callObject(JNIEnv *env, jclass clazz, jint methodId,
    jobject thiz, jobjectArray args) {
    return VmpRuntime_Execute(env, methodId, thiz, args).objectValue;
}

static JNINativeMethod g_methods[] = {
    {"callVoid",    "(ILjava/lang/Object;[Ljava/lang/Object;)V",  (void *)native_callVoid},
    {"callBoolean", "(ILjava/lang/Object;[Ljava/lang/Object;)Z",  (void *)native_callBoolean},
    {"callByte",    "(ILjava/lang/Object;[Ljava/lang/Object;)B",  (void *)native_callByte},
    {"callShort",   "(ILjava/lang/Object;[Ljava/lang/Object;)S",  (void *)native_callShort},
    {"callChar",    "(ILjava/lang/Object;[Ljava/lang/Object;)C",  (void *)native_callChar},
    {"callInt",     "(ILjava/lang/Object;[Ljava/lang/Object;)I",  (void *)native_callInt},
    {"callLong",    "(ILjava/lang/Object;[Ljava/lang/Object;)J",  (void *)native_callLong},
    {"callFloat",   "(ILjava/lang/Object;[Ljava/lang/Object;)F",  (void *)native_callFloat},
    {"callDouble",  "(ILjava/lang/Object;[Ljava/lang/Object;)D",  (void *)native_callDouble},
    {"callObject",  "(ILjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                                                                    (void *)native_callObject},
};

/* JNI 注册表 — 增加伪装类型管理接口 */
static JNINativeMethod g_vmp_jni_methods[] = {
    {"nativeSetDisguiseType",       "(ILjava/lang/String;)V", (void *)Java_com_ark_safe_ArkVMP_nativeSetDisguiseType},
    {"nativeSetDisguiseTypeSimple", "(I)V",                   (void *)Java_com_ark_safe_ArkVMP_nativeSetDisguiseTypeSimple},
    {"nativeGetDisguiseType",       "()I",                    (void *)Java_com_ark_safe_ArkVMP_nativeGetDisguiseType},
};

/* ================================================================
 * ArkVMP_OnLoad
 * 在加载时根据伪装类型初始化 section 内容并注册 native 方法
 * ================================================================ */

extern "C" jint ArkVMP_OnLoad(JavaVM *vm) {
    g_vm = vm;

    /* 初始化自定义 section 内容 */
    init_section_content();

    JNIEnv *env = NULL;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    /* 注册伪装类型管理 JNI 方法 */
    jclass vmpClass = env->FindClass("com/ark/safe/ArkVMP");
    if (vmpClass != NULL) {
        int vmpMethodCount = sizeof(g_vmp_jni_methods) / sizeof(g_vmp_jni_methods[0]);
        env->RegisterNatives(vmpClass, g_vmp_jni_methods, vmpMethodCount);
        env->ExceptionClear();
    }

    std::string className = getStubClassNameFromProperty(env);
    if (className.empty()) {
        className = "com/ark/safe/StubApp";
    }

    jclass stubClass = env->FindClass(className.c_str());
    if (stubClass == NULL) {
        env->ExceptionClear();
        LOGE("[ArkVMP] 找不到VM调用入口类：%s", className.c_str());
        return JNI_ERR;
    }

    int methodCount = sizeof(g_methods) / sizeof(g_methods[0]);
    if (env->RegisterNatives(stubClass, g_methods, methodCount) != JNI_OK) {
        env->ExceptionClear();
        LOGE("[ArkVMP] RegisterNatives失败，目标类：%s", className.c_str());
        return JNI_ERR;
    }

    LOGI("[ArkVMP] 注册成功，目标类：%s, 伪装类型=%d",
         className.c_str(), (int)g_disguise_type);

    (void)ArkVmpKeepCustomSection();

    return JNI_VERSION_1_6;
}
