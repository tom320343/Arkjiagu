#include <jni.h>
#include <android/log.h>
#include <string>
#include <pthread.h>
#include "GuardEnvGuard.h"
#include "GuardVMP.h"
#include "GuardDexLoader.h"

#define LOG_TAG "GuardVMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static jobject g_ark_context = nullptr;
static bool g_ark_dex_loaded = false;
static jobject g_real_factory = nullptr;
static pthread_mutex_t g_ark_load_mutex = PTHREAD_MUTEX_INITIALIZER;

static void saveArkContext(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return;
    }

    if (g_ark_context != nullptr) {
        return;
    }

    g_ark_context = env->NewGlobalRef(context);
}

static jobject getCurrentApplication(JNIEnv *env) {
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID midCurrentApplication = env->GetStaticMethodID(
            activityThreadClass,
            "currentApplication",
            "()Landroid/app/Application;"
    );

    if (midCurrentApplication == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject app = env->CallStaticObjectMethod(activityThreadClass, midCurrentApplication);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }

    return app;
}

static jobject getRealAppComponentFactory(JNIEnv *env, jobject classLoader) {
    if (g_real_factory != nullptr) {
        return g_real_factory;
    }

    const char *factoryName = GuardDexLoader_GetRealAppComponentFactoryName();
    if (factoryName == nullptr || strlen(factoryName) <= 0) {
        return nullptr;
    }

    jclass clsClassLoader = env->FindClass("java/lang/ClassLoader");
    jclass clsClass = env->FindClass("java/lang/Class");

    if (clsClassLoader == nullptr || clsClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID midLoadClass = env->GetMethodID(
            clsClassLoader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;"
    );

    jmethodID midNewInstance = env->GetMethodID(
            clsClass,
            "newInstance",
            "()Ljava/lang/Object;"
    );

    if (midLoadClass == nullptr || midNewInstance == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jstring factoryNameJ = env->NewStringUTF(factoryName);

    jobject factoryClass = env->CallObjectMethod(
            classLoader,
            midLoadClass,
            factoryNameJ
    );

    if (env->ExceptionCheck() || factoryClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject factoryObj = env->CallObjectMethod(
            factoryClass,
            midNewInstance
    );

    if (env->ExceptionCheck() || factoryObj == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    g_real_factory = env->NewGlobalRef(factoryObj);

    //LOGI("已创建原 AppComponentFactory：%s", factoryName);

    return g_real_factory;
}
static jobject defaultNewInstance(JNIEnv *env, jobject classLoader, jstring className) {
    jclass clsClassLoader = env->FindClass("java/lang/ClassLoader");
    jclass clsClass = env->FindClass("java/lang/Class");

    if (clsClassLoader == nullptr || clsClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID midLoadClass = env->GetMethodID(
            clsClassLoader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;"
    );

    jmethodID midNewInstance = env->GetMethodID(
            clsClass,
            "newInstance",
            "()Ljava/lang/Object;"
    );

    if (midLoadClass == nullptr || midNewInstance == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject targetClass = env->CallObjectMethod(
            classLoader,
            midLoadClass,
            className
    );

    if (env->ExceptionCheck() || targetClass == nullptr) {
        return nullptr;
    }

    jobject obj = env->CallObjectMethod(
            targetClass,
            midNewInstance
    );

    return obj;
}
static bool ensureDexLoadedFromFactory(JNIEnv *env, jobject classLoader) {
    if (classLoader == nullptr) {
        return false;
    }

    pthread_mutex_lock(&g_ark_load_mutex);

    if (g_ark_dex_loaded) {
        pthread_mutex_unlock(&g_ark_load_mutex);
        return true;
    }

    GuardDexLoaderFactoryFunc factoryFunc = GuardDexLoader_GetFactoryEntry();
    if (factoryFunc == nullptr) {
        pthread_mutex_unlock(&g_ark_load_mutex);
        return false;
    }

    bool ok = factoryFunc(env, classLoader);
    if (ok) {
        g_ark_dex_loaded = true;
        //LOGI("加载 dex 成功，来源=AppComponentFactory代理");
    }

    pthread_mutex_unlock(&g_ark_load_mutex);
    return ok;
}
static bool ensureArkDexLoaded(JNIEnv *env, jobject context, const char *from) {
    if (env == nullptr || context == nullptr) {
        //LOGE("加载 dex 失败：env 或 context 为空，来源=%s", from);
        return false;
    }

    pthread_mutex_lock(&g_ark_load_mutex);

    if (g_ark_dex_loaded) {
        //LOGI("dex 已加载，跳过重复加载，来源=%s", from);
        pthread_mutex_unlock(&g_ark_load_mutex);
        return true;
    }

    //LOGI("开始加载 dex，来源=%s", from);

    saveArkContext(env, context);

    GuardVMP_SetContext(env, context);

    GuardEnvGuardFunc guardFunc = GuardEnvGuard_GetEntry();
    if (guardFunc == nullptr) {
        //LOGE("加载 dex 失败：GuardEnvGuard_GetEntry 返回空，来源=%s", from);
        pthread_mutex_unlock(&g_ark_load_mutex);
        return false;
    }

    bool ok = guardFunc(env, context);
    if (ok) {
        g_ark_dex_loaded = true;
        //LOGI("加载 dex 成功，来源=%s", from);
    } else {
        //LOGE("加载 dex 失败：guardFunc 返回 false，来源=%s", from);
    }

    pthread_mutex_unlock(&g_ark_load_mutex);
    return ok;
}

static jobject native_instantiateApplication(JNIEnv *env, jclass clazz, jobject classLoader, jstring className) {
    ensureDexLoadedFromFactory(env, classLoader);

    jobject realFactory = getRealAppComponentFactory(env, classLoader);
    if (realFactory != nullptr) {
        jclass clsFactory = env->FindClass("android/app/AppComponentFactory");
        jmethodID mid = env->GetMethodID(
                clsFactory,
                "instantiateApplication",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;"
        );

        jobject obj = env->CallObjectMethod(realFactory, mid, classLoader, className);
        if (!env->ExceptionCheck() && obj != nullptr) {
            return obj;
        }

        env->ExceptionClear();
    }

    return defaultNewInstance(env, classLoader, className);
}
static jobject native_instantiateProvider(JNIEnv *env, jclass clazz, jobject classLoader, jstring className) {
    ensureDexLoadedFromFactory(env, classLoader);

    jobject realFactory = getRealAppComponentFactory(env, classLoader);
    if (realFactory != nullptr) {
        jclass clsFactory = env->FindClass("android/app/AppComponentFactory");
        jmethodID mid = env->GetMethodID(
                clsFactory,
                "instantiateProvider",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/content/ContentProvider;"
        );

        jobject obj = env->CallObjectMethod(realFactory, mid, classLoader, className);
        if (!env->ExceptionCheck() && obj != nullptr) {
            return obj;
        }

        env->ExceptionClear();
    }

    return defaultNewInstance(env, classLoader, className);
}
static jobject native_instantiateActivity(JNIEnv *env, jclass clazz, jobject classLoader, jstring className, jobject intent) {
    ensureDexLoadedFromFactory(env, classLoader);

    jobject realFactory = getRealAppComponentFactory(env, classLoader);
    if (realFactory != nullptr) {
        jclass clsFactory = env->FindClass("android/app/AppComponentFactory");
        jmethodID mid = env->GetMethodID(
                clsFactory,
                "instantiateActivity",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Activity;"
        );

        jobject obj = env->CallObjectMethod(realFactory, mid, classLoader, className, intent);
        if (!env->ExceptionCheck() && obj != nullptr) {
            return obj;
        }

        env->ExceptionClear();
    }

    return defaultNewInstance(env, classLoader, className);
}
static jobject native_instantiateService(JNIEnv *env, jclass clazz, jobject classLoader, jstring className, jobject intent) {
    ensureDexLoadedFromFactory(env, classLoader);

    jobject realFactory = getRealAppComponentFactory(env, classLoader);
    if (realFactory != nullptr) {
        jclass clsFactory = env->FindClass("android/app/AppComponentFactory");
        jmethodID mid = env->GetMethodID(
                clsFactory,
                "instantiateService",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Service;"
        );

        jobject obj = env->CallObjectMethod(realFactory, mid, classLoader, className, intent);
        if (!env->ExceptionCheck() && obj != nullptr) {
            return obj;
        }

        env->ExceptionClear();
    }

    return defaultNewInstance(env, classLoader, className);
}
static jobject native_instantiateReceiver(JNIEnv *env, jclass clazz, jobject classLoader, jstring className, jobject intent) {
    ensureDexLoadedFromFactory(env, classLoader);

    jobject realFactory = getRealAppComponentFactory(env, classLoader);
    if (realFactory != nullptr) {
        jclass clsFactory = env->FindClass("android/app/AppComponentFactory");
        jmethodID mid = env->GetMethodID(
                clsFactory,
                "instantiateReceiver",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/content/BroadcastReceiver;"
        );

        jobject obj = env->CallObjectMethod(realFactory, mid, classLoader, className, intent);
        if (!env->ExceptionCheck() && obj != nullptr) {
            return obj;
        }

        env->ExceptionClear();
    }

    return defaultNewInstance(env, classLoader, className);
}

/**
 * 给 AppComponentFactory 调用
 * 对应壳类方法：
 * public static native void loadDexFromFactory(ClassLoader cl);
 */
static void native_loadDexFromFactory(JNIEnv *env, jclass clazz, jobject classLoader) {
    //LOGI("进入 AppComponentFactory 加载入口");

    if (classLoader == nullptr) {
        //LOGE("Factory 入口传入的 ClassLoader 为空");
        return;
    }

    pthread_mutex_lock(&g_ark_load_mutex);

    if (g_ark_dex_loaded) {
        //LOGI("dex 已加载，跳过重复加载，来源=AppComponentFactory");
        pthread_mutex_unlock(&g_ark_load_mutex);
        return;
    }

    GuardDexLoaderFactoryFunc factoryFunc = GuardDexLoader_GetFactoryEntry();
    if (factoryFunc == nullptr) {
        //LOGE("Factory 加载 dex 失败：GuardDexLoader_GetFactoryEntry 返回空");
        pthread_mutex_unlock(&g_ark_load_mutex);
        return;
    }

    bool ok = factoryFunc(env, classLoader);
    if (ok) {
        g_ark_dex_loaded = true;
        //LOGI("加载 dex 成功，来源=AppComponentFactory");
    } else {
        //LOGE("加载 dex 失败，来源=AppComponentFactory");
    }

    pthread_mutex_unlock(&g_ark_load_mutex);
}




static void native_attachBaseContext(JNIEnv *env, jobject thiz, jobject context) {
    if (context == nullptr) {
        return;
    }

    jclass contextWrapperClass = env->FindClass("android/content/ContextWrapper");
    if (contextWrapperClass == nullptr) {
        env->ExceptionClear();
        return;
    }

    jmethodID midAttachBaseContext = env->GetMethodID(
            contextWrapperClass,
            "attachBaseContext",
            "(Landroid/content/Context;)V"
    );

    if (midAttachBaseContext == nullptr) {
        env->ExceptionClear();
        return;
    }

    env->CallNonvirtualVoidMethod(
            thiz,
            contextWrapperClass,
            midAttachBaseContext,
            context
    );

    if (env->ExceptionCheck()) {
        return;
    }

    saveArkContext(env, context);
    ensureArkDexLoaded(env, context, "attachBaseContext");
}

static void native_onCreate(JNIEnv *env, jobject thiz) {
    jclass applicationClass = env->FindClass("android/app/Application");
    if (applicationClass == nullptr) {
        env->ExceptionClear();
        return;
    }

    jmethodID midOnCreate = env->GetMethodID(
            applicationClass,
            "onCreate",
            "()V"
    );

    if (midOnCreate == nullptr) {
        env->ExceptionClear();
        return;
    }

    env->CallNonvirtualVoidMethod(
            thiz,
            applicationClass,
            midOnCreate
    );

    if (env->ExceptionCheck()) {
        return;
    }

    saveArkContext(env, thiz);
    GuardVMP_SetContext(env, thiz);

    GuardEnvGuardFunc starterFunc = GuardEnvGuard_GetStartRealApplicationEntry();
    if (starterFunc != nullptr) {
        starterFunc(env, thiz);
    }
}

static std::string jstringToString(JNIEnv *env, jstring str) {
    if (str == nullptr) {
        return "";
    }

    const char *chars = env->GetStringUTFChars(str, nullptr);
    if (chars == nullptr) {
        return "";
    }

    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);
    return result;
}

static void dotToSlash(std::string &name) {
    for (size_t i = 0; i < name.length(); i++) {
        if (name[i] == '.') {
            name[i] = '/';
        }
    }
}

static std::string getStubClassNameFromProperty(JNIEnv *env) {
    jclass clsSystem = env->FindClass("java/lang/System");
    if (clsSystem == nullptr) {
        env->ExceptionClear();
        return "";
    }

    jmethodID midGetProperty = env->GetStaticMethodID(
            clsSystem,
            "getProperty",
            "(Ljava/lang/String;)Ljava/lang/String;"
    );

    if (midGetProperty == nullptr) {
        env->ExceptionClear();
        return "";
    }

    jstring key = env->NewStringUTF("guard");

    jstring value = (jstring) env->CallStaticObjectMethod(
            clsSystem,
            midGetProperty,
            key
    );

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return "";
    }

    std::string className = jstringToString(env, value);
    dotToSlash(className);

    return className;
}

static JNINativeMethod gStubMethods[] = {
        {
                "attachBaseContext",
                "(Landroid/content/Context;)V",
                (void *) native_attachBaseContext
        },
        {
                "onCreate",
                "()V",
                (void *) native_onCreate
        },
        {
                "loadDexFromFactory",
                "(Ljava/lang/ClassLoader;)V",
                (void *) native_loadDexFromFactory
        },
        {
                "nativeInstantiateApplication",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;",
                (void *) native_instantiateApplication
        },
        {
                "nativeInstantiateProvider",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/content/ContentProvider;",
                (void *) native_instantiateProvider
        },
        {
                "nativeInstantiateActivity",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Activity;",
                (void *) native_instantiateActivity
        },
        {
                "nativeInstantiateService",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Service;",
                (void *) native_instantiateService
        },
        {
                "nativeInstantiateReceiver",
                "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/content/BroadcastReceiver;",
                (void *) native_instantiateReceiver
        }
};

static int registerNativeMethods(JNIEnv *env) {
    std::string className = getStubClassNameFromProperty(env);

    if (className.empty()) {
        className = "com/apk/guard/safe/StubApp";
    }

    jclass clazz = env->FindClass(className.c_str());
    if (clazz == nullptr) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    if (env->RegisterNatives(
            clazz,
            gStubMethods,
            sizeof(gStubMethods) / sizeof(gStubMethods[0])
    ) != JNI_OK) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    if (!registerNativeMethods(env)) {
        //LOGE("注册方法失败");
        return JNI_ERR;
    }

    if (GuardVMP_OnLoad(vm) == JNI_ERR) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

