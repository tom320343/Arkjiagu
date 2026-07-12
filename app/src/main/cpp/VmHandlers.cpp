#include "VmHandlers.h"
#include <math.h>
#include <android/log.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include "VmpRuntime.h"
#define LOG_TAG "ArkVMP_Handlers"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static VmHandler g_handlerTable[256];
//==================================================================================辅助方法区域

static std::string jstringToDebugString(JNIEnv *env, jobject obj) {
    if (env == nullptr || obj == nullptr) {
        return "null";
    }

    jclass cls = env->GetObjectClass(obj);
    if (env->ExceptionCheck() || cls == nullptr) {
        env->ExceptionClear();
        return "<GetObjectClass失败>";
    }

    jclass stringClass = env->FindClass("java/lang/String");
    if (env->ExceptionCheck() || stringClass == nullptr) {
        env->ExceptionClear();
        return "<FindClass String失败>";
    }

    if (!env->IsAssignableFrom(cls, stringClass)) {
        return "<不是String对象>";
    }

    jstring str = static_cast<jstring>(obj);

    const char *chars = env->GetStringUTFChars(str, nullptr);
    if (env->ExceptionCheck() || chars == nullptr) {
        env->ExceptionClear();
        return "<GetStringUTFChars失败>";
    }

    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);

    return result;
}
static std::vector<std::string> parseMethodParameterTypes(const std::string &signature) {
    std::vector<std::string> result;

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return result;
    }

    size_t i = start + 1;

    while (i < end) {
        char c = signature[i];

        if (c == 'L') {
            size_t semi = signature.find(';', i);
            if (semi == std::string::npos || semi > end) {
                break;
            }

            result.push_back(signature.substr(i, semi - i + 1));
            i = semi + 1;
        } else if (c == '[') {
            size_t arrayStart = i;

            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i < end && signature[i] == 'L') {
                size_t semi = signature.find(';', i);
                if (semi == std::string::npos || semi > end) {
                    break;
                }

                result.push_back(signature.substr(arrayStart, semi - arrayStart + 1));
                i = semi + 1;
            } else {
                result.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            result.push_back(signature.substr(i, 1));
            i++;
        }
    }

    return result;
}

static std::string parseMethodReturnType(const std::string &signature) {
    size_t end = signature.find(')');

    if (end == std::string::npos || end + 1 >= signature.length()) {
        return "";
    }

    return signature.substr(end + 1);
}
static jfloat intBitsToFloat(jint value) {
    jfloat result;
    memcpy(&result, &value, sizeof(jfloat));
    return result;
}
static jint floatToIntBits(jfloat value) {
    jint result;
    memcpy(&result, &value, sizeof(jint));
    return result;
}
static jdouble longBitsToDouble(jlong value) {
    jdouble result;
    memcpy(&result, &value, sizeof(jdouble));
    return result;
}
static jlong doubleToLongBits(jdouble value) {
    jlong result;
    memcpy(&result, &value, sizeof(jlong));
    return result;
}
static jfloat vmIntBitsToFloatValue(jint value) {
    jfloat result;
    memcpy(&result, &value, sizeof(jfloat));
    return result;
}

static jint vmFloatToIntBitsValue(jfloat value) {
    jint result;
    memcpy(&result, &value, sizeof(jint));
    return result;
}
static jfloat VmBitsToFloatForConvert(jint value) {
    jfloat result = 0;
    memcpy(&result, &value, sizeof(jfloat));
    return result;
}

static jint VmFloatToBitsForConvert(jfloat value) {
    jint result = 0;
    memcpy(&result, &value, sizeof(jint));
    return result;
}

static jdouble VmBitsToDoubleForConvert(jlong value) {
    jdouble result = 0;
    memcpy(&result, &value, sizeof(jdouble));
    return result;
}

static jlong VmDoubleToBitsForConvert(jdouble value) {
    jlong result = 0;
    memcpy(&result, &value, sizeof(jlong));
    return result;
}
static jclass findClassByTypeWithClassLoaderObject(JNIEnv *env, jobject classLoader, const std::string &type) {
    if (env == nullptr || classLoader == nullptr || type.empty()) {
        return nullptr;
    }

    std::string name = type;

    if (name[0] == 'L' && name[name.length() - 1] == ';') {
        name = name.substr(1, name.length() - 2);
    }

    for (size_t i = 0; i < name.length(); i++) {
        if (name[i] == '/') {
            name[i] = '.';
        }
    }

    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    if (env->ExceptionCheck() || classLoaderClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID loadClassMethod = env->GetMethodID(
            classLoaderClass,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;"
    );

    if (env->ExceptionCheck() || loadClassMethod == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jstring className = env->NewStringUTF(name.c_str());
    if (className == nullptr) {
        return nullptr;
    }

    jobject loadedClass = env->CallObjectMethod(classLoader, loadClassMethod, className);
    if (env->ExceptionCheck() || loadedClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    return static_cast<jclass>(loadedClass);
}

static jclass findClassByTypeWithRuntimeContext(JNIEnv *env, const std::string &type) {
    jobject context = VmpRuntime_GetContext();
    if (env == nullptr || context == nullptr) {
        return nullptr;
    }

    jclass contextClass = env->GetObjectClass(context);
    if (env->ExceptionCheck() || contextClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID getClassLoaderMethod = env->GetMethodID(
            contextClass,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;"
    );

    if (env->ExceptionCheck() || getClassLoaderMethod == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject classLoader = env->CallObjectMethod(context, getClassLoaderMethod);
    if (env->ExceptionCheck() || classLoader == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    return findClassByTypeWithClassLoaderObject(env, classLoader, type);
}
static std::string getReturnTypeFromSignature(const std::string &signature) {
    size_t pos = signature.find(')');
    if (pos == std::string::npos || pos + 1 >= signature.length()) {
        return "";
    }
    return signature.substr(pos + 1);
}

static std::vector<std::string> parseParameterTypesFromSignature(const std::string &signature) {
    std::vector<std::string> result;

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return result;
    }

    size_t i = start + 1;
    while (i < end) {
        char c = signature[i];

        if (c == 'L') {
            size_t objEnd = signature.find(';', i);
            if (objEnd == std::string::npos || objEnd >= end) {
                break;
            }
            result.push_back(signature.substr(i, objEnd - i + 1));
            i = objEnd + 1;
        } else if (c == '[') {
            size_t arrayStart = i;
            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i < end && signature[i] == 'L') {
                size_t objEnd = signature.find(';', i);
                if (objEnd == std::string::npos || objEnd >= end) {
                    break;
                }
                result.push_back(signature.substr(arrayStart, objEnd - arrayStart + 1));
                i = objEnd + 1;
            } else {
                result.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            result.push_back(signature.substr(i, 1));
            i++;
        }
    }

    return result;
}


static bool buildJValueArgsFromMethod(
        VmContext &ctx,
        const std::vector<std::string> &paramTypes,
        std::vector<jvalue> &args
) {
    args.clear();

    if (ctx.method == nullptr) {
        LOGE("buildJValueArgsFromMethod method为空");
        return false;
    }

    int paramRegisterCount = ctx.method->isStatic ? 0 : 1;

    for (int i = 0; i < static_cast<int>(ctx.method->parameterTypes.size()); i++) {
        const std::string &type = ctx.method->parameterTypes[i];
        if (type == "J" || type == "D") {
            paramRegisterCount += 2;
        } else {
            paramRegisterCount += 1;
        }
    }

    int paramBase = ctx.method->registerCount - paramRegisterCount;
    if (paramBase < 0) {
        LOGE("buildJValueArgsFromMethod 参数寄存器计算错误 registerCount=%d paramRegisterCount=%d",
             ctx.method->registerCount, paramRegisterCount);
        return false;
    }

    int current = paramBase;

    if (!ctx.method->isStatic) {
        current++;
    }

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        if (current >= static_cast<int>(ctx.regs.size())) {
            LOGE("buildJValueArgsFromMethod 寄存器越界 index=%d current=%d", i, current);
            return false;
        }

        const std::string &type = paramTypes[i];

        jvalue value;
        memset(&value, 0, sizeof(jvalue));

        if (type == "Z") {
            value.z = ctx.regs[current].intValue ? JNI_TRUE : JNI_FALSE;
            current++;
        } else if (type == "B") {
            value.b = static_cast<jbyte>(ctx.regs[current].intValue);
            current++;
        } else if (type == "S") {
            value.s = static_cast<jshort>(ctx.regs[current].intValue);
            current++;
        } else if (type == "C") {
            value.c = static_cast<jchar>(ctx.regs[current].intValue);
            current++;
        } else if (type == "I") {
            value.i = static_cast<jint>(ctx.regs[current].intValue);
            current++;
        } else if (type == "J") {
            value.j = static_cast<jlong>(ctx.regs[current].longValue);
            current += 2;
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[current].intValue);
            memcpy(&value.f, &bits, sizeof(jfloat));
            current++;
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[current].longValue);
            memcpy(&value.d, &bits, sizeof(jdouble));
            current += 2;
        } else {
            value.l = ctx.regs[current].objectValue;
            current++;
        }

        args.push_back(value);
    }

    return true;
}

static bool buildJValueArgs(
        VmContext &ctx,
        const VmpInstruction &insn,
        const std::vector<std::string> &paramTypes,
        std::vector<jvalue> &args
) {
    args.clear();

    int regIndex = 1;

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        if (regIndex >= static_cast<int>(insn.registers.size())) {
            LOGE("构造参数失败，寄存器不足 index=%d", i);
            return false;
        }

        int reg = insn.registers[regIndex];
        const std::string &type = paramTypes[i];

        jvalue value;
        memset(&value, 0, sizeof(jvalue));

        if (type == "Z") {
            value.z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
            regIndex++;
        } else if (type == "B") {
            value.b = static_cast<jbyte>(ctx.regs[reg].intValue);
            regIndex++;
        } else if (type == "S") {
            value.s = static_cast<jshort>(ctx.regs[reg].intValue);
            regIndex++;
        } else if (type == "C") {
            value.c = static_cast<jchar>(ctx.regs[reg].intValue);
            regIndex++;
        } else if (type == "I") {
            value.i = static_cast<jint>(ctx.regs[reg].intValue);
            regIndex++;
        } else if (type == "J") {
            value.j = static_cast<jlong>(ctx.regs[reg].longValue);
            regIndex += 2;
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[reg].intValue);
            memcpy(&value.f, &bits, sizeof(jfloat));
            regIndex++;
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[reg].longValue);
            memcpy(&value.d, &bits, sizeof(jdouble));
            regIndex += 2;
        } else {
            value.l = ctx.regs[reg].objectValue;
            regIndex++;
        }

        args.push_back(value);
    }

    return true;
}
static void logAndClearJavaException(JNIEnv *env, const char *tag) {
    if (env == nullptr || !env->ExceptionCheck()) {
        return;
    }

    jthrowable ex = env->ExceptionOccurred();
    env->ExceptionClear();

    if (ex == nullptr) {
        LOGE("%s Java异常为空", tag);
        return;
    }

    jclass throwableClass = env->FindClass("java/lang/Throwable");
    if (env->ExceptionCheck() || throwableClass == nullptr) {
        env->ExceptionClear();
        LOGE("%s 获取Throwable类失败", tag);
        return;
    }

    jmethodID toStringMethod = env->GetMethodID(
            throwableClass,
            "toString",
            "()Ljava/lang/String;"
    );

    if (env->ExceptionCheck() || toStringMethod == nullptr) {
        env->ExceptionClear();
        LOGE("%s 获取Throwable.toString失败", tag);
        return;
    }

    jstring message = static_cast<jstring>(
            env->CallObjectMethod(ex, toStringMethod)
    );

    if (env->ExceptionCheck() || message == nullptr) {
        env->ExceptionClear();
        LOGE("%s Java异常存在，但读取异常信息失败", tag);
        return;
    }

    const char *msg = env->GetStringUTFChars(message, nullptr);
    if (msg != nullptr) {
        LOGE("%s Java异常：%s", tag, msg);
        env->ReleaseStringUTFChars(message, msg);
    }
}
static std::vector<std::string> parseMethodParamTypesFromSignature(const std::string &signature) {
    std::vector<std::string> result;

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return result;
    }

    size_t i = start + 1;
    while (i < end) {
        char c = signature[i];

        if (c == 'L') {
            size_t semi = signature.find(';', i);
            if (semi == std::string::npos || semi > end) {
                break;
            }
            result.push_back(signature.substr(i, semi - i + 1));
            i = semi + 1;
        } else if (c == '[') {
            size_t arrayStart = i;
            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i < end && signature[i] == 'L') {
                size_t semi = signature.find(';', i);
                if (semi == std::string::npos || semi > end) {
                    break;
                }
                result.push_back(signature.substr(arrayStart, semi - arrayStart + 1));
                i = semi + 1;
            } else {
                result.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            result.push_back(signature.substr(i, 1));
            i++;
        }
    }

    return result;
}

static std::string getMethodReturnTypeFromSignature(const std::string &signature) {
    size_t end = signature.find(')');
    if (end == std::string::npos || end + 1 >= signature.length()) {
        return "";
    }
    return signature.substr(end + 1);
}

static bool buildJValuesFromRegisters(
        VmContext &ctx,
        const std::vector<std::string> &paramTypes,
        const std::vector<int> &registers,
        int startRegisterIndex,
        std::vector<jvalue> &outArgs
) {
    outArgs.clear();

    int regIndex = startRegisterIndex;

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        if (regIndex >= static_cast<int>(registers.size())) {
            LOGE("INVOKE_RANGE 参数寄存器数量不足 index=%d", i);
            return false;
        }

        const std::string &type = paramTypes[i];
        int reg = registers[regIndex];

        jvalue value;
        memset(&value, 0, sizeof(jvalue));

        if (type == "Z") {
            value.z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
        } else if (type == "B") {
            value.b = static_cast<jbyte>(ctx.regs[reg].intValue);
        } else if (type == "S") {
            value.s = static_cast<jshort>(ctx.regs[reg].intValue);
        } else if (type == "C") {
            value.c = static_cast<jchar>(ctx.regs[reg].intValue);
        } else if (type == "I") {
            value.i = static_cast<jint>(ctx.regs[reg].intValue);
        } else if (type == "J") {
            value.j = static_cast<jlong>(ctx.regs[reg].longValue);
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[reg].intValue);
            memcpy(&value.f, &bits, sizeof(jfloat));
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[reg].longValue);
            memcpy(&value.d, &bits, sizeof(jdouble));
        } else {
            value.l = ctx.regs[reg].objectValue;
        }

        outArgs.push_back(value);

        if (type == "J" || type == "D") {
            regIndex += 2;
        } else {
            regIndex++;
        }
    }

    return true;
}
static std::vector<std::string> parseMethodParamTypes(const std::string &signature) {
    std::vector<std::string> result;

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return result;
    }

    size_t i = start + 1;
    while (i < end) {
        char c = signature[i];

        if (c == 'L') {
            size_t semi = signature.find(';', i);
            if (semi == std::string::npos || semi > end) {
                break;
            }

            result.push_back(signature.substr(i, semi - i + 1));
            i = semi + 1;
        } else if (c == '[') {
            size_t arrayStart = i;
            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i < end && signature[i] == 'L') {
                size_t semi = signature.find(';', i);
                if (semi == std::string::npos || semi > end) {
                    break;
                }

                result.push_back(signature.substr(arrayStart, semi - arrayStart + 1));
                i = semi + 1;
            } else if (i < end) {
                result.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            result.push_back(signature.substr(i, 1));
            i++;
        }
    }

    return result;
}

static bool parseMethodParameterTypes(const std::string &signature, std::vector<std::string> &outTypes) {
    outTypes.clear();

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return false;
    }

    size_t i = start + 1;

    while (i < end) {
        char c = signature[i];

        if (c == 'L') {
            size_t semicolon = signature.find(';', i);
            if (semicolon == std::string::npos || semicolon > end) {
                return false;
            }

            outTypes.push_back(signature.substr(i, semicolon - i + 1));
            i = semicolon + 1;
        } else if (c == '[') {
            size_t arrayStart = i;

            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i >= end) {
                return false;
            }

            if (signature[i] == 'L') {
                size_t semicolon = signature.find(';', i);
                if (semicolon == std::string::npos || semicolon > end) {
                    return false;
                }

                outTypes.push_back(signature.substr(arrayStart, semicolon - arrayStart + 1));
                i = semicolon + 1;
            } else {
                outTypes.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            outTypes.push_back(signature.substr(i, 1));
            i++;
        }
    }

    return true;
}

static std::string getMethodReturnType(const std::string &signature) {
    size_t end = signature.find(')');
    if (end == std::string::npos || end + 1 >= signature.length()) {
        return "";
    }

    return signature.substr(end + 1);
}

static jclass findClassByType(JNIEnv *env, const std::string &type) {
    if (type.empty()) {
        return nullptr;
    }

    std::string name = type;

    if (name[0] == 'L' && name[name.length() - 1] == ';') {
        name = name.substr(1, name.length() - 2);
    }

    jclass cls = env->FindClass(name.c_str());
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }

    return cls;
}

static jclass findClassByTypeWithObjectLoader(JNIEnv *env, jobject obj, const std::string &type) {
    if (env == nullptr || type.empty()) {
        return nullptr;
    }

    std::string name = type;

    if (name[0] == 'L' && name[name.length() - 1] == ';') {
        name = name.substr(1, name.length() - 2);
    }

    std::string dotName = name;
    for (size_t i = 0; i < dotName.length(); i++) {
        if (dotName[i] == '/') {
            dotName[i] = '.';
        }
    }

    jclass cls = env->FindClass(name.c_str());
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (cls != nullptr) {
        return cls;
    }

    if (obj == nullptr) {
        return nullptr;
    }

    jclass objClass = env->GetObjectClass(obj);
    if (env->ExceptionCheck() || objClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jclass classClass = env->FindClass("java/lang/Class");
    if (env->ExceptionCheck() || classClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID getClassLoaderMethod = env->GetMethodID(
            classClass,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;"
    );

    if (env->ExceptionCheck() || getClassLoaderMethod == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject classLoader = env->CallObjectMethod(objClass, getClassLoaderMethod);
    if (env->ExceptionCheck() || classLoader == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    if (env->ExceptionCheck() || classLoaderClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID loadClassMethod = env->GetMethodID(
            classLoaderClass,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;"
    );

    if (env->ExceptionCheck() || loadClassMethod == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jstring className = env->NewStringUTF(dotName.c_str());
    if (className == nullptr) {
        return nullptr;
    }

    jobject loadedClass = env->CallObjectMethod(classLoader, loadClassMethod, className);
    if (env->ExceptionCheck() || loadedClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    return static_cast<jclass>(loadedClass);
}

static bool parseMethodReference(
        const std::string &ref,
        std::string &classType,
        std::string &methodName,
        std::string &signature
) {
    size_t arrow = ref.find("->");
    if (arrow == std::string::npos) {
        return false;
    }

    classType = ref.substr(0, arrow);

    std::string right = ref.substr(arrow + 2);
    size_t sigStart = right.find('(');
    if (sigStart == std::string::npos) {
        return false;
    }

    methodName = right.substr(0, sigStart);
    signature = right.substr(sigStart);

    return true;
}

static bool parseFieldReference(
        const std::string &ref,
        std::string &classType,
        std::string &fieldName,
        std::string &fieldType
) {
    size_t arrow = ref.find("->");
    if (arrow == std::string::npos) {
        return false;
    }

    classType = ref.substr(0, arrow);

    std::string right = ref.substr(arrow + 2);
    size_t colon = right.find(':');
    if (colon == std::string::npos) {
        return false;
    }

    fieldName = right.substr(0, colon);
    fieldType = right.substr(colon + 1);

    return true;
}
// 实例字段 / 实例方法用：有 obj 的情况
static jclass findVmClassForObject(
        JNIEnv *env,
        jobject obj,
        const std::string &classType
) {
    if (env == nullptr || classType.empty()) {
        return nullptr;
    }

    jclass cls = nullptr;

    // 1. 优先用对象真实类
    if (obj != nullptr) {
        cls = env->GetObjectClass(obj);
        if (env->ExceptionCheck() || cls == nullptr) {
            env->ExceptionClear();
            cls = nullptr;
        }
    }

    // 2. 用对象 ClassLoader 加载声明类
    if (cls == nullptr && obj != nullptr) {
        cls = findClassByTypeWithObjectLoader(env, obj, classType);
    }

    // 3. 用 Runtime Context 的 ClassLoader
    if (cls == nullptr) {
        cls = findClassByTypeWithRuntimeContext(env, classType);
    }

    // 4. 最后才用 FindClass
    if (cls == nullptr) {
        cls = findClassByType(env, classType);
    }

    return cls;
}

// 静态字段 / new-instance / const-class 用：没有 obj 的情况
static jclass findVmClassForStatic(
        JNIEnv *env,
        const std::string &classType
) {
    if (env == nullptr || classType.empty()) {
        return nullptr;
    }

    jclass cls = nullptr;

    // 1. 优先用 Runtime Context 的 ClassLoader
    cls = findClassByTypeWithRuntimeContext(env, classType);

    // 2. 再用 FindClass
    if (cls == nullptr) {
        cls = findClassByType(env, classType);
    }

    return cls;
}
static bool isVoidReturn(const std::string &signature) {
    return !signature.empty() && signature[signature.length() - 1] == 'V';
}
static bool VmContext_JumpToExceptionHandler(VmContext &ctx, int throwOffset) {
    if (ctx.method == nullptr || ctx.currentException == nullptr) {
        LOGE("异常跳转失败：method或currentException为空");
        return false;
    }

    jclass exceptionClass = ctx.env->GetObjectClass(ctx.currentException);
    if (ctx.env->ExceptionCheck() || exceptionClass == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("异常跳转失败：获取异常类失败");
        return false;
    }

    for (const VmpTryBlock &tryBlock : ctx.method->tryBlocks) {
        int start = tryBlock.startCodeAddress;
        int end = tryBlock.startCodeAddress + tryBlock.codeUnitCount;

        if (throwOffset < start || throwOffset >= end) {
            continue;
        }

        for (const VmpExceptionHandler &handler : tryBlock.handlers) {
            bool match = false;

            // catch-all
            if (handler.exceptionType.empty()
                || handler.exceptionType == "Ljava/lang/Throwable;") {
                match = true;
            } else {
                jclass handlerClass = findVmClassForStatic(ctx.env, handler.exceptionType);
                if (handlerClass != nullptr) {
                    match = ctx.env->IsAssignableFrom(exceptionClass, handlerClass);
                    if (ctx.env->ExceptionCheck()) {
                        ctx.env->ExceptionClear();
                        match = false;
                    }
                }
            }

            if (!match) {
                continue;
            }

            int targetIndex = VmContext_FindInstructionIndexByOffset(
                    ctx,
                    handler.handlerCodeAddress
            );

            if (targetIndex < 0) {
                LOGE("异常跳转失败：找不到handler offset=%d",
                     handler.handlerCodeAddress);
                return false;
            }

            //LOGI("异常跳转成功 throwOffset=%d handlerOffset=%d targetIndex=%d type=%s",throwOffset,handler.handlerCodeAddress,targetIndex,handler.exceptionType.c_str());

            ctx.pc = targetIndex;
            return true;
        }
    }

    LOGE("异常未命中try-catch throwOffset=%d", throwOffset);
    return false;
}
//==================================================================================

//====================================指令实现区==================================
//指令 NOP
bool VmHandleNop(VmContext &ctx, const VmpInstruction &insn) {
    (void) insn;

    //LOGI("NOP");

    ctx.pc++;
    return true;
}

//指令 MOVE
bool VmHandleMove(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].intValue = ctx.regs[src].intValue;
    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("MOVE v%d <- v%d int=%d object=%p",dst,src,ctx.regs[dst].intValue,ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_FROM16
bool VmHandleMoveFrom16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_FROM16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].intValue = ctx.regs[src].intValue;
    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("MOVE_FROM16 v%d <- v%d int=%d object=%p",dst,src,ctx.regs[dst].intValue,ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_16
bool VmHandleMove16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].intValue = ctx.regs[src].intValue;
    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("MOVE_16 v%d <- v%d int=%d object=%p",dst,src,ctx.regs[dst].intValue,ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_WIDE
bool VmHandleMoveWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].intValue = ctx.regs[src].intValue;
    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("MOVE_WIDE v%d <- v%d long=%lld",dst,src,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 MOVE_WIDE_FROM16
bool VmHandleMoveWideFrom16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_WIDE_FROM16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("MOVE_WIDE_FROM16 v%d <- v%d long=%lld",dst,src,(long long) ctx.regs[dst].longValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_WIDE_16
bool VmHandleMoveWide16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_WIDE_16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].longValue = ctx.regs[src].longValue;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("MOVE_WIDE_16 v%d <- v%d long=%lld",dst,src,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}


//指令 MOVE_OBJECT
bool VmHandleMoveObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_OBJECT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].intValue = 0;
    ctx.regs[dst].longValue = 0;
    ctx.regs[dst].kind = VM_REG_OBJECT;

    //LOGI("MOVE_OBJECT v%d <- v%d object=%p", dst, src, ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_OBJECT_FROM16
bool VmHandleMoveObjectFrom16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_OBJECT_FROM16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("MOVE_OBJECT_FROM16 v%d <- v%d object=%p",dst,src,ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_OBJECT_16
bool VmHandleMoveObject16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MOVE_OBJECT_16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].objectValue = ctx.regs[src].objectValue;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("MOVE_OBJECT_16 v%d <- v%d object=%p",dst,src,ctx.regs[dst].objectValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_RESULT
bool VmHandleMoveResult(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MOVE_RESULT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    ctx.regs[dst].intValue = ctx.lastResultInt;
    ctx.regs[dst].longValue = ctx.lastResultInt;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("MOVE_RESULT v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 MOVE_RESULT_WIDE
bool VmHandleMoveResultWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MOVE_RESULT_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    ctx.regs[dst].longValue = ctx.lastResultLong;
    ctx.regs[dst].intValue = static_cast<int>(ctx.lastResultLong);
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("MOVE_RESULT_WIDE v%d=%lld",dst,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}


bool VmHandleMoveResultObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MOVE_RESULT_OBJECT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    ctx.regs[dst].intValue = 0;
    ctx.regs[dst].longValue = 0;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    if (ctx.lastResultObject != nullptr) {
        ctx.regs[dst].objectValue = ctx.env->NewGlobalRef(ctx.lastResultObject);

        if (ctx.env->ExceptionCheck() || ctx.regs[dst].objectValue == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("MOVE_RESULT_OBJECT 创建全局引用失败 v%d", dst);
            return false;
        }
    } else {
        ctx.regs[dst].objectValue = nullptr;
    }

    //LOGI("MOVE_RESULT_OBJECT v%d=%p text=%s",dst,ctx.regs[dst].objectValue,jstringToDebugString(ctx.env, ctx.regs[dst].objectValue).c_str());

    ctx.pc++;
    return true;
}

//指令 MOVE_EXCEPTION
bool VmHandleMoveException(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MOVE_EXCEPTION 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    ctx.regs[dst].objectValue = ctx.currentException;

    //LOGI("MOVE_EXCEPTION v%d=%p", dst, ctx.currentException);

    ctx.pc++;
    return true;
}

//指令 RETURN_VOID
bool VmHandleReturnVoid(VmContext &ctx, const VmpInstruction &insn) {
    (void) insn;

    //LOGI("RETURN_VOID");

    ctx.running = false;
    return true;
}

//指令 RETURN
bool VmHandleReturn(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("RETURN 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    ctx.result.intValue = ctx.regs[src].intValue;
    ctx.result.longValue = ctx.regs[src].intValue;
    ctx.result.floatValue = static_cast<jfloat>(ctx.regs[src].intValue);
    ctx.result.booleanValue = ctx.regs[src].intValue ? JNI_TRUE : JNI_FALSE;
    ctx.result.byteValue = static_cast<jbyte>(ctx.regs[src].intValue);
    ctx.result.shortValue = static_cast<jshort>(ctx.regs[src].intValue);
    ctx.result.charValue = static_cast<jchar>(ctx.regs[src].intValue);
    ctx.result.objectValue = nullptr;

    //LOGI("RETURN v%d int=%d",src,ctx.result.intValue);

    ctx.running = false;
    return true;
}

//指令 RETURN_WIDE
bool VmHandleReturnWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("RETURN_WIDE 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    ctx.result.longValue = ctx.regs[src].longValue;
    ctx.result.doubleValue = static_cast<jdouble>(ctx.regs[src].longValue);
    ctx.result.intValue = static_cast<jint>(ctx.regs[src].longValue);
    ctx.result.objectValue = nullptr;

    //LOGI("RETURN_WIDE v%d long=%lld",src,static_cast<long long>(ctx.result.longValue));

    ctx.running = false;
    return true;
}

//指令 RETURN_OBJECT
bool VmHandleReturnObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("RETURN_OBJECT 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    ctx.result.objectValue = ctx.regs[src].objectValue;

    //LOGI("RETURN_OBJECT v%d object=%p",src,ctx.result.objectValue);

    ctx.running = false;
    return true;
}

//指令 CONST_4
bool VmHandleConst4(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_4 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int value = static_cast<int>(insn.literalValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].kind = VM_REG_INT;
    // 关键修复：
    // const/4 vX, #0 在对象参数场景通常表示 null
    if (value == 0) {
        ctx.regs[dst].objectValue = nullptr;
    }

    //LOGI("CONST_4 v%d=%d", dst, value);

    ctx.pc++;
    return true;
}

//指令 CONST_16
bool VmHandleConst16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int value = static_cast<int>(insn.literalValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].kind = VM_REG_INT;
    if (value == 0) {
        ctx.regs[dst].objectValue = nullptr;
    }

    //LOGI("CONST_16 v%d=%d", dst, value);

    ctx.pc++;
    return true;
}
//指令 CONST
bool VmHandleConst(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int value = static_cast<int>(insn.literalValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].kind = VM_REG_INT;
    if (value == 0) {
        ctx.regs[dst].objectValue = nullptr;
    }

    //LOGI("CONST v%d=%d", dst, value);

    ctx.pc++;
    return true;
}
//指令 CONST_HIGH16
bool VmHandleConstHigh16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_HIGH16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    jint bits = static_cast<jint>(insn.literalValue);
    ctx.regs[dst].intValue = bits;
    ctx.regs[dst].longValue = bits;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    jfloat floatValue = 0;
    memcpy(&floatValue, &bits, sizeof(jfloat));
    //LOGI("CONST_HIGH16 v%d bits=0x%08x float=%f",dst,bits,floatValue);
    ctx.pc++;
    return true;
}
//指令 CONST_WIDE_16
bool VmHandleConstWide16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_WIDE_16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int64_t value = static_cast<int16_t>(insn.literalValue);

    ctx.regs[dst].longValue = value;
    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("CONST_WIDE_16 v%d=%lld",dst,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 CONST_WIDE_32
bool VmHandleConstWide32(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_WIDE_32 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int64_t value = static_cast<int32_t>(insn.literalValue);

    ctx.regs[dst].longValue = value;
    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("CONST_WIDE_32 v%d=%lld",dst,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 CONST_WIDE
bool VmHandleConstWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int64_t value = static_cast<int64_t>(insn.literalValue);

    ctx.regs[dst].longValue = value;
    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("CONST_WIDE v%d=%lld",dst,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 CONST_WIDE_HIGH16
bool VmHandleConstWideHigh16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_WIDE_HIGH16 寄存器数量不足");
        return false;
    }
    int dst = insn.registers[0];
    jlong bits = static_cast<jlong>(insn.literalValue);
    ctx.regs[dst].longValue = bits;
    ctx.regs[dst].intValue = static_cast<jint>(bits);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    jdouble doubleValue = 0;
    memcpy(&doubleValue, &bits, sizeof(jdouble));
    //LOGI("CONST_WIDE_HIGH16 v%d bits=0x%016llx double=%f",dst,static_cast<long long>(bits),doubleValue);
    ctx.pc++;
    return true;
}
bool VmHandleConstString(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_STRING 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    jobject strObj = ctx.env->NewStringUTF(insn.referenceData.c_str());
    if (ctx.env->ExceptionCheck() || strObj == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("CONST_STRING 创建字符串失败");
        return false;
    }

    ctx.regs[dst].objectValue = strObj;
    ctx.regs[dst].intValue = 0;
    ctx.regs[dst].longValue = 0;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("CONST_STRING v%d=%s", dst, insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 CONST_STRING_JUMBO
bool VmHandleConstStringJumbo(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_STRING_JUMBO 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    jobject strObj = ctx.env->NewStringUTF(insn.referenceData.c_str());
    if (ctx.env->ExceptionCheck() || strObj == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("CONST_STRING_JUMBO 创建字符串失败");
        return false;
    }

    ctx.regs[dst].objectValue = strObj;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("CONST_STRING_JUMBO v%d=%s", dst, insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 CONST_CLASS
bool VmHandleConstClass(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CONST_CLASS 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    jclass cls = findVmClassForStatic(ctx.env, insn.referenceData);
    if (cls == nullptr) {
        LOGE("CONST_CLASS 找不到类：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = cls;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("CONST_CLASS v%d=%p type=%s",dst,ctx.regs[dst].objectValue,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 MONITOR_ENTER
bool VmHandleMonitorEnter(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MONITOR_ENTER 寄存器数量不足");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("MONITOR_ENTER 对象为空 v%d", objReg);
        return false;
    }

    jint ret = ctx.env->MonitorEnter(obj);
    if (ret != JNI_OK || ctx.env->ExceptionCheck()) {
        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
        }

        LOGE("MONITOR_ENTER 进入监视器失败 v%d object=%p",
             objReg,
             obj);
        return false;
    }

    //LOGI("MONITOR_ENTER v%d object=%p",objReg,obj);

    ctx.pc++;
    return true;
}

//指令 MONITOR_EXIT
bool VmHandleMonitorExit(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("MONITOR_EXIT 寄存器数量不足");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("MONITOR_EXIT 对象为空 v%d", objReg);
        return false;
    }

    jint ret = ctx.env->MonitorExit(obj);
    if (ret != JNI_OK || ctx.env->ExceptionCheck()) {
        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
        }

        LOGE("MONITOR_EXIT 退出监视器失败 v%d object=%p",
             objReg,
             obj);
        return false;
    }

    //LOGI("MONITOR_EXIT v%d object=%p",objReg,obj);

    ctx.pc++;
    return true;
}

//指令 CHECK_CAST
bool VmHandleCheckCast(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("CHECK_CAST 寄存器数量不足");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        ctx.regs[objReg].kind = VM_REG_OBJECT;

        //LOGI("CHECK_CAST v%d object=null type=%s",objReg,insn.referenceData.c_str());

        ctx.pc++;
        return true;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, insn.referenceData);

    if (cls == nullptr) {
        LOGE("CHECK_CAST 找不到类：%s", insn.referenceData.c_str());
        return false;
    }

    jboolean ok = ctx.env->IsInstanceOf(obj, cls);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();

        LOGE("CHECK_CAST 类型检查异常：%s",
             insn.referenceData.c_str());
        return false;
    }

    if (!ok) {
        LOGE("CHECK_CAST 类型不匹配 v%d object=%p type=%s",
             objReg,
             obj,
             insn.referenceData.c_str());
        return false;
    }

    ctx.regs[objReg].kind = VM_REG_OBJECT;

    //LOGI("CHECK_CAST v%d object=%p type=%s",objReg,obj,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 INSTANCE_OF
bool VmHandleInstanceOf(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INSTANCE_OF 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        ctx.regs[dst].intValue = 0;
        ctx.regs[dst].longValue = 0;
        ctx.regs[dst].objectValue = nullptr;
        ctx.regs[dst].kind = VM_REG_INT;
        //LOGI("INSTANCE_OF v%d <- v%d null result=0", dst, objReg);

        ctx.pc++;
        return true;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, insn.referenceData);
    if (cls == nullptr) {
        LOGE("INSTANCE_OF 找不到类：%s", insn.referenceData.c_str());
        return false;
    }

    jboolean result = ctx.env->IsInstanceOf(obj, cls);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("INSTANCE_OF 判断失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = result == JNI_TRUE ? 1 : 0;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("INSTANCE_OF v%d <- v%d type=%s result=%d",dst,objReg,insn.referenceData.c_str(),ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 ARRAY_LENGTH
bool VmHandleArrayLength(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ARRAY_LENGTH 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    if (arrayObj == nullptr) {
        LOGE("ARRAY_LENGTH 数组对象为空 v%d", arrayReg);
        return false;
    }

    jsize length = ctx.env->GetArrayLength(static_cast<jarray>(arrayObj));
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("ARRAY_LENGTH 获取数组长度失败 v%d", arrayReg);
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(length);
    ctx.regs[dst].longValue = static_cast<int64_t>(length);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("ARRAY_LENGTH v%d <- length(v%d)=%d",dst,arrayReg,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}


//指令 NEW_INSTANCE
bool VmHandleNewInstance(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("NEW_INSTANCE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    jobject loaderBaseObj = ctx.thiz;
    if (loaderBaseObj == nullptr) {
        for (int i = 0; i < static_cast<int>(ctx.regs.size()); i++) {
            if (ctx.regs[i].objectValue != nullptr) {
                loaderBaseObj = ctx.regs[i].objectValue;
                break;
            }
        }
    }

    jclass cls = findVmClassForStatic(ctx.env, insn.referenceData);

    if (cls == nullptr && loaderBaseObj != nullptr) {
        cls = findClassByTypeWithObjectLoader(ctx.env, loaderBaseObj, insn.referenceData);
    }
    if (cls == nullptr) {
        LOGE("NEW_INSTANCE 找不到类：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.env->AllocObject(cls);
    if (ctx.env->ExceptionCheck() || obj == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("NEW_INSTANCE 创建对象失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = obj;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("NEW_INSTANCE v%d=%p type=%s", dst, obj, insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 NEW_ARRAY
bool VmHandleNewArray(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NEW_ARRAY 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int sizeReg = insn.registers[1];

    jint arraySize = ctx.regs[sizeReg].intValue;
    if (arraySize < 0) {
        LOGE("NEW_ARRAY 数组长度非法 v%d=%d", sizeReg, arraySize);
        return false;
    }

    jobject arrayObj = nullptr;

    if (insn.referenceData == "[Z") {
        arrayObj = ctx.env->NewBooleanArray(arraySize);
    } else if (insn.referenceData == "[B") {
        arrayObj = ctx.env->NewByteArray(arraySize);
    } else if (insn.referenceData == "[C") {
        arrayObj = ctx.env->NewCharArray(arraySize);
    } else if (insn.referenceData == "[S") {
        arrayObj = ctx.env->NewShortArray(arraySize);
    } else if (insn.referenceData == "[I") {
        arrayObj = ctx.env->NewIntArray(arraySize);
    } else if (insn.referenceData == "[J") {
        arrayObj = ctx.env->NewLongArray(arraySize);
    } else if (insn.referenceData == "[F") {
        arrayObj = ctx.env->NewFloatArray(arraySize);
    } else if (insn.referenceData == "[D") {
        arrayObj = ctx.env->NewDoubleArray(arraySize);
    } else if (!insn.referenceData.empty() && insn.referenceData[0] == '[') {
        std::string elementType = insn.referenceData.substr(1);

        jclass elementClass = findClassByType(ctx.env, elementType);
        if (elementClass == nullptr) {
            LOGE("NEW_ARRAY 找不到对象数组元素类：%s", elementType.c_str());
            return false;
        }

        arrayObj = ctx.env->NewObjectArray(arraySize, elementClass, nullptr);
    } else {
        LOGE("NEW_ARRAY 数组类型不支持：%s", insn.referenceData.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck() || arrayObj == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("NEW_ARRAY 创建数组失败 type=%s size=%d",
             insn.referenceData.c_str(),
             arraySize);
        return false;
    }

    ctx.regs[dst].objectValue = arrayObj;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("NEW_ARRAY v%d type=%s size=%d object=%p",dst,insn.referenceData.c_str(),arraySize,arrayObj);

    ctx.pc++;
    return true;
}
//指令 FILLED_NEW_ARRAY
bool VmHandleFilledNewArray(VmContext &ctx, const VmpInstruction &insn) {
    int count = static_cast<int>(insn.registers.size());

    std::string arrayType = insn.referenceData;
    if (arrayType.empty() || arrayType[0] != '[') {
        LOGE("FILLED_NEW_ARRAY 数组类型错误：%s", arrayType.c_str());
        return false;
    }

    jobject arrayObj = nullptr;
    char elementType = arrayType.length() > 1 ? arrayType[1] : 0;

    if (elementType == 'I') {
        jintArray arr = ctx.env->NewIntArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建 int 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jint value = ctx.regs[insn.registers[i]].intValue;
            ctx.env->SetIntArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'Z') {
        jbooleanArray arr = ctx.env->NewBooleanArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建 boolean 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jboolean value = ctx.regs[insn.registers[i]].intValue ? JNI_TRUE : JNI_FALSE;
            ctx.env->SetBooleanArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'B') {
        jbyteArray arr = ctx.env->NewByteArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建 byte 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jbyte value = static_cast<jbyte>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetByteArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'S') {
        jshortArray arr = ctx.env->NewShortArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建 short 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jshort value = static_cast<jshort>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetShortArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'C') {
        jcharArray arr = ctx.env->NewCharArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建 char 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jchar value = static_cast<jchar>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetCharArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'L' || elementType == '[') {
        std::string elementClassName;

        if (elementType == 'L') {
            elementClassName = arrayType.substr(2, arrayType.length() - 3);
        } else {
            elementClassName = arrayType.substr(1);
        }

        jclass elementClass = ctx.env->FindClass(elementClassName.c_str());
        if (elementClass == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 找不到对象数组元素类：%s", elementClassName.c_str());
            return false;
        }

        jobjectArray arr = ctx.env->NewObjectArray(count, elementClass, nullptr);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY 创建对象数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jobject value = ctx.regs[insn.registers[i]].objectValue;
            ctx.env->SetObjectArrayElement(arr, i, value);
        }

        arrayObj = arr;
    } else {
        LOGE("FILLED_NEW_ARRAY 暂不支持数组类型：%s", arrayType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("FILLED_NEW_ARRAY 填充数组失败");
        return false;
    }

    ctx.lastResultObject = arrayObj;

    //LOGI("FILLED_NEW_ARRAY result=%p count=%d type=%s",ctx.lastResultObject,count,arrayType.c_str());

    ctx.pc++;
    return true;
}

//指令 FILLED_NEW_ARRAY_RANGE
bool VmHandleFilledNewArrayRange(VmContext &ctx, const VmpInstruction &insn) {
    int count = static_cast<int>(insn.registers.size());

    std::string arrayType = insn.referenceData;
    if (arrayType.empty() || arrayType[0] != '[') {
        LOGE("FILLED_NEW_ARRAY_RANGE 数组类型错误：%s", arrayType.c_str());
        return false;
    }

    jobject arrayObj = nullptr;
    char elementType = arrayType.length() > 1 ? arrayType[1] : 0;

    if (elementType == 'I') {
        jintArray arr = ctx.env->NewIntArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建 int 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jint value = ctx.regs[insn.registers[i]].intValue;
            ctx.env->SetIntArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'Z') {
        jbooleanArray arr = ctx.env->NewBooleanArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建 boolean 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jboolean value = ctx.regs[insn.registers[i]].intValue ? JNI_TRUE : JNI_FALSE;
            ctx.env->SetBooleanArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'B') {
        jbyteArray arr = ctx.env->NewByteArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建 byte 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jbyte value = static_cast<jbyte>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetByteArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'S') {
        jshortArray arr = ctx.env->NewShortArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建 short 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jshort value = static_cast<jshort>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetShortArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'C') {
        jcharArray arr = ctx.env->NewCharArray(count);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建 char 数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jchar value = static_cast<jchar>(ctx.regs[insn.registers[i]].intValue);
            ctx.env->SetCharArrayRegion(arr, i, 1, &value);
        }

        arrayObj = arr;
    } else if (elementType == 'L' || elementType == '[') {
        std::string elementClassName;

        if (elementType == 'L') {
            elementClassName = arrayType.substr(2, arrayType.length() - 3);
        } else {
            elementClassName = arrayType.substr(1);
        }

        jclass elementClass = ctx.env->FindClass(elementClassName.c_str());
        if (elementClass == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 找不到对象数组元素类：%s", elementClassName.c_str());
            return false;
        }

        jobjectArray arr = ctx.env->NewObjectArray(count, elementClass, nullptr);
        if (arr == nullptr || ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILLED_NEW_ARRAY_RANGE 创建对象数组失败");
            return false;
        }

        for (int i = 0; i < count; i++) {
            jobject value = ctx.regs[insn.registers[i]].objectValue;
            ctx.env->SetObjectArrayElement(arr, i, value);
        }

        arrayObj = arr;
    } else {
        LOGE("FILLED_NEW_ARRAY_RANGE 暂不支持数组类型：%s", arrayType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("FILLED_NEW_ARRAY_RANGE 填充数组失败");
        return false;
    }

    ctx.lastResultObject = arrayObj;

    //LOGI("FILLED_NEW_ARRAY_RANGE result=%p count=%d type=%s",ctx.lastResultObject,count,arrayType.c_str());

    ctx.pc++;
    return true;
}

//指令 FILL_ARRAY_DATA
bool VmHandleFillArrayData(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("FILL_ARRAY_DATA 寄存器数量不足");
        return false;
    }

    int arrayReg = insn.registers[0];
    jobject arrayObj = ctx.regs[arrayReg].objectValue;

    if (arrayObj == nullptr) {
        LOGE("FILL_ARRAY_DATA 数组对象为空 v%d", arrayReg);
        return false;
    }

    if (ctx.method == nullptr) {
        LOGE("FILL_ARRAY_DATA method为空");
        return false;
    }

    int payloadOffset = insn.codeUnitOffset + insn.offsetValue;
    int payloadIndex = VmContext_FindInstructionIndexByOffset(ctx, payloadOffset);

    if (payloadIndex < 0 || payloadIndex >= static_cast<int>(ctx.method->instructions.size())) {
        LOGE("FILL_ARRAY_DATA 找不到payload offset=%d", payloadOffset);
        return false;
    }

    const VmpInstruction &payload = ctx.method->instructions[payloadIndex];

    if (payload.literalType != 100 || payload.offsetType != 100 || payload.referenceType != 100) {
        LOGE("FILL_ARRAY_DATA payload格式错误 offset=%d", payloadOffset);
        return false;
    }

    int elementWidth = static_cast<int>(payload.literalValue);
    int elementCount = payload.offsetValue;

    jarray arrayValue = static_cast<jarray>(arrayObj);
    jsize arrayLength = ctx.env->GetArrayLength(arrayValue);

    if (arrayLength < elementCount) {
        LOGE("FILL_ARRAY_DATA 数组长度不足 arrayLength=%d elementCount=%d",
             arrayLength,
             elementCount);
        return false;
    }

    const char *dataText = payload.referenceData.c_str();
    char *endPtr = nullptr;

    for (int i = 0; i < elementCount; i++) {
        long long value = strtoll(dataText, &endPtr, 10);

        if (dataText == endPtr) {
            LOGE("FILL_ARRAY_DATA 解析数组数据失败 index=%d", i);
            return false;
        }

        if (elementWidth == 1) {
            jbyte v = static_cast<jbyte>(value);
            ctx.env->SetByteArrayRegion(static_cast<jbyteArray>(arrayObj), i, 1, &v);
        } else if (elementWidth == 2) {
            jshort v = static_cast<jshort>(value);
            ctx.env->SetShortArrayRegion(static_cast<jshortArray>(arrayObj), i, 1, &v);
        } else if (elementWidth == 4) {
            jint v = static_cast<jint>(value);
            ctx.env->SetIntArrayRegion(static_cast<jintArray>(arrayObj), i, 1, &v);
        } else if (elementWidth == 8) {
            jlong v = static_cast<jlong>(value);
            ctx.env->SetLongArrayRegion(static_cast<jlongArray>(arrayObj), i, 1, &v);
        } else {
            LOGE("FILL_ARRAY_DATA 不支持的elementWidth=%d", elementWidth);
            return false;
        }

        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("FILL_ARRAY_DATA 写入数组失败 index=%d", i);
            return false;
        }

        dataText = endPtr;
        if (*dataText == ',') {
            dataText++;
        }
    }

    //LOGI("FILL_ARRAY_DATA v%d elementWidth=%d elementCount=%d",arrayReg,elementWidth,elementCount);

    ctx.pc++;
    return true;
}
//指令 THROW
bool VmHandleThrow(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("THROW 寄存器数量不足");
        return false;
    }

    int exceptionReg = insn.registers[0];
    jobject exceptionObj = ctx.regs[exceptionReg].objectValue;

    if (exceptionObj == nullptr) {
        LOGE("THROW 异常对象为空 v%d", exceptionReg);
        return false;
    }

    ctx.env->Throw(static_cast<jthrowable>(exceptionObj));

    if (ctx.env->ExceptionCheck()) {
        //LOGI("THROW v%d exception=%p", exceptionReg, exceptionObj);
        ctx.running = false;
        return true;
    }

    LOGE("THROW 抛出异常失败 v%d", exceptionReg);
    return false;
}

//指令 GOTO
bool VmHandleGoto(VmContext &ctx, const VmpInstruction &insn) {
    int targetOffset = insn.codeUnitOffset + insn.offsetValue;
    int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

    if (targetIndex < 0) {
        LOGE("GOTO 找不到目标 offset=%d currentOffset=%d jumpOffset=%d",
             targetOffset,
             insn.codeUnitOffset,
             insn.offsetValue);
        return false;
    }

    //LOGI("GOTO currentOffset=%d jumpOffset=%d targetOffset=%d targetIndex=%d",insn.codeUnitOffset,insn.offsetValue,targetOffset,targetIndex);

    ctx.pc = targetIndex;
    return true;
}

//指令 GOTO_16
bool VmHandleGoto16(VmContext &ctx, const VmpInstruction &insn) {
    int targetOffset = insn.codeUnitOffset + insn.offsetValue;
    int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

    if (targetIndex < 0) {
        LOGE("GOTO_16 找不到目标 offset=%d currentOffset=%d jumpOffset=%d",
             targetOffset,
             insn.codeUnitOffset,
             insn.offsetValue);
        return false;
    }

    //LOGI("GOTO_16 currentOffset=%d jumpOffset=%d targetOffset=%d targetIndex=%d",insn.codeUnitOffset,insn.offsetValue,targetOffset,targetIndex);

    ctx.pc = targetIndex;
    return true;
}

//指令 GOTO_32
bool VmHandleGoto32(VmContext &ctx, const VmpInstruction &insn) {
    int targetOffset = insn.codeUnitOffset + insn.offsetValue;
    int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

    if (targetIndex < 0) {
        LOGE("GOTO_32 找不到目标 offset=%d currentOffset=%d jumpOffset=%d",
             targetOffset,
             insn.codeUnitOffset,
             insn.offsetValue);
        return false;
    }

    //LOGI("GOTO_32 currentOffset=%d jumpOffset=%d targetOffset=%d targetIndex=%d",insn.codeUnitOffset,insn.offsetValue,targetOffset,targetIndex);

    ctx.pc = targetIndex;
    return true;
}
//指令 PACKED_SWITCH
bool VmHandlePackedSwitch(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("PACKED_SWITCH 寄存器数量不足");
        return false;
    }

    if (ctx.method == nullptr) {
        LOGE("PACKED_SWITCH method为空");
        return false;
    }

    int testReg = insn.registers[0];
    int testValue = ctx.regs[testReg].intValue;

    int payloadOffset = insn.codeUnitOffset + insn.offsetValue;
    int payloadIndex = VmContext_FindInstructionIndexByOffset(ctx, payloadOffset);

    if (payloadIndex < 0 || payloadIndex >= static_cast<int>(ctx.method->instructions.size())) {
        LOGE("PACKED_SWITCH 找不到payload offset=%d", payloadOffset);
        return false;
    }

    const VmpInstruction &payload = ctx.method->instructions[payloadIndex];

    if (payload.literalType != 101 || payload.offsetType != 101 || payload.referenceType != 101) {
        LOGE("PACKED_SWITCH payload格式错误 offset=%d", payloadOffset);
        return false;
    }

    const char *dataText = payload.referenceData.c_str();
    char *endPtr = nullptr;

    for (int i = 0; i < payload.offsetValue; i++) {
        long key = strtol(dataText, &endPtr, 10);

        if (dataText == endPtr) {
            LOGE("PACKED_SWITCH 解析key失败 index=%d", i);
            return false;
        }

        if (*endPtr != ':') {
            LOGE("PACKED_SWITCH 数据格式错误 index=%d", i);
            return false;
        }

        dataText = endPtr + 1;

        long targetOffset = strtol(dataText, &endPtr, 10);

        if (dataText == endPtr) {
            LOGE("PACKED_SWITCH 解析target失败 index=%d", i);
            return false;
        }

        if (testValue == static_cast<int>(key)) {
            int jumpOffset = insn.codeUnitOffset + static_cast<int>(targetOffset);
            int jumpIndex = VmContext_FindInstructionIndexByOffset(ctx, jumpOffset);

            if (jumpIndex < 0) {
                LOGE("PACKED_SWITCH 跳转目标不存在 offset=%d", jumpOffset);
                return false;
            }

            //LOGI("PACKED_SWITCH 命中 v%d=%d -> offset=%d",testReg,testValue,jumpOffset);

            ctx.pc = jumpIndex;
            return true;
        }

        dataText = endPtr;
        if (*dataText == ',') {
            dataText++;
        }
    }

    //LOGI("PACKED_SWITCH 未命中 v%d=%d", testReg, testValue);

    ctx.pc++;
    return true;
}

//指令 SPARSE_SWITCH
bool VmHandleSparseSwitch(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPARSE_SWITCH 寄存器数量不足");
        return false;
    }

    if (ctx.method == nullptr) {
        LOGE("SPARSE_SWITCH method为空");
        return false;
    }

    int testReg = insn.registers[0];
    int testValue = ctx.regs[testReg].intValue;

    int payloadOffset = insn.codeUnitOffset + insn.offsetValue;
    int payloadIndex = VmContext_FindInstructionIndexByOffset(ctx, payloadOffset);

    if (payloadIndex < 0 || payloadIndex >= static_cast<int>(ctx.method->instructions.size())) {
        LOGE("SPARSE_SWITCH 找不到payload offset=%d", payloadOffset);
        return false;
    }

    const VmpInstruction &payload = ctx.method->instructions[payloadIndex];

    if (payload.literalType != 102 || payload.offsetType != 102 || payload.referenceType != 102) {
        LOGE("SPARSE_SWITCH payload格式错误 offset=%d", payloadOffset);
        return false;
    }

    const char *dataText = payload.referenceData.c_str();
    char *endPtr = nullptr;

    for (int i = 0; i < payload.offsetValue; i++) {
        long key = strtol(dataText, &endPtr, 10);

        if (dataText == endPtr) {
            LOGE("SPARSE_SWITCH 解析key失败 index=%d", i);
            return false;
        }

        if (*endPtr != ':') {
            LOGE("SPARSE_SWITCH 数据格式错误 index=%d", i);
            return false;
        }

        dataText = endPtr + 1;

        long targetOffset = strtol(dataText, &endPtr, 10);

        if (dataText == endPtr) {
            LOGE("SPARSE_SWITCH 解析target失败 index=%d", i);
            return false;
        }

        if (testValue == static_cast<int>(key)) {
            int jumpOffset = insn.codeUnitOffset + static_cast<int>(targetOffset);
            int jumpIndex = VmContext_FindInstructionIndexByOffset(ctx, jumpOffset);

            if (jumpIndex < 0) {
                LOGE("SPARSE_SWITCH 跳转目标不存在 offset=%d", jumpOffset);
                return false;
            }

            //LOGI("SPARSE_SWITCH 命中 v%d=%d -> offset=%d",testReg,testValue,jumpOffset);

            ctx.pc = jumpIndex;
            return true;
        }

        dataText = endPtr;
        if (*dataText == ',') {
            dataText++;
        }
    }

    //LOGI("SPARSE_SWITCH 未命中 v%d=%d", testReg, testValue);

    ctx.pc++;
    return true;
}
//指令 CMPL_FLOAT
bool VmHandleCmplFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("CMPL_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    float v1 = static_cast<float>(ctx.regs[src1].intValue);
    float v2 = static_cast<float>(ctx.regs[src2].intValue);

    int result = 0;

    if (isnan(v1) || isnan(v2)) {
        result = -1;
    } else if (v1 > v2) {
        result = 1;
    } else if (v1 == v2) {
        result = 0;
    } else {
        result = -1;
    }

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("CMPL_FLOAT v%d <- compare v%d=%f v%d=%f result=%d",dst,src1,v1,src2,v2,result);

    ctx.pc++;
    return true;
}

//指令 CMPG_FLOAT
bool VmHandleCmpgFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("CMPG_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    float v1 = static_cast<float>(ctx.regs[src1].intValue);
    float v2 = static_cast<float>(ctx.regs[src2].intValue);

    int result = 0;

    if (isnan(v1) || isnan(v2)) {
        result = 1;
    } else if (v1 > v2) {
        result = 1;
    } else if (v1 == v2) {
        result = 0;
    } else {
        result = -1;
    }

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("CMPG_FLOAT v%d <- compare v%d=%f v%d=%f result=%d",dst,src1,v1,src2,v2,result);

    ctx.pc++;
    return true;
}

//指令 CMPL_DOUBLE
bool VmHandleCmplDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("CMPL_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    double v1 = static_cast<double>(ctx.regs[src1].longValue);
    double v2 = static_cast<double>(ctx.regs[src2].longValue);

    int result = 0;

    if (isnan(v1) || isnan(v2)) {
        result = -1;
    } else if (v1 > v2) {
        result = 1;
    } else if (v1 == v2) {
        result = 0;
    } else {
        result = -1;
    }

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("CMPL_DOUBLE v%d <- compare v%d=%lf v%d=%lf result=%d",dst,src1,v1,src2,v2,result);

    ctx.pc++;
    return true;
}

//指令 CMPG_DOUBLE
bool VmHandleCmpgDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("CMPG_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    double v1 = static_cast<double>(ctx.regs[src1].longValue);
    double v2 = static_cast<double>(ctx.regs[src2].longValue);

    int result = 0;

    if (isnan(v1) || isnan(v2)) {
        result = 1;
    } else if (v1 > v2) {
        result = 1;
    } else if (v1 == v2) {
        result = 0;
    } else {
        result = -1;
    }

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("CMPG_DOUBLE v%d <- compare v%d=%lf v%d=%lf result=%d",dst,src1,v1,src2,v2,result);

    ctx.pc++;
    return true;
}

//指令 CMP_LONG
bool VmHandleCmpLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("CMP_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    int64_t v1 = ctx.regs[src1].longValue;
    int64_t v2 = ctx.regs[src2].longValue;

    int result = 0;

    if (v1 > v2) {
        result = 1;
    } else if (v1 == v2) {
        result = 0;
    } else {
        result = -1;
    }

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("CMP_LONG v%d <- compare v%d=%lld v%d=%lld result=%d",dst,src1,static_cast<long long>(v1),src2,static_cast<long long>(v2),result);

    ctx.pc++;
    return true;
}
//指令 IF_EQ
bool VmHandleIfEq(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_EQ 寄存器数量不足");
        return false;
    }

    if (ctx.method == nullptr) {
        LOGE("IF_EQ method为空");
        return false;
    }

    int regA = insn.registers[0];
    int regB = insn.registers[1];

    int valueA = ctx.regs[regA].intValue;
    int valueB = ctx.regs[regB].intValue;

    if (valueA == valueB) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_EQ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_EQ 命中 v%d=%d v%d=%d -> offset=%d",regA,valueA,regB,valueB,targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_EQ 未命中 v%d=%d v%d=%d",regA,valueA,regB,valueB);

    ctx.pc++;
    return true;
}

//指令 IF_NE
bool VmHandleIfNe(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_NE 寄存器数量不足");
        return false;
    }

    if (ctx.method == nullptr) {
        LOGE("IF_NE method为空");
        return false;
    }

    int regA = insn.registers[0];
    int regB = insn.registers[1];

    int valueA = ctx.regs[regA].intValue;
    int valueB = ctx.regs[regB].intValue;

    if (valueA != valueB) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_NE 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_NE 命中 v%d=%d v%d=%d -> offset=%d",regA,valueA,regB,valueB,targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_NE 未命中 v%d=%d v%d=%d",regA,valueA,regB,valueB);

    ctx.pc++;
    return true;
}
//指令 IF_LT
bool VmHandleIfLt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_LT 寄存器数量不足");
        return false;
    }

    int leftReg = insn.registers[0];
    int rightReg = insn.registers[1];

    int leftValue = ctx.regs[leftReg].intValue;
    int rightValue = ctx.regs[rightReg].intValue;

    if (leftValue < rightValue) {
        int jumpOffset = insn.codeUnitOffset + insn.offsetValue;
        int jumpIndex = VmContext_FindInstructionIndexByOffset(ctx, jumpOffset);

        if (jumpIndex < 0) {
            LOGE("IF_LT 跳转目标不存在 offset=%d", jumpOffset);
            return false;
        }

        //LOGI("IF_LT 命中 v%d=%d v%d=%d -> offset=%d",leftReg,leftValue,rightReg,rightValue,jumpOffset);

        ctx.pc = jumpIndex;
        return true;
    }

    //LOGI("IF_LT 未命中 v%d=%d v%d=%d",leftReg,leftValue,rightReg,rightValue);

    ctx.pc++;
    return true;
}

//指令 IF_GE
bool VmHandleIfGe(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_GE 寄存器数量不足");
        return false;
    }

    int leftReg = insn.registers[0];
    int rightReg = insn.registers[1];

    int leftValue = ctx.regs[leftReg].intValue;
    int rightValue = ctx.regs[rightReg].intValue;

    if (leftValue >= rightValue) {
        int jumpOffset = insn.codeUnitOffset + insn.offsetValue;
        int jumpIndex = VmContext_FindInstructionIndexByOffset(ctx, jumpOffset);

        if (jumpIndex < 0) {
            LOGE("IF_GE 跳转目标不存在 offset=%d", jumpOffset);
            return false;
        }

        //LOGI("IF_GE 命中 v%d=%d v%d=%d -> offset=%d",leftReg,leftValue,rightReg,rightValue,jumpOffset);

        ctx.pc = jumpIndex;
        return true;
    }

    //LOGI("IF_GE 未命中 v%d=%d v%d=%d",leftReg,leftValue,rightReg,rightValue);

    ctx.pc++;
    return true;
}

//指令 IF_GT
bool VmHandleIfGt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_GT 寄存器数量不足");
        return false;
    }

    int leftReg = insn.registers[0];
    int rightReg = insn.registers[1];

    int leftValue = ctx.regs[leftReg].intValue;
    int rightValue = ctx.regs[rightReg].intValue;

    if (leftValue > rightValue) {
        int jumpOffset = insn.codeUnitOffset + insn.offsetValue;
        int jumpIndex = VmContext_FindInstructionIndexByOffset(ctx, jumpOffset);

        if (jumpIndex < 0) {
            LOGE("IF_GT 跳转目标不存在 offset=%d", jumpOffset);
            return false;
        }

        //LOGI("IF_GT 命中 v%d=%d v%d=%d -> offset=%d",leftReg,leftValue,rightReg,rightValue,jumpOffset);

        ctx.pc = jumpIndex;
        return true;
    }

    //LOGI("IF_GT 未命中 v%d=%d v%d=%d",leftReg,leftValue,rightReg,rightValue);

    ctx.pc++;
    return true;
}
//指令 IF_LE
bool VmHandleIfLe(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IF_LE 寄存器数量不足");
        return false;
    }

    int regA = insn.registers[0];
    int regB = insn.registers[1];

    int valueA = ctx.regs[regA].intValue;
    int valueB = ctx.regs[regB].intValue;

    if (valueA <= valueB) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_LE 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_LE 命中 v%d=%d <= v%d=%d -> offset=%d",regA,valueA,regB,valueB,targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_LE 未命中 v%d=%d > v%d=%d",regA,valueA,regB,valueB);

    ctx.pc++;
    return true;
}

//指令 IF_EQZ
bool VmHandleIfEqz(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_EQZ 寄存器数量不足");
        return false;
    }

    int regA = insn.registers[0];

    int intValue = ctx.regs[regA].intValue;
    jobject objectValue = ctx.regs[regA].objectValue;
    VmRegKind kind = ctx.regs[regA].kind;

    bool hit = false;

    if (kind == VM_REG_OBJECT) {
        hit = objectValue == nullptr;
    } else {
        hit = intValue == 0;
    }

    if (hit) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_EQZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_EQZ 命中 v%d kind=%d int=%d object=%p -> offset=%d",regA,static_cast<int>(kind),intValue,objectValue,targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_EQZ 未命中 v%d kind=%d int=%d object=%p",regA,static_cast<int>(kind),intValue,objectValue);

    ctx.pc++;
    return true;
}

//指令 IF_NEZ
bool VmHandleIfNez(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_NEZ 寄存器数量不足");
        return false;
    }

    int regA = insn.registers[0];

    int intValue = ctx.regs[regA].intValue;
    jobject objectValue = ctx.regs[regA].objectValue;

    if (intValue != 0 || objectValue != nullptr) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_NEZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_NEZ 命中 v%d int=%d object=%p -> offset=%d",regA,intValue,objectValue,targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_NEZ 未命中 v%d int=%d object=%p",regA,intValue,objectValue);

    ctx.pc++;
    return true;
}
//指令 IF_LTZ
bool VmHandleIfLtz(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_LTZ 寄存器数量不足");
        return false;
    }

    int reg = insn.registers[0];
    int value = ctx.regs[reg].intValue;

    if (value < 0) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_LTZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_LTZ 命中 v%d=%d -> offset=%d", reg, value, targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_LTZ 未命中 v%d=%d", reg, value);

    ctx.pc++;
    return true;
}

//指令 IF_GEZ
bool VmHandleIfGez(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_GEZ 寄存器数量不足");
        return false;
    }

    int reg = insn.registers[0];
    int value = ctx.regs[reg].intValue;

    if (value >= 0) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_GEZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_GEZ 命中 v%d=%d -> offset=%d", reg, value, targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_GEZ 未命中 v%d=%d", reg, value);

    ctx.pc++;
    return true;
}

//指令 IF_GTZ
bool VmHandleIfGtz(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_GTZ 寄存器数量不足");
        return false;
    }

    int reg = insn.registers[0];
    int value = ctx.regs[reg].intValue;

    if (value > 0) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_GTZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_GTZ 命中 v%d=%d -> offset=%d", reg, value, targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_GTZ 未命中 v%d=%d", reg, value);

    ctx.pc++;
    return true;
}

//指令 IF_LEZ
bool VmHandleIfLez(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("IF_LEZ 寄存器数量不足");
        return false;
    }

    int reg = insn.registers[0];
    int value = ctx.regs[reg].intValue;

    if (value <= 0) {
        int targetOffset = insn.codeUnitOffset + insn.offsetValue;
        int targetIndex = VmContext_FindInstructionIndexByOffset(ctx, targetOffset);

        if (targetIndex < 0) {
            LOGE("IF_LEZ 跳转目标不存在 offset=%d", targetOffset);
            return false;
        }

        //LOGI("IF_LEZ 命中 v%d=%d -> offset=%d", reg, value, targetOffset);

        ctx.pc = targetIndex;
        return true;
    }

    //LOGI("IF_LEZ 未命中 v%d=%d", reg, value);

    ctx.pc++;
    return true;
}
//指令 UNUSED_3E
bool VmHandleUnused3E(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;

    LOGE("UNUSED_3E 非法保留指令 offset=%d", insn.codeUnitOffset);

    return false;
}

//指令 UNUSED_3F
bool VmHandleUnused3F(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;

    LOGE("UNUSED_3F 非法保留指令 offset=%d", insn.codeUnitOffset);

    return false;
}

//指令 UNUSED_40
bool VmHandleUnused40(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;

    LOGE("UNUSED_40 非法保留指令 offset=%d", insn.codeUnitOffset);

    return false;
}

//指令 UNUSED_41
bool VmHandleUnused41(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;
    (void) insn;

    LOGE("UNUSED_41 非法保留指令 offset=%d", insn.codeUnitOffset);
    return false;
}

//指令 UNUSED_42
bool VmHandleUnused42(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;
    (void) insn;

    LOGE("UNUSED_42 非法保留指令 offset=%d", insn.codeUnitOffset);
    return false;
}

//指令 UNUSED_43
bool VmHandleUnused43(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;
    (void) insn;

    LOGE("UNUSED_43 非法保留指令 offset=%d", insn.codeUnitOffset);
    return false;
}
//指令 AGET
bool VmHandleAget(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;

    if (arrayObj == nullptr) {
        LOGE("AGET 数组对象为空 v%d", arrayReg);
        return false;
    }

    jint value = 0;
    ctx.env->GetIntArrayRegion(
            static_cast<jintArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET 读取数组失败 arrayReg=v%d index=%d", arrayReg, index);
        return false;
    }

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("AGET v%d <- v%d[v%d] index=%d value=%d",dst,arrayReg,indexReg,index,value);

    ctx.pc++;
    return true;
}

//指令 AGET_WIDE
bool VmHandleAgetWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;

    if (arrayObj == nullptr) {
        LOGE("AGET_WIDE 数组对象为空 v%d", arrayReg);
        return false;
    }

    jlong value = 0;
    ctx.env->GetLongArrayRegion(
            static_cast<jlongArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_WIDE 读取数组失败 arrayReg=v%d index=%d", arrayReg, index);
        return false;
    }

    ctx.regs[dst].longValue = value;
    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("AGET_WIDE v%d <- v%d[v%d] index=%d value=%lld",dst,arrayReg,indexReg,index,static_cast<long long>(value));

    ctx.pc++;
    return true;
}

//指令 AGET_OBJECT
bool VmHandleAgetObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_OBJECT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;

    if (arrayObj == nullptr) {
        LOGE("AGET_OBJECT 数组对象为空 v%d", arrayReg);
        return false;
    }

    jobject value = ctx.env->GetObjectArrayElement(
            static_cast<jobjectArray>(arrayObj),
            index
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_OBJECT 读取数组失败 arrayReg=v%d index=%d", arrayReg, index);
        return false;
    }

    ctx.regs[dst].objectValue = value;
    ctx.regs[dst].intValue = 0;
    ctx.regs[dst].longValue = 0;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("AGET_OBJECT v%d <- v%d[v%d] index=%d object=%p",dst,arrayReg,indexReg,index,value);

    ctx.pc++;
    return true;
}
//指令 AGET_BOOLEAN
bool VmHandleAgetBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_BOOLEAN 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jbooleanArray arrayObj = static_cast<jbooleanArray>(ctx.regs[arrayReg].objectValue);
    if (arrayObj == nullptr) {
        LOGE("AGET_BOOLEAN 数组对象为空 v%d", arrayReg);
        return false;
    }

    jint index = ctx.regs[indexReg].intValue;
    jsize length = ctx.env->GetArrayLength(arrayObj);

    if (index < 0 || index >= length) {
        LOGE("AGET_BOOLEAN 数组下标越界 index=%d length=%d", index, length);
        return false;
    }

    jboolean value = JNI_FALSE;
    ctx.env->GetBooleanArrayRegion(arrayObj, index, 1, &value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_BOOLEAN 读取数组失败");
        return false;
    }

    ctx.regs[dst].intValue = value ? 1 : 0;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("AGET_BOOLEAN v%d <- v%d[v%d] = %d",dst,arrayReg,indexReg,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 AGET_BYTE
bool VmHandleAgetByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_BYTE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jbyteArray arrayObj = static_cast<jbyteArray>(ctx.regs[arrayReg].objectValue);
    if (arrayObj == nullptr) {
        LOGE("AGET_BYTE 数组对象为空 v%d", arrayReg);
        return false;
    }

    jint index = ctx.regs[indexReg].intValue;
    jsize length = ctx.env->GetArrayLength(arrayObj);

    if (index < 0 || index >= length) {
        LOGE("AGET_BYTE 数组下标越界 index=%d length=%d", index, length);
        return false;
    }

    jbyte value = 0;
    ctx.env->GetByteArrayRegion(arrayObj, index, 1, &value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_BYTE 读取数组失败");
        return false;
    }

    ctx.regs[dst].intValue = static_cast<jint>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("AGET_BYTE v%d <- v%d[v%d] = %d",dst,arrayReg,indexReg,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 AGET_CHAR
bool VmHandleAgetChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_CHAR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jcharArray arrayObj = static_cast<jcharArray>(ctx.regs[arrayReg].objectValue);
    if (arrayObj == nullptr) {
        LOGE("AGET_CHAR 数组对象为空 v%d", arrayReg);
        return false;
    }

    jint index = ctx.regs[indexReg].intValue;
    jsize length = ctx.env->GetArrayLength(arrayObj);

    if (index < 0 || index >= length) {
        LOGE("AGET_CHAR 数组下标越界 index=%d length=%d", index, length);
        return false;
    }

    jchar value = 0;
    ctx.env->GetCharArrayRegion(arrayObj, index, 1, &value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_CHAR 读取数组失败");
        return false;
    }

    ctx.regs[dst].intValue = static_cast<jint>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("AGET_CHAR v%d <- v%d[v%d] = %d",dst,arrayReg,indexReg,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 AGET_SHORT
bool VmHandleAgetShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AGET_SHORT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jshortArray arrayObj = static_cast<jshortArray>(ctx.regs[arrayReg].objectValue);
    if (arrayObj == nullptr) {
        LOGE("AGET_SHORT 数组对象为空 v%d", arrayReg);
        return false;
    }

    jint index = ctx.regs[indexReg].intValue;
    jsize length = ctx.env->GetArrayLength(arrayObj);

    if (index < 0 || index >= length) {
        LOGE("AGET_SHORT 数组下标越界 index=%d length=%d", index, length);
        return false;
    }

    jshort value = 0;
    ctx.env->GetShortArrayRegion(arrayObj, index, 1, &value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("AGET_SHORT 读取数组失败");
        return false;
    }

    ctx.regs[dst].intValue = static_cast<jint>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("AGET_SHORT v%d <- v%d[v%d] = %d",dst,arrayReg,indexReg,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}


//指令 APUT
bool VmHandleAput(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jint intValue = ctx.regs[valueReg].intValue;

    if (arrayObj == nullptr) {
        LOGE("APUT 数组对象为空 v%d", arrayReg);
        return false;
    }

    jclass intArrayClass = ctx.env->FindClass("[I");
    jclass floatArrayClass = ctx.env->FindClass("[F");

    if (ctx.env->IsInstanceOf(arrayObj, intArrayClass)) {
        ctx.env->SetIntArrayRegion(
                static_cast<jintArray>(arrayObj),
                index,
                1,
                &intValue
        );
    } else if (ctx.env->IsInstanceOf(arrayObj, floatArrayClass)) {
        jfloat floatValue = intBitsToFloat(intValue);

        ctx.env->SetFloatArrayRegion(
                static_cast<jfloatArray>(arrayObj),
                index,
                1,
                &floatValue
        );
    } else {
        LOGE("APUT 不支持的数组类型 v%d", arrayReg);
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT v%d[%d] <- v%d intBits=%d",arrayReg,index,valueReg,intValue);

    ctx.pc++;
    return true;
}

//指令 APUT_WIDE
bool VmHandleAputWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_WIDE 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jlong longValue = ctx.regs[valueReg].longValue;

    if (arrayObj == nullptr) {
        LOGE("APUT_WIDE 数组对象为空 v%d", arrayReg);
        return false;
    }

    jclass longArrayClass = ctx.env->FindClass("[J");
    jclass doubleArrayClass = ctx.env->FindClass("[D");

    if (ctx.env->IsInstanceOf(arrayObj, longArrayClass)) {
        ctx.env->SetLongArrayRegion(
                static_cast<jlongArray>(arrayObj),
                index,
                1,
                &longValue
        );
    } else if (ctx.env->IsInstanceOf(arrayObj, doubleArrayClass)) {
        jdouble doubleValue = longBitsToDouble(longValue);

        ctx.env->SetDoubleArrayRegion(
                static_cast<jdoubleArray>(arrayObj),
                index,
                1,
                &doubleValue
        );
    } else {
        LOGE("APUT_WIDE 不支持的数组类型 v%d", arrayReg);
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_WIDE 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_WIDE v%d[%d] <- v%d longBits=%lld",arrayReg,index,valueReg,static_cast<long long>(longValue));

    ctx.pc++;
    return true;
}

//指令 APUT_OBJECT
bool VmHandleAputObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_OBJECT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jobject value = ctx.regs[valueReg].objectValue;

    if (arrayObj == nullptr) {
        LOGE("APUT_OBJECT 数组对象为空 v%d", arrayReg);
        return false;
    }

    jobjectArray arrayValue = static_cast<jobjectArray>(arrayObj);
    ctx.env->SetObjectArrayElement(arrayValue, index, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_OBJECT 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_OBJECT v%d[%d] <- v%d object=%p",arrayReg,index,valueReg,value);

    ctx.pc++;
    return true;
}
//指令 APUT_BOOLEAN
bool VmHandleAputBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_BOOLEAN 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jboolean value = ctx.regs[valueReg].intValue ? JNI_TRUE : JNI_FALSE;

    if (arrayObj == nullptr) {
        LOGE("APUT_BOOLEAN 数组对象为空 v%d", arrayReg);
        return false;
    }

    ctx.env->SetBooleanArrayRegion(
            static_cast<jbooleanArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_BOOLEAN 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_BOOLEAN v%d[%d] <- v%d value=%d",arrayReg,index,valueReg,value);

    ctx.pc++;
    return true;
}

//指令 APUT_BYTE
bool VmHandleAputByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_BYTE 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jbyte value = static_cast<jbyte>(ctx.regs[valueReg].intValue);

    if (arrayObj == nullptr) {
        LOGE("APUT_BYTE 数组对象为空 v%d", arrayReg);
        return false;
    }

    ctx.env->SetByteArrayRegion(
            static_cast<jbyteArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_BYTE 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_BYTE v%d[%d] <- v%d value=%d",arrayReg,index,valueReg,value);

    ctx.pc++;
    return true;
}

//指令 APUT_CHAR
bool VmHandleAputChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_CHAR 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jchar value = static_cast<jchar>(ctx.regs[valueReg].intValue);

    if (arrayObj == nullptr) {
        LOGE("APUT_CHAR 数组对象为空 v%d", arrayReg);
        return false;
    }

    ctx.env->SetCharArrayRegion(
            static_cast<jcharArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_CHAR 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_CHAR v%d[%d] <- v%d value=%d",arrayReg,index,valueReg,value);

    ctx.pc++;
    return true;
}
//指令 APUT_SHORT
bool VmHandleAputShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("APUT_SHORT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int arrayReg = insn.registers[1];
    int indexReg = insn.registers[2];

    jobject arrayObj = ctx.regs[arrayReg].objectValue;
    int index = ctx.regs[indexReg].intValue;
    jshort value = static_cast<jshort>(ctx.regs[valueReg].intValue);

    if (arrayObj == nullptr) {
        LOGE("APUT_SHORT 数组对象为空 v%d", arrayReg);
        return false;
    }

    ctx.env->SetShortArrayRegion(
            static_cast<jshortArray>(arrayObj),
            index,
            1,
            &value
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("APUT_SHORT 写入数组失败 v%d[%d]=v%d", arrayReg, index, valueReg);
        return false;
    }

    //LOGI("APUT_SHORT v%d[%d] <- v%d short=%d",arrayReg,index,valueReg,value);

    ctx.pc++;
    return true;
}

//指令 IGET
bool VmHandleIget(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];
    ctx.regs[dst].kind = VM_REG_INT;
    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    if (fieldType == "I") {
        jint value = ctx.env->GetIntField(obj, fieldId);
        ctx.regs[dst].intValue = value;
        ctx.regs[dst].longValue = value;
    } else if (fieldType == "F") {
        jfloat value = ctx.env->GetFloatField(obj, fieldId);
        jint bits = 0;
        memcpy(&bits, &value, sizeof(jint));
        ctx.regs[dst].intValue = bits;
        ctx.regs[dst].longValue = bits;
    } else if (fieldType == "Z") {
        jboolean value = ctx.env->GetBooleanField(obj, fieldId);
        ctx.regs[dst].intValue = value ? 1 : 0;
        ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    } else if (fieldType == "B") {
        jbyte value = ctx.env->GetByteField(obj, fieldId);
        ctx.regs[dst].intValue = value;
        ctx.regs[dst].longValue = value;
    } else if (fieldType == "S") {
        jshort value = ctx.env->GetShortField(obj, fieldId);
        ctx.regs[dst].intValue = value;
        ctx.regs[dst].longValue = value;
    } else if (fieldType == "C") {
        jchar value = ctx.env->GetCharField(obj, fieldId);
        ctx.regs[dst].intValue = value;
        ctx.regs[dst].longValue = value;
    } else {
        LOGE("IGET 不支持的字段类型：%s", fieldType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = nullptr;

    //LOGI("IGET v%d <- v%d.%s value=%d",dst,objReg,fieldName.c_str(),ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 IGET_WIDE
bool VmHandleIgetWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_WIDE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_WIDE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_WIDE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_WIDE 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    if (fieldType == "J") {
        jlong value = ctx.env->GetLongField(obj, fieldId);
        ctx.regs[dst].longValue = value;
        ctx.regs[dst].intValue = static_cast<jint>(value);
    } else if (fieldType == "D") {
        jdouble value = ctx.env->GetDoubleField(obj, fieldId);
        jlong bits = 0;
        memcpy(&bits, &value, sizeof(jlong));
        ctx.regs[dst].longValue = bits;
        ctx.regs[dst].intValue = static_cast<jint>(bits);
    } else {
        LOGE("IGET_WIDE 不支持的字段类型：%s", fieldType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_WIDE 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("IGET_WIDE v%d <- v%d.%s longBits=%lld",dst,objReg,fieldName.c_str(),static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}




//指令 IGET_OBJECT
bool VmHandleIgetObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_OBJECT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_OBJECT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_OBJECT 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_OBJECT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_OBJECT 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jobject value = ctx.env->GetObjectField(obj, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_OBJECT 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = value;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("IGET_OBJECT v%d=%p", dst, value);

    ctx.pc++;
    return true;
}
//指令 IGET_BOOLEAN
bool VmHandleIgetBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_BOOLEAN 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_BOOLEAN 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_BOOLEAN 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_BOOLEAN 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_BOOLEAN 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jboolean value = ctx.env->GetBooleanField(obj, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_BOOLEAN 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = value ? 1 : 0;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("IGET_BOOLEAN v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 IGET_BYTE
bool VmHandleIgetByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_BYTE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_BYTE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_BYTE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_BYTE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_BYTE 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jbyte value = ctx.env->GetByteField(obj, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_BYTE 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("IGET_BYTE v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 IGET_CHAR
bool VmHandleIgetChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_CHAR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_CHAR 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_CHAR 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_CHAR 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_CHAR 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jchar value = ctx.env->GetCharField(obj, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_CHAR 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("IGET_CHAR v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 IGET_SHORT
bool VmHandleIgetShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IGET_SHORT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IGET_SHORT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IGET_SHORT 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IGET_SHORT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IGET_SHORT 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jshort value = ctx.env->GetShortField(obj, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IGET_SHORT 读取字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_INT;
    //LOGI("IGET_SHORT v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 IPUT
bool VmHandleIput(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jint value = ctx.regs[valueReg].intValue;

    if (fieldType == "Z") {
        ctx.env->SetBooleanField(obj, fieldId, value ? JNI_TRUE : JNI_FALSE);
    } else if (fieldType == "B") {
        ctx.env->SetByteField(obj, fieldId, static_cast<jbyte>(value));
    } else if (fieldType == "S") {
        ctx.env->SetShortField(obj, fieldId, static_cast<jshort>(value));
    } else if (fieldType == "C") {
        ctx.env->SetCharField(obj, fieldId, static_cast<jchar>(value));
    } else if (fieldType == "I") {
        ctx.env->SetIntField(obj, fieldId, value);
    } else if (fieldType == "F") {
        jfloat floatValue;
        memcpy(&floatValue, &value, sizeof(jfloat));
        ctx.env->SetFloatField(obj, fieldId, floatValue);
    } else {
        LOGE("IPUT 不支持的字段类型：%s", fieldType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT v%d -> v%d.%s type=%s value=%d",valueReg,objReg,fieldName.c_str(),fieldType.c_str(),value);

    ctx.pc++;
    return true;
}

//指令 IPUT_WIDE
bool VmHandleIputWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_WIDE 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_WIDE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_WIDE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_WIDE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_WIDE 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jlong value = ctx.regs[valueReg].longValue;

    if (fieldType == "J") {
        ctx.env->SetLongField(obj, fieldId, value);
    } else if (fieldType == "D") {
        jdouble doubleValue;
        memcpy(&doubleValue, &value, sizeof(jdouble));
        ctx.env->SetDoubleField(obj, fieldId, doubleValue);
    } else {
        LOGE("IPUT_WIDE 不支持的字段类型：%s", fieldType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_WIDE 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_WIDE v%d -> v%d.%s type=%s longBits=%lld",valueReg,objReg,fieldName.c_str(),fieldType.c_str(),static_cast<long long>(value));

    ctx.pc++;
    return true;
}

//指令 IPUT_OBJECT
bool VmHandleIputObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_OBJECT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_OBJECT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_OBJECT 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_OBJECT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_OBJECT 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jobject value = ctx.regs[valueReg].objectValue;

    ctx.env->SetObjectField(obj, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_OBJECT 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_OBJECT v%d -> v%d.%s object=%p",valueReg,objReg,fieldName.c_str(),value);

    ctx.pc++;
    return true;
}
//指令 IPUT_BOOLEAN
bool VmHandleIputBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_BOOLEAN 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_BOOLEAN 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_BOOLEAN 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_BOOLEAN 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_BOOLEAN 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jboolean value = ctx.regs[valueReg].intValue ? JNI_TRUE : JNI_FALSE;
    ctx.env->SetBooleanField(obj, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_BOOLEAN 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_BOOLEAN v%d -> v%d.%s value=%d",valueReg,objReg,fieldName.c_str(),value ? 1 : 0);

    ctx.pc++;
    return true;
}

//指令 IPUT_BYTE
bool VmHandleIputByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_BYTE 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_BYTE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_BYTE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_BYTE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_BYTE 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jbyte value = static_cast<jbyte>(ctx.regs[valueReg].intValue);
    ctx.env->SetByteField(obj, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_BYTE 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_BYTE v%d -> v%d.%s value=%d",valueReg,objReg,fieldName.c_str(),static_cast<int>(value));

    ctx.pc++;
    return true;
}

//指令 IPUT_CHAR
bool VmHandleIputChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_CHAR 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_CHAR 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_CHAR 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_CHAR 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_CHAR 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jchar value = static_cast<jchar>(ctx.regs[valueReg].intValue);
    ctx.env->SetCharField(obj, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_CHAR 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_CHAR v%d -> v%d.%s value=%d",valueReg,objReg,fieldName.c_str(),static_cast<int>(value));

    ctx.pc++;
    return true;
}

//指令 IPUT_SHORT
bool VmHandleIputShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("IPUT_SHORT 寄存器数量不足");
        return false;
    }

    int valueReg = insn.registers[0];
    int objReg = insn.registers[1];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("IPUT_SHORT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject obj = ctx.regs[objReg].objectValue;
    if (obj == nullptr) {
        LOGE("IPUT_SHORT 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("IPUT_SHORT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            fieldId = ctx.env->GetFieldID(objCls, fieldName.c_str(), fieldType.c_str());
        }

        if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("IPUT_SHORT 找不到字段：%s", insn.referenceData.c_str());
            return false;
        }
    }

    jshort value = static_cast<jshort>(ctx.regs[valueReg].intValue);
    ctx.env->SetShortField(obj, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("IPUT_SHORT 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("IPUT_SHORT v%d -> v%d.%s value=%d",valueReg,objReg,fieldName.c_str(),static_cast<int>(value));

    ctx.pc++;
    return true;
}
//指令 SGET
bool VmHandleSget(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);

    if (cls == nullptr) {
        LOGE("SGET 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jint value = ctx.env->GetStaticIntField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SGET v%d=%d field=%s",dst,value,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 SGET_WIDE
bool VmHandleSgetWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_WIDE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_WIDE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SGET_WIDE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_WIDE 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    if (fieldType == "D") {
        jdouble doubleValue = ctx.env->GetStaticDoubleField(cls, fieldId);
        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("SGET_WIDE 读取double静态字段失败：%s", insn.referenceData.c_str());
            return false;
        }

        jlong bits;
        memcpy(&bits, &doubleValue, sizeof(jlong));

        ctx.regs[dst].longValue = bits;
        ctx.regs[dst].intValue = static_cast<jint>(bits);
    } else {
        jlong value = ctx.env->GetStaticLongField(cls, fieldId);
        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("SGET_WIDE 读取long静态字段失败：%s", insn.referenceData.c_str());
            return false;
        }

        ctx.regs[dst].longValue = value;
        ctx.regs[dst].intValue = static_cast<jint>(value);
    }

    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("SGET_WIDE v%d=%lld field=%s",dst,static_cast<long long>(ctx.regs[dst].longValue),insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 SGET_OBJECT
bool VmHandleSgetObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_OBJECT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_OBJECT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);

    if (cls == nullptr) {
        LOGE("SGET_OBJECT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_OBJECT 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jobject value = ctx.env->GetStaticObjectField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET_OBJECT 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].objectValue = value;
    ctx.regs[dst].intValue = 0;
    ctx.regs[dst].longValue = 0;
    ctx.regs[dst].kind = VM_REG_OBJECT;
    //LOGI("SGET_OBJECT v%d=%p field=%s",dst,value,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 SGET_BOOLEAN
bool VmHandleSgetBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_BOOLEAN 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_BOOLEAN 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SGET_BOOLEAN 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_BOOLEAN 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jboolean value = ctx.env->GetStaticBooleanField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET_BOOLEAN 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = value ? 1 : 0;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SGET_BOOLEAN v%d=%d field=%s",dst,ctx.regs[dst].intValue,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 SGET_BYTE
bool VmHandleSgetByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_BYTE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_BYTE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SGET_BYTE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_BYTE 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jbyte value = ctx.env->GetStaticByteField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET_BYTE 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = static_cast<int64_t>(value);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SGET_BYTE v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 SGET_CHAR
bool VmHandleSgetChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_CHAR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_CHAR 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SGET_CHAR 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_CHAR 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jchar value = ctx.env->GetStaticCharField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET_CHAR 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = static_cast<int64_t>(value);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SGET_CHAR v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 SGET_SHORT
bool VmHandleSgetShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SGET_SHORT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SGET_SHORT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SGET_SHORT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SGET_SHORT 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jshort value = ctx.env->GetStaticShortField(cls, fieldId);
    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SGET_SHORT 读取静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.regs[dst].intValue = static_cast<int>(value);
    ctx.regs[dst].longValue = static_cast<int64_t>(value);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SGET_SHORT v%d=%d", dst, ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 SPUT
bool VmHandleSput(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    if (fieldType == "F") {
        jfloat value;
        jint bits = ctx.regs[src].intValue;
        memcpy(&value, &bits, sizeof(jfloat));
        ctx.env->SetStaticFloatField(cls, fieldId, value);
    } else {
        jint value = ctx.regs[src].intValue;
        ctx.env->SetStaticIntField(cls, fieldId, value);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT 写入静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT %s <- v%d int=%d",insn.referenceData.c_str(),src,ctx.regs[src].intValue);

    ctx.pc++;
    return true;
}
//指令 SPUT_WIDE
bool VmHandleSputWide(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_WIDE 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_WIDE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT_WIDE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_WIDE 找不到字段：%s", insn.referenceData.c_str());
        return false;
    }

    if (fieldType == "J") {
        ctx.env->SetStaticLongField(cls, fieldId, ctx.regs[src].longValue);
    } else if (fieldType == "D") {
        jdouble value;
        jlong bits = ctx.regs[src].longValue;
        memcpy(&value, &bits, sizeof(jdouble));
        ctx.env->SetStaticDoubleField(cls, fieldId, value);
    } else {
        LOGE("SPUT_WIDE 不支持的字段类型：%s", fieldType.c_str());
        return false;
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_WIDE 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_WIDE %s longBits=%lld",insn.referenceData.c_str(),static_cast<long long>(ctx.regs[src].longValue));

    ctx.pc++;
    return true;
}

//指令 SPUT_OBJECT
//指令 SPUT_OBJECT
bool VmHandleSputObject(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_OBJECT 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_OBJECT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject loaderBaseObj = ctx.thiz;
    if (loaderBaseObj == nullptr) {
        for (int i = 0; i < static_cast<int>(ctx.regs.size()); i++) {
            if (ctx.regs[i].objectValue != nullptr) {
                loaderBaseObj = ctx.regs[i].objectValue;
                break;
            }
        }
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);

    if (cls == nullptr && loaderBaseObj != nullptr) {
        cls = findClassByTypeWithObjectLoader(ctx.env, loaderBaseObj, classType);
    }

    if (cls == nullptr) {
        LOGE("SPUT_OBJECT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_OBJECT 找不到字段：%s", insn.referenceData.c_str());
        return false;
    }

    ctx.env->SetStaticObjectField(cls, fieldId, ctx.regs[src].objectValue);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_OBJECT 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_OBJECT %s object=%p",insn.referenceData.c_str(),ctx.regs[src].objectValue);

    ctx.pc++;
    return true;
}

//指令 SPUT_BOOLEAN
bool VmHandleSputBoolean(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_BOOLEAN 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_BOOLEAN 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (fieldType != "Z") {
        LOGE("SPUT_BOOLEAN 字段类型不匹配：%s", fieldType.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT_BOOLEAN 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_BOOLEAN 找不到字段：%s", insn.referenceData.c_str());
        return false;
    }

    jboolean value = ctx.regs[src].intValue ? JNI_TRUE : JNI_FALSE;
    ctx.env->SetStaticBooleanField(cls, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_BOOLEAN 写入字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_BOOLEAN %s value=%d",insn.referenceData.c_str(),value);

    ctx.pc++;
    return true;
}
//指令 SPUT_BYTE
bool VmHandleSputByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_BYTE 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_BYTE 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT_BYTE 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_BYTE 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jbyte value = static_cast<jbyte>(ctx.regs[src].intValue);
    ctx.env->SetStaticByteField(cls, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_BYTE 写入静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_BYTE %s <- v%d byte=%d",insn.referenceData.c_str(),src,static_cast<int>(value));

    ctx.pc++;
    return true;
}

//指令 SPUT_CHAR
bool VmHandleSputChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_CHAR 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_CHAR 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT_CHAR 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_CHAR 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jchar value = static_cast<jchar>(ctx.regs[src].intValue);
    ctx.env->SetStaticCharField(cls, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_CHAR 写入静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_CHAR %s <- v%d char=%d",insn.referenceData.c_str(),src,static_cast<int>(value));

    ctx.pc++;
    return true;
}

//指令 SPUT_SHORT
bool VmHandleSputShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 1) {
        LOGE("SPUT_SHORT 寄存器数量不足");
        return false;
    }

    int src = insn.registers[0];

    std::string classType;
    std::string fieldName;
    std::string fieldType;

    if (!parseFieldReference(insn.referenceData, classType, fieldName, fieldType)) {
        LOGE("SPUT_SHORT 字段引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);
    if (cls == nullptr) {
        LOGE("SPUT_SHORT 找不到类：%s", classType.c_str());
        return false;
    }

    jfieldID fieldId = ctx.env->GetStaticFieldID(cls, fieldName.c_str(), fieldType.c_str());
    if (ctx.env->ExceptionCheck() || fieldId == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_SHORT 找不到静态字段：%s", insn.referenceData.c_str());
        return false;
    }

    jshort value = static_cast<jshort>(ctx.regs[src].intValue);
    ctx.env->SetStaticShortField(cls, fieldId, value);

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("SPUT_SHORT 写入静态字段失败：%s", insn.referenceData.c_str());
        return false;
    }

    //LOGI("SPUT_SHORT %s <- v%d short=%d",insn.referenceData.c_str(),src,static_cast<int>(value));

    ctx.pc++;
    return true;
}
static std::vector<std::string> parseParamTypesFromSignature(const std::string &signature) {
    std::vector<std::string> result;

    size_t start = signature.find('(');
    size_t end = signature.find(')');

    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return result;
    }

    size_t i = start + 1;

    while (i < end) {
        char c = signature[i];

        if (c == 'Z' || c == 'B' || c == 'S' || c == 'C' ||
            c == 'I' || c == 'J' || c == 'F' || c == 'D') {
            result.push_back(signature.substr(i, 1));
            i++;
        } else if (c == 'L') {
            size_t semi = signature.find(';', i);
            if (semi == std::string::npos || semi > end) {
                break;
            }
            result.push_back(signature.substr(i, semi - i + 1));
            i = semi + 1;
        } else if (c == '[') {
            size_t arrayStart = i;
            while (i < end && signature[i] == '[') {
                i++;
            }

            if (i >= end) {
                break;
            }

            if (signature[i] == 'L') {
                size_t semi = signature.find(';', i);
                if (semi == std::string::npos || semi > end) {
                    break;
                }
                result.push_back(signature.substr(arrayStart, semi - arrayStart + 1));
                i = semi + 1;
            } else {
                result.push_back(signature.substr(arrayStart, i - arrayStart + 1));
                i++;
            }
        } else {
            break;
        }
    }

    return result;
}


//指令 INVOKE
bool VmHandleInvokeCommon(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("INVOKE 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), signature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE 找不到方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValueArgs(ctx, insn, paramTypes, args)) {
        return false;
    }

    const jvalue *argArray = args.empty() ? nullptr : args.data();
    std::string returnType = getReturnTypeFromSignature(signature);

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;
    if (classType == "Ljava/lang/String;" && methodName == "equals") {
        std::string left = jstringToDebugString(ctx.env, obj);
        std::string right = "null";

        if (!insn.registers.empty() && insn.registers.size() >= 2) {
            int argReg = insn.registers[1];
            right = jstringToDebugString(ctx.env, ctx.regs[argReg].objectValue);
        }

        //LOGI("DEBUG String.equals 左边=%s", left.c_str());
        //LOGI("DEBUG String.equals 右边=%s", right.c_str());
    }
    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argArray);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argArray);
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argArray);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();

        LOGE("INVOKE 调用失败：%s", insn.referenceData.c_str());
        logAndClearJavaException(ctx.env, "INVOKE");
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    if (!ctx.lastResultObject && returnType != "V") {
        //LOGI("INVOKE 调用完成：%s returnType=%s intResult=%d longResult=%lld",insn.referenceData.c_str(),returnType.c_str(),ctx.lastResultInt,static_cast<long long>(ctx.lastResultLong));
    } else {
        //LOGI("INVOKE 调用完成：%s returnType=%s objectResult=%p objectText=%s",insn.referenceData.c_str(),returnType.c_str(),ctx.lastResultObject,jstringToDebugString(ctx.env, ctx.lastResultObject).c_str());
    }

    ctx.pc++;
    return true;
}

//指令 INVOKE_DIRECT
bool VmHandleInvokeDirect(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_DIRECT 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_DIRECT 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_DIRECT 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);
    if (cls == nullptr) {
        LOGE("INVOKE_DIRECT 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), signature.c_str());
            if (!ctx.env->ExceptionCheck() && mid != nullptr) {
                cls = objCls;
            }
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_DIRECT 找不到方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValueArgs(ctx, insn, paramTypes, args)) {
        return false;
    }


    int logRegIndex = 1;

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        int reg = insn.registers[logRegIndex];
        const std::string &type = paramTypes[i];

        //LOGI("INVOKE_DIRECT 参数 index=%d type=%s reg=v%d int=%d long=%lld object=%p",i,type.c_str(),reg,ctx.regs[reg].intValue,static_cast<long long>(ctx.regs[reg].longValue),ctx.regs[reg].objectValue);

        if (type == "J" || type == "D") {
            logRegIndex += 2;
        } else {
            logRegIndex++;
        }
    }

    const jvalue *argArray = args.empty() ? nullptr : args.data();
    std::string returnType = getReturnTypeFromSignature(signature);

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    if (returnType == "V") {
        ctx.env->CallNonvirtualVoidMethodA(obj, cls, mid, argArray);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallNonvirtualBooleanMethodA(obj, cls, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallNonvirtualByteMethodA(obj, cls, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallNonvirtualShortMethodA(obj, cls, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallNonvirtualCharMethodA(obj, cls, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallNonvirtualIntMethodA(obj, cls, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallNonvirtualLongMethodA(obj, cls, mid, argArray);
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallNonvirtualFloatMethodA(obj, cls, mid, argArray);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallNonvirtualDoubleMethodA(obj, cls, mid, argArray);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallNonvirtualObjectMethodA(obj, cls, mid, argArray);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();

        LOGE("INVOKE_DIRECT 调用失败：%s", insn.referenceData.c_str());
        logAndClearJavaException(ctx.env, "INVOKE_DIRECT");

        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }

        return false;
    }
    //LOGI("INVOKE_DIRECT 当前pc=%d ref=%s", ctx.pc, insn.referenceData.c_str());
    //LOGI("INVOKE_DIRECT 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 INVOKE_SUPER
bool VmHandleInvokeSuper(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_SUPER 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_SUPER 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_SUPER 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jobject loaderBaseObj = ctx.thiz;
    if (loaderBaseObj == nullptr) {
        loaderBaseObj = obj;
    }

    jclass superCls = findVmClassForStatic(ctx.env, classType);

    if (superCls == nullptr && loaderBaseObj != nullptr) {
        superCls = findClassByTypeWithObjectLoader(ctx.env, loaderBaseObj, classType);
    }

    if (superCls == nullptr) {
        LOGE("INVOKE_SUPER 找不到父类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(
            superCls,
            methodName.c_str(),
            signature.c_str()
    );

    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_SUPER 找不到方法：%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<std::string> paramTypes = parseParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValueArgs(ctx, insn, paramTypes, args)) {
        LOGE("INVOKE_SUPER buildJValueArgs失败，尝试buildJValueArgsFromMethod");
        if (!buildJValueArgsFromMethod(ctx, paramTypes, args)) {
            LOGE("INVOKE_SUPER 构造参数失败：%s", insn.referenceData.c_str());
            return false;
        }
    }

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    std::string returnType = getReturnTypeFromSignature(signature);
    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallNonvirtualVoidMethodA(obj, superCls, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallNonvirtualBooleanMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallNonvirtualByteMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallNonvirtualShortMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallNonvirtualCharMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallNonvirtualIntMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallNonvirtualLongMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallNonvirtualFloatMethodA(obj, superCls, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallNonvirtualDoubleMethodA(obj, superCls, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallNonvirtualObjectMethodA(obj, superCls, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_SUPER 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    ctx.pc++;
    return true;
}
//指令 INVOKE_INTERFACE
bool VmHandleInvokeInterface(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_INTERFACE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_INTERFACE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_INTERFACE 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);
    if (cls == nullptr) {
        LOGE("INVOKE_INTERFACE 找不到接口类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), signature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_INTERFACE 找不到方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseMethodParamTypes(signature);
    std::string returnType = parseMethodReturnType(signature);

    if (insn.registers.size() - 1 < paramTypes.size()) {
        LOGE("INVOKE_INTERFACE 参数寄存器数量不足 ref=%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<jvalue> args;
    args.resize(paramTypes.size());

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        int reg = insn.registers[i + 1];
        const std::string &type = paramTypes[i];

        memset(&args[i], 0, sizeof(jvalue));

        if (type == "Z") {
            args[i].z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
        } else if (type == "B") {
            args[i].b = static_cast<jbyte>(ctx.regs[reg].intValue);
        } else if (type == "S") {
            args[i].s = static_cast<jshort>(ctx.regs[reg].intValue);
        } else if (type == "C") {
            args[i].c = static_cast<jchar>(ctx.regs[reg].intValue);
        } else if (type == "I") {
            args[i].i = static_cast<jint>(ctx.regs[reg].intValue);
        } else if (type == "J") {
            args[i].j = static_cast<jlong>(ctx.regs[reg].longValue);
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[reg].intValue);
            memcpy(&args[i].f, &bits, sizeof(jfloat));
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[reg].longValue);
            memcpy(&args[i].d, &bits, sizeof(jdouble));
        } else {
            args[i].l = ctx.regs[reg].objectValue;
        }
    }

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argPtr);
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_INTERFACE 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    //LOGI("INVOKE_INTERFACE 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 UNUSED_73
bool VmHandleUnused73(VmContext &ctx, const VmpInstruction &insn) {
    (void) insn;

    //LOGI("UNUSED_73");

    ctx.pc++;
    return true;
}

//指令 INVOKE_VIRTUAL_RANGE
bool VmHandleInvokeVirtualRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_VIRTUAL_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_VIRTUAL_RANGE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_VIRTUAL_RANGE 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("INVOKE_VIRTUAL_RANGE 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), signature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_VIRTUAL_RANGE 找不到方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseParameterTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValuesFromRegisters(ctx, paramTypes, insn.registers, 1, args)) {
        LOGE("INVOKE_VIRTUAL_RANGE 构造参数失败：%s", insn.referenceData.c_str());
        return false;
    }

    std::string returnType = getReturnTypeFromSignature(signature);

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argPtr);
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argPtr);
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argPtr);
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argPtr);
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argPtr);
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argPtr);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        //ctx.env->ExceptionClear();
        LOGE("INVOKE_VIRTUAL_RANGE 调用失败：%s", insn.referenceData.c_str());
        logAndClearJavaException(ctx.env, "INVOKE_VIRTUAL_RANGE");
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    //LOGI("INVOKE_VIRTUAL_RANGE 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 INVOKE_SUPER_RANGE
bool VmHandleInvokeSuperRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_SUPER_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_SUPER_RANGE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_SUPER_RANGE 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jobject loaderBaseObj = ctx.thiz;
    if (loaderBaseObj == nullptr) {
        loaderBaseObj = obj;
    }

    jclass superCls = findVmClassForStatic(ctx.env, classType);

    if (superCls == nullptr && loaderBaseObj != nullptr) {
        superCls = findClassByTypeWithObjectLoader(ctx.env, loaderBaseObj, classType);
    }

    if (superCls == nullptr) {
        LOGE("INVOKE_SUPER_RANGE 找不到父类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(
            superCls,
            methodName.c_str(),
            signature.c_str()
    );

    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_SUPER_RANGE 找不到方法：%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<std::string> paramTypes = parseMethodParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValuesFromRegisters(ctx, paramTypes, insn.registers, 1, args)) {
        LOGE("INVOKE_SUPER_RANGE buildJValuesFromRegisters失败，尝试buildJValueArgsFromMethod");
        if (!buildJValueArgsFromMethod(ctx, paramTypes, args)) {
            LOGE("INVOKE_SUPER_RANGE 构造参数失败：%s", insn.referenceData.c_str());
            return false;
        }
    }

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    std::string returnType = getMethodReturnTypeFromSignature(signature);
    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallNonvirtualVoidMethodA(obj, superCls, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallNonvirtualBooleanMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallNonvirtualByteMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallNonvirtualShortMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallNonvirtualCharMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallNonvirtualIntMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallNonvirtualLongMethodA(obj, superCls, mid, argPtr);
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallNonvirtualFloatMethodA(obj, superCls, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallNonvirtualDoubleMethodA(obj, superCls, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallNonvirtualObjectMethodA(obj, superCls, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_SUPER_RANGE 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    ctx.pc++;
    return true;
}
//指令 INVOKE_STATIC_RANGE
bool VmHandleInvokeStaticRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_STATIC_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jobject loaderBaseObj = ctx.thiz;
    if (loaderBaseObj == nullptr) {
        for (int i = 0; i < static_cast<int>(ctx.regs.size()); i++) {
            if (ctx.regs[i].objectValue != nullptr) {
                loaderBaseObj = ctx.regs[i].objectValue;
                break;
            }
        }
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);

    if (cls == nullptr && loaderBaseObj != nullptr) {
        cls = findClassByTypeWithObjectLoader(ctx.env, loaderBaseObj, classType);
    }
    if (cls == nullptr) {
        LOGE("INVOKE_STATIC_RANGE 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetStaticMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_STATIC_RANGE 找不到静态方法：%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<std::string> paramTypes = parseMethodParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValuesFromRegisters(ctx, paramTypes, insn.registers, 0, args)) {
        return false;
    }

    std::string returnType = getMethodReturnTypeFromSignature(signature);

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallStaticVoidMethodA(cls, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallStaticBooleanMethodA(cls, mid, argPtr);
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallStaticByteMethodA(cls, mid, argPtr);
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallStaticShortMethodA(cls, mid, argPtr);
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallStaticCharMethodA(cls, mid, argPtr);
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallStaticIntMethodA(cls, mid, argPtr);
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallStaticLongMethodA(cls, mid, argPtr);
    } else if (returnType == "F") {
        jfloat ret = ctx.env->CallStaticFloatMethodA(cls, mid, argPtr);
        memcpy(&ctx.lastResultInt, &ret, sizeof(jfloat));
    } else if (returnType == "D") {
        jdouble ret = ctx.env->CallStaticDoubleMethodA(cls, mid, argPtr);
        memcpy(&ctx.lastResultLong, &ret, sizeof(jdouble));
    } else {
        ctx.lastResultObject = ctx.env->CallStaticObjectMethodA(cls, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_STATIC_RANGE 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    //LOGI("INVOKE_STATIC_RANGE 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}

//指令 INVOKE_INTERFACE_RANGE
bool VmHandleInvokeInterfaceRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_INTERFACE_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.size() < 1) {
        LOGE("INVOKE_INTERFACE_RANGE 寄存器数量不足");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_INTERFACE_RANGE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);
    if (cls == nullptr) {
        LOGE("INVOKE_INTERFACE_RANGE 找不到接口类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), signature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_INTERFACE_RANGE 找不到接口方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseMethodParamTypesFromSignature(signature);
    std::vector<jvalue> args;

    if (!buildJValuesFromRegisters(ctx, paramTypes, insn.registers, 1, args)) {
        return false;
    }

    std::string returnType = getMethodReturnTypeFromSignature(signature);

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argPtr);
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argPtr);
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argPtr);
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argPtr);
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argPtr);
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argPtr);
    } else if (returnType == "F") {
        jfloat ret = ctx.env->CallFloatMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultInt, &ret, sizeof(jfloat));
    } else if (returnType == "D") {
        jdouble ret = ctx.env->CallDoubleMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultLong, &ret, sizeof(jdouble));
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_INTERFACE_RANGE 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    //LOGI("INVOKE_INTERFACE_RANGE 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}
//指令 UNUSED_79
bool VmHandleUnused79(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;

    LOGE("UNUSED_79 非法指令 offset=%d vmOpcode=0x%02x",
         insn.codeUnitOffset,
         insn.vmOpcode);

    return false;
}

//指令 UNUSED_7A
bool VmHandleUnused7A(VmContext &ctx, const VmpInstruction &insn) {
    (void) ctx;

    LOGE("UNUSED_7A 非法指令 offset=%d vmOpcode=0x%02x",
         insn.codeUnitOffset,
         insn.vmOpcode);

    return false;
}
//指令 NEG_INT
bool VmHandleNegInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NEG_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint value = ctx.regs[src].intValue;
    jint result = -value;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NEG_INT v%d <- -v%d result=%d",dst,src,result);

    ctx.pc++;
    return true;
}

//指令 NOT_INT
bool VmHandleNotInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NOT_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint value = ctx.regs[src].intValue;
    jint result = ~value;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NOT_INT v%d <- ~v%d result=%d",dst,src,result);

    ctx.pc++;
    return true;
}

//指令 NEG_LONG
bool VmHandleNegLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NEG_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong value = ctx.regs[src].longValue;
    jlong result = -value;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NEG_LONG v%d <- -v%d result=%lld",dst,src,static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 NOT_LONG
bool VmHandleNotLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NOT_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong value = ctx.regs[src].longValue;
    jlong result = ~value;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NOT_LONG v%d <- ~v%d result=%lld",dst,src,static_cast<long long>(result));

    ctx.pc++;
    return true;
}
//指令 NEG_FLOAT
bool VmHandleNegFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NEG_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat srcValue = intBitsToFloat(ctx.regs[src].intValue);
    jfloat resultValue = -srcValue;

    memcpy(&ctx.regs[dst].intValue, &resultValue, sizeof(jfloat));
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NEG_FLOAT v%d <- -v%d value=%f",dst,src,resultValue);

    ctx.pc++;
    return true;
}

//指令 NEG_DOUBLE
bool VmHandleNegDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("NEG_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble srcValue = longBitsToDouble(ctx.regs[src].longValue);
    jdouble resultValue = -srcValue;

    memcpy(&ctx.regs[dst].longValue, &resultValue, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("NEG_DOUBLE v%d <- -v%d value=%f",dst,src,resultValue);

    ctx.pc++;
    return true;
}
//指令 INT_TO_LONG
bool VmHandleIntToLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint intValue = ctx.regs[src].intValue;
    jlong longValue = static_cast<jlong>(intValue);

    ctx.regs[dst].longValue = longValue;
    ctx.regs[dst].intValue = static_cast<jint>(longValue);
    ctx.regs[dst].objectValue = nullptr;
    ctx.regs[dst].kind = VM_REG_LONG;
    //LOGI("INT_TO_LONG v%d <- v%d int=%d long=%lld",dst,src,intValue,static_cast<long long>(longValue));

    ctx.pc++;
    return true;
}
//指令 INT_TO_FLOAT
bool VmHandleIntToFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint intValue = ctx.regs[src].intValue;
    jfloat floatValue = static_cast<jfloat>(intValue);

    jint floatBits = 0;
    memcpy(&floatBits, &floatValue, sizeof(jint));

    ctx.regs[dst].intValue = floatBits;
    ctx.regs[dst].longValue = static_cast<jlong>(floatBits);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("INT_TO_FLOAT v%d <- v%d int=%d floatBits=%d",dst,src,intValue,floatBits);

    ctx.pc++;
    return true;
}

//指令 INT_TO_DOUBLE
bool VmHandleIntToDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint intValue = ctx.regs[src].intValue;
    jdouble doubleValue = static_cast<jdouble>(intValue);

    jlong doubleBits = 0;
    memcpy(&doubleBits, &doubleValue, sizeof(jlong));

    ctx.regs[dst].longValue = doubleBits;
    ctx.regs[dst].intValue = static_cast<jint>(doubleBits);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("INT_TO_DOUBLE v%d <- v%d int=%d doubleBits=%lld",dst,src,intValue,static_cast<long long>(doubleBits));

    ctx.pc++;
    return true;
}




//指令 LONG_TO_INT
bool VmHandleLongToInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("LONG_TO_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong srcValue = ctx.regs[src].longValue;
    jint result = static_cast<jint>(srcValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("LONG_TO_INT v%d <- v%d long=%lld int=%d",dst,src,static_cast<long long>(srcValue),result);

    ctx.pc++;
    return true;
}

//指令 LONG_TO_FLOAT
bool VmHandleLongToFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("LONG_TO_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong srcValue = ctx.regs[src].longValue;
    jfloat resultFloat = static_cast<jfloat>(srcValue);

    jint resultBits = 0;
    memcpy(&resultBits, &resultFloat, sizeof(jint));

    ctx.regs[dst].intValue = resultBits;
    ctx.regs[dst].longValue = resultBits;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("LONG_TO_FLOAT v%d <- v%d long=%lld float=%f bits=%d",dst,src,static_cast<long long>(srcValue),resultFloat,resultBits);

    ctx.pc++;
    return true;
}

//指令 LONG_TO_DOUBLE
bool VmHandleLongToDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("LONG_TO_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong srcValue = ctx.regs[src].longValue;
    jdouble resultDouble = static_cast<jdouble>(srcValue);

    jlong resultBits = 0;
    memcpy(&resultBits, &resultDouble, sizeof(jlong));

    ctx.regs[dst].longValue = resultBits;
    ctx.regs[dst].intValue = static_cast<jint>(resultBits);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("LONG_TO_DOUBLE v%d <- v%d long=%lld double=%f bits=%lld",dst,src,static_cast<long long>(srcValue),resultDouble,static_cast<long long>(resultBits));

    ctx.pc++;
    return true;
}
//指令 FLOAT_TO_INT
bool VmHandleFloatToInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("FLOAT_TO_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint bits = ctx.regs[src].intValue;
    jfloat floatValue = 0;

    memcpy(&floatValue, &bits, sizeof(jfloat));

    jint intValue = static_cast<jint>(floatValue);

    ctx.regs[dst].intValue = intValue;
    ctx.regs[dst].longValue = intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("FLOAT_TO_INT v%d <- v%d float=%f int=%d",dst,src,floatValue,intValue);

    ctx.pc++;
    return true;
}
//指令 FLOAT_TO_LONG
bool VmHandleFloatToLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("FLOAT_TO_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat srcValue = VmBitsToFloatForConvert(ctx.regs[src].intValue);
    jlong result = static_cast<jlong>(srcValue);

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("FLOAT_TO_LONG v%d <- v%d float=%f long=%lld",dst,src,srcValue,static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 FLOAT_TO_DOUBLE
bool VmHandleFloatToDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("FLOAT_TO_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat srcValue = VmBitsToFloatForConvert(ctx.regs[src].intValue);
    jdouble resultDouble = static_cast<jdouble>(srcValue);
    jlong resultBits = VmDoubleToBitsForConvert(resultDouble);

    ctx.regs[dst].longValue = resultBits;
    ctx.regs[dst].intValue = static_cast<jint>(resultBits);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("FLOAT_TO_DOUBLE v%d <- v%d float=%f double=%lf bits=%lld",dst,src,srcValue,resultDouble,static_cast<long long>(resultBits));

    ctx.pc++;
    return true;
}

//指令 DOUBLE_TO_INT
bool VmHandleDoubleToInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DOUBLE_TO_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble srcValue = VmBitsToDoubleForConvert(ctx.regs[src].longValue);
    jint result = static_cast<jint>(srcValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DOUBLE_TO_INT v%d <- v%d double=%lf int=%d",dst,src,srcValue,result);

    ctx.pc++;
    return true;
}

//指令 DOUBLE_TO_LONG
bool VmHandleDoubleToLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DOUBLE_TO_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble srcValue = VmBitsToDoubleForConvert(ctx.regs[src].longValue);
    jlong result = static_cast<jlong>(srcValue);

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DOUBLE_TO_LONG v%d <- v%d double=%lf long=%lld",dst,src,srcValue,static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 DOUBLE_TO_FLOAT
bool VmHandleDoubleToFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DOUBLE_TO_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble srcValue = VmBitsToDoubleForConvert(ctx.regs[src].longValue);
    jfloat resultFloat = static_cast<jfloat>(srcValue);
    jint resultBits = VmFloatToBitsForConvert(resultFloat);

    ctx.regs[dst].intValue = resultBits;
    ctx.regs[dst].longValue = resultBits;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DOUBLE_TO_FLOAT v%d <- v%d double=%lf float=%f bits=%d",dst,src,srcValue,resultFloat,resultBits);

    ctx.pc++;
    return true;
}
//指令 INT_TO_BYTE
bool VmHandleIntToByte(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_BYTE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int value = static_cast<int8_t>(ctx.regs[src].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("INT_TO_BYTE v%d <- v%d value=%d",dst,src,value);

    ctx.pc++;
    return true;
}

//指令 INT_TO_CHAR
bool VmHandleIntToChar(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_CHAR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int value = static_cast<uint16_t>(ctx.regs[src].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("INT_TO_CHAR v%d <- v%d value=%d",dst,src,value);

    ctx.pc++;
    return true;
}

//指令 INT_TO_SHORT
bool VmHandleIntToShort(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("INT_TO_SHORT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int value = static_cast<int16_t>(ctx.regs[src].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("INT_TO_SHORT v%d <- v%d value=%d",dst,src,value);

    ctx.pc++;
    return true;
}
//指令 ADD_INT
bool VmHandleAddInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("ADD_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint value = static_cast<jint>(ctx.regs[src1].intValue + ctx.regs[src2].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_INT v%d <- v%d + v%d = %d",dst,src1,src2,value);

    ctx.pc++;
    return true;
}

//指令 SUB_INT
bool VmHandleSubInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SUB_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint value = static_cast<jint>(ctx.regs[src1].intValue - ctx.regs[src2].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_INT v%d <- v%d - v%d = %d",dst,src1,src2,value);

    ctx.pc++;
    return true;
}

//指令 MUL_INT
bool VmHandleMulInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("MUL_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint value = static_cast<jint>(ctx.regs[src1].intValue * ctx.regs[src2].intValue);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_INT v%d <- v%d * v%d = %d",dst,src1,src2,value);

    ctx.pc++;
    return true;
}

//指令 DIV_INT
bool VmHandleDivInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("DIV_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint right = ctx.regs[src2].intValue;

    if (right == 0) {
        LOGE("DIV_INT 除数为0 v%d", src2);
        return false;
    }

    jint value = static_cast<jint>(ctx.regs[src1].intValue / right);

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_INT v%d <- v%d / v%d = %d",dst,src1,src2,value);

    ctx.pc++;
    return true;
}
//指令 REM_INT
bool VmHandleRemInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("REM_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint left = ctx.regs[src1].intValue;
    jint right = ctx.regs[src2].intValue;

    if (right == 0) {
        LOGE("REM_INT 除数为0 v%d", src2);
        return false;
    }

    ctx.regs[dst].intValue = left % right;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_INT v%d <- v%d %% v%d result=%d",dst,src1,src2,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 AND_INT
bool VmHandleAndInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AND_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint left = ctx.regs[src1].intValue;
    jint right = ctx.regs[src2].intValue;

    ctx.regs[dst].intValue = left & right;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("AND_INT v%d <- v%d & v%d result=%d",dst,src1,src2,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}

//指令 OR_INT
bool VmHandleOrInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("OR_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint left = ctx.regs[src1].intValue;
    jint right = ctx.regs[src2].intValue;

    ctx.regs[dst].intValue = left | right;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("OR_INT v%d <- v%d | v%d result=%d",dst,src1,src2,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 XOR_INT
bool VmHandleXorInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("XOR_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    ctx.regs[dst].intValue = ctx.regs[src1].intValue ^ ctx.regs[src2].intValue;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("XOR_INT v%d = v%d ^ v%d -> %d",dst,src1,src2,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 SHL_INT
bool VmHandleShlInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SHL_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint left = ctx.regs[src1].intValue;
    jint right = ctx.regs[src2].intValue & 0x1f;
    jint result = left << right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHL_INT v%d = v%d(%d) << v%d(%d) = %d",dst, src1, left, src2, right, result);

    ctx.pc++;
    return true;
}

//指令 SHR_INT
bool VmHandleShrInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SHR_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jint left = ctx.regs[src1].intValue;
    jint right = ctx.regs[src2].intValue & 0x1f;
    jint result = left >> right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHR_INT v%d = v%d(%d) >> v%d(%d) = %d",dst, src1, left, src2, right, result);

    ctx.pc++;
    return true;
}

//指令 USHR_INT
bool VmHandleUshrInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("USHR_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    uint32_t left = static_cast<uint32_t>(ctx.regs[src1].intValue);
    jint right = ctx.regs[src2].intValue & 0x1f;
    jint result = static_cast<jint>(left >> right);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("USHR_INT v%d = v%d(%u) >>> v%d(%d) = %d",dst, src1, left, src2, right, result);

    ctx.pc++;
    return true;
}

//指令 ADD_LONG
bool VmHandleAddLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("ADD_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jlong right = ctx.regs[src2].longValue;
    jlong result = left + right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_LONG v%d = v%d(%lld) + v%d(%lld) = %lld",dst,src1,static_cast<long long>(left),src2,static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 SUB_LONG
bool VmHandleSubLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SUB_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jlong right = ctx.regs[src2].longValue;
    jlong result = left - right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_LONG v%d = v%d(%lld) - v%d(%lld) = %lld",dst,src1,static_cast<long long>(left),src2,static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 MUL_LONG
bool VmHandleMulLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("MUL_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jlong right = ctx.regs[src2].longValue;
    jlong result = left * right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_LONG v%d = v%d(%lld) * v%d(%lld) = %lld",dst,src1,static_cast<long long>(left),src2,static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}
//指令 DIV_LONG
bool VmHandleDivLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("DIV_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jlong right = ctx.regs[src2].longValue;

    if (right == 0) {
        LOGE("DIV_LONG 除数为0");
        return false;
    }

    ctx.regs[dst].longValue = left / right;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_LONG v%d = v%d / v%d -> %lld",dst,src1,src2,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 REM_LONG
bool VmHandleRemLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("REM_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jlong right = ctx.regs[src2].longValue;

    if (right == 0) {
        LOGE("REM_LONG 除数为0");
        return false;
    }

    ctx.regs[dst].longValue = left % right;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_LONG v%d = v%d %% v%d -> %lld",dst,src1,src2,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 AND_LONG
bool VmHandleAndLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("AND_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    ctx.regs[dst].longValue = ctx.regs[src1].longValue & ctx.regs[src2].longValue;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("AND_LONG v%d = v%d & v%d -> %lld",dst,src1,src2,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 OR_LONG
bool VmHandleOrLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("OR_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    ctx.regs[dst].longValue = ctx.regs[src1].longValue | ctx.regs[src2].longValue;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("OR_LONG v%d = v%d | v%d -> %lld",dst,src1,src2,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 XOR_LONG
bool VmHandleXorLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("XOR_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    ctx.regs[dst].longValue = ctx.regs[src1].longValue ^ ctx.regs[src2].longValue;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("XOR_LONG v%d = v%d ^ v%d -> %lld",dst,src1,src2,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 SHL_LONG
bool VmHandleShlLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SHL_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong value = ctx.regs[src1].longValue;
    jint shift = ctx.regs[src2].intValue & 0x3f;

    ctx.regs[dst].longValue = value << shift;
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHL_LONG v%d = v%d << %d -> %lld",dst,src1,shift,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}
//指令 SHR_LONG
bool VmHandleShrLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SHR_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jlong left = ctx.regs[src1].longValue;
    jint shift = ctx.regs[src2].intValue & 0x3f;

    jlong result = left >> shift;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHR_LONG v%d = v%d >> v%d result=%lld",dst,src1,src2,static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 USHR_LONG
bool VmHandleUshrLong(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("USHR_LONG 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    uint64_t left = static_cast<uint64_t>(ctx.regs[src1].longValue);
    jint shift = ctx.regs[src2].intValue & 0x3f;

    jlong result = static_cast<jlong>(left >> shift);

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("USHR_LONG v%d = v%d >>> v%d result=%lld",dst,src1,src2,static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 ADD_FLOAT
bool VmHandleAddFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("ADD_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jfloat left = vmIntBitsToFloatValue(ctx.regs[src1].intValue);
    jfloat right = vmIntBitsToFloatValue(ctx.regs[src2].intValue);
    jfloat result = left + right;

    ctx.regs[dst].intValue = vmFloatToIntBitsValue(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_FLOAT v%d = v%d + v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 SUB_FLOAT
bool VmHandleSubFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SUB_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jfloat left = vmIntBitsToFloatValue(ctx.regs[src1].intValue);
    jfloat right = vmIntBitsToFloatValue(ctx.regs[src2].intValue);
    jfloat result = left - right;

    ctx.regs[dst].intValue = vmFloatToIntBitsValue(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_FLOAT v%d = v%d - v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 MUL_FLOAT
bool VmHandleMulFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("MUL_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jfloat left = vmIntBitsToFloatValue(ctx.regs[src1].intValue);
    jfloat right = vmIntBitsToFloatValue(ctx.regs[src2].intValue);
    jfloat result = left * right;

    ctx.regs[dst].intValue = vmFloatToIntBitsValue(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_FLOAT v%d = v%d * v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 DIV_FLOAT
bool VmHandleDivFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("DIV_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jfloat left = vmIntBitsToFloatValue(ctx.regs[src1].intValue);
    jfloat right = vmIntBitsToFloatValue(ctx.regs[src2].intValue);
    jfloat result = left / right;

    ctx.regs[dst].intValue = vmFloatToIntBitsValue(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_FLOAT v%d = v%d / v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 REM_FLOAT
bool VmHandleRemFloat(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("REM_FLOAT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jfloat left = vmIntBitsToFloatValue(ctx.regs[src1].intValue);
    jfloat right = vmIntBitsToFloatValue(ctx.regs[src2].intValue);
    jfloat result = fmodf(left, right);

    ctx.regs[dst].intValue = vmFloatToIntBitsValue(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_FLOAT v%d = v%d %% v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}
//指令 ADD_DOUBLE
bool VmHandleAddDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("ADD_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jdouble value1 = longBitsToDouble(ctx.regs[src1].longValue);
    jdouble value2 = longBitsToDouble(ctx.regs[src2].longValue);
    jdouble result = value1 + value2;

    ctx.regs[dst].longValue = doubleToLongBits(result);
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_DOUBLE v%d <- v%d + v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 SUB_DOUBLE
bool VmHandleSubDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("SUB_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jdouble value1 = longBitsToDouble(ctx.regs[src1].longValue);
    jdouble value2 = longBitsToDouble(ctx.regs[src2].longValue);
    jdouble result = value1 - value2;

    ctx.regs[dst].longValue = doubleToLongBits(result);
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_DOUBLE v%d <- v%d - v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 MUL_DOUBLE
bool VmHandleMulDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("MUL_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jdouble value1 = longBitsToDouble(ctx.regs[src1].longValue);
    jdouble value2 = longBitsToDouble(ctx.regs[src2].longValue);
    jdouble result = value1 * value2;

    ctx.regs[dst].longValue = doubleToLongBits(result);
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_DOUBLE v%d <- v%d * v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 DIV_DOUBLE
bool VmHandleDivDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("DIV_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jdouble value1 = longBitsToDouble(ctx.regs[src1].longValue);
    jdouble value2 = longBitsToDouble(ctx.regs[src2].longValue);
    jdouble result = value1 / value2;

    ctx.regs[dst].longValue = doubleToLongBits(result);
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_DOUBLE v%d <- v%d / v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}

//指令 REM_DOUBLE
bool VmHandleRemDouble(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 3) {
        LOGE("REM_DOUBLE 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src1 = insn.registers[1];
    int src2 = insn.registers[2];

    jdouble value1 = longBitsToDouble(ctx.regs[src1].longValue);
    jdouble value2 = longBitsToDouble(ctx.regs[src2].longValue);
    jdouble result = fmod(value1, value2);

    ctx.regs[dst].longValue = doubleToLongBits(result);
    ctx.regs[dst].intValue = static_cast<jint>(ctx.regs[dst].longValue);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_DOUBLE v%d <- v%d %% v%d result=%f",dst,src1,src2,result);

    ctx.pc++;
    return true;
}
//指令 ADD_INT_2ADDR
bool VmHandleAddInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint result = static_cast<jint>(ctx.regs[dst].intValue + ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_INT_2ADDR v%d <- v%d + v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 SUB_INT_2ADDR
bool VmHandleSubInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SUB_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint result = static_cast<jint>(ctx.regs[dst].intValue - ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_INT_2ADDR v%d <- v%d - v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 MUL_INT_2ADDR
bool VmHandleMulInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint result = static_cast<jint>(ctx.regs[dst].intValue * ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_INT_2ADDR v%d <- v%d * v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 DIV_INT_2ADDR
bool VmHandleDivInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint right = ctx.regs[src].intValue;

    if (right == 0) {
        LOGE("DIV_INT_2ADDR 除数为0");
        return false;
    }

    jint result = static_cast<jint>(ctx.regs[dst].intValue / right);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_INT_2ADDR v%d <- v%d / v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 REM_INT_2ADDR
bool VmHandleRemInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint right = ctx.regs[src].intValue;

    if (right == 0) {
        LOGE("REM_INT_2ADDR 除数为0");
        return false;
    }

    jint result = static_cast<jint>(ctx.regs[dst].intValue % right);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_INT_2ADDR v%d <- v%d %% v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 AND_INT_2ADDR
bool VmHandleAndInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("AND_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint result = static_cast<jint>(ctx.regs[dst].intValue & ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("AND_INT_2ADDR v%d <- v%d & v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}

//指令 OR_INT_2ADDR
bool VmHandleOrInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("OR_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint result = static_cast<jint>(ctx.regs[dst].intValue | ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("OR_INT_2ADDR v%d <- v%d | v%d = %d",dst,dst,src,result);

    ctx.pc++;
    return true;
}
//指令 XOR_INT_2ADDR
bool VmHandleXorInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("XOR_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    ctx.regs[dst].intValue = ctx.regs[dst].intValue ^ ctx.regs[src].intValue;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("XOR_INT_2ADDR v%d ^= v%d -> %d",dst,src,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 SHL_INT_2ADDR
bool VmHandleShlInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHL_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint left = ctx.regs[dst].intValue;
    jint right = ctx.regs[src].intValue & 0x1f;
    jint result = left << right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHL_INT_2ADDR v%d=%d << %d => %d",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 SHR_INT_2ADDR
bool VmHandleShrInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHR_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint left = ctx.regs[dst].intValue;
    jint right = ctx.regs[src].intValue & 0x1f;
    jint result = left >> right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHR_INT_2ADDR v%d=%d >> %d => %d",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 USHR_INT_2ADDR
bool VmHandleUshrInt2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("USHR_INT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    uint32_t left = static_cast<uint32_t>(ctx.regs[dst].intValue);
    jint right = ctx.regs[src].intValue & 0x1f;
    jint result = static_cast<jint>(left >> right);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("USHR_INT_2ADDR v%d=%u >>> %d => %d",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 ADD_LONG_2ADDR
bool VmHandleAddLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;
    jlong result = left + right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_LONG_2ADDR v%d=%lld + %lld => %lld",dst,static_cast<long long>(left),static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 SUB_LONG_2ADDR
bool VmHandleSubLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SUB_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;
    jlong result = left - right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_LONG_2ADDR v%d=%lld - %lld => %lld",dst,static_cast<long long>(left),static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 MUL_LONG_2ADDR
bool VmHandleMulLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;
    jlong result = left * right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_LONG_2ADDR v%d=%lld * %lld => %lld",dst,static_cast<long long>(left),static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}

//指令 DIV_LONG_2ADDR
bool VmHandleDivLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;

    if (right == 0) {
        LOGE("DIV_LONG_2ADDR 除数为0");

        jclass cls = ctx.env->FindClass("java/lang/ArithmeticException");
        if (cls != nullptr) {
            ctx.env->ThrowNew(cls, "divide by zero");
        }

        return false;
    }

    jlong result = left / right;

    ctx.regs[dst].longValue = result;
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_LONG_2ADDR v%d=%lld / %lld => %lld",dst,static_cast<long long>(left),static_cast<long long>(right),static_cast<long long>(result));

    ctx.pc++;
    return true;
}
//指令 REM_LONG_2ADDR
bool VmHandleRemLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;

    if (right == 0) {
        LOGE("REM_LONG_2ADDR 除数为0 v%d", src);
        return false;
    }

    ctx.regs[dst].longValue = left % right;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("REM_LONG_2ADDR v%d=%lld %% v%d=%lld -> %lld",dst,static_cast<long long>(left),src,static_cast<long long>(right),static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 AND_LONG_2ADDR
bool VmHandleAndLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("AND_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;

    ctx.regs[dst].longValue = left & right;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("AND_LONG_2ADDR v%d=%lld & v%d=%lld -> %lld",dst,static_cast<long long>(left),src,static_cast<long long>(right),static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 OR_LONG_2ADDR
bool VmHandleOrLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("OR_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;

    ctx.regs[dst].longValue = left | right;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("OR_LONG_2ADDR v%d=%lld | v%d=%lld -> %lld",dst,static_cast<long long>(left),src,static_cast<long long>(right),static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 XOR_LONG_2ADDR
bool VmHandleXorLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("XOR_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    jlong right = ctx.regs[src].longValue;

    ctx.regs[dst].longValue = left ^ right;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("XOR_LONG_2ADDR v%d=%lld ^ v%d=%lld -> %lld",dst,static_cast<long long>(left),src,static_cast<long long>(right),static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 SHL_LONG_2ADDR
bool VmHandleShlLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHL_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    int shift = ctx.regs[src].intValue & 0x3f;

    ctx.regs[dst].longValue = left << shift;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("SHL_LONG_2ADDR v%d=%lld << %d -> %lld",dst,static_cast<long long>(left),shift,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 SHR_LONG_2ADDR
bool VmHandleShrLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHR_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jlong left = ctx.regs[dst].longValue;
    int shift = ctx.regs[src].intValue & 0x3f;

    ctx.regs[dst].longValue = left >> shift;
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("SHR_LONG_2ADDR v%d=%lld >> %d -> %lld",dst,static_cast<long long>(left),shift,static_cast<long long>(ctx.regs[dst].longValue));

    ctx.pc++;
    return true;
}

//指令 USHR_LONG_2ADDR
bool VmHandleUshrLong2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("USHR_LONG_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    uint64_t left = static_cast<uint64_t>(ctx.regs[dst].longValue);
    int shift = ctx.regs[src].intValue & 0x3f;

    uint64_t result = left >> shift;

    ctx.regs[dst].longValue = static_cast<jlong>(result);
    ctx.regs[dst].intValue = static_cast<int>(ctx.regs[dst].longValue);

    //LOGI("USHR_LONG_2ADDR v%d=%llu >>> %d -> %llu",dst,static_cast<unsigned long long>(left),shift,static_cast<unsigned long long>(result));

    ctx.pc++;
    return true;
}
//指令 ADD_FLOAT_2ADDR
bool VmHandleAddFloat2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_FLOAT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat left = intBitsToFloat(ctx.regs[dst].intValue);
    jfloat right = intBitsToFloat(ctx.regs[src].intValue);
    jfloat result = left + right;

    ctx.regs[dst].intValue = floatToIntBits(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_FLOAT_2ADDR v%d = %f + %f -> %f",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 SUB_FLOAT_2ADDR
bool VmHandleSubFloat2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SUB_FLOAT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat left = intBitsToFloat(ctx.regs[dst].intValue);
    jfloat right = intBitsToFloat(ctx.regs[src].intValue);
    jfloat result = left - right;

    ctx.regs[dst].intValue = floatToIntBits(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_FLOAT_2ADDR v%d = %f - %f -> %f",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 MUL_FLOAT_2ADDR
bool VmHandleMulFloat2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_FLOAT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat left = intBitsToFloat(ctx.regs[dst].intValue);
    jfloat right = intBitsToFloat(ctx.regs[src].intValue);
    jfloat result = left * right;

    ctx.regs[dst].intValue = floatToIntBits(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_FLOAT_2ADDR v%d = %f * %f -> %f",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 DIV_FLOAT_2ADDR
bool VmHandleDivFloat2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_FLOAT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat left = intBitsToFloat(ctx.regs[dst].intValue);
    jfloat right = intBitsToFloat(ctx.regs[src].intValue);
    jfloat result = left / right;

    ctx.regs[dst].intValue = floatToIntBits(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_FLOAT_2ADDR v%d = %f / %f -> %f",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 REM_FLOAT_2ADDR
bool VmHandleRemFloat2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_FLOAT_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jfloat left = intBitsToFloat(ctx.regs[dst].intValue);
    jfloat right = intBitsToFloat(ctx.regs[src].intValue);
    jfloat result = fmodf(left, right);

    ctx.regs[dst].intValue = floatToIntBits(result);
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_FLOAT_2ADDR v%d = %f %% %f -> %f",dst,left,right,result);

    ctx.pc++;
    return true;
}
//指令 ADD_DOUBLE_2ADDR
bool VmHandleAddDouble2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_DOUBLE_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble left;
    jdouble right;
    jdouble result;

    memcpy(&left, &ctx.regs[dst].longValue, sizeof(jdouble));
    memcpy(&right, &ctx.regs[src].longValue, sizeof(jdouble));

    result = left + right;

    memcpy(&ctx.regs[dst].longValue, &result, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_DOUBLE_2ADDR v%d = %lf + %lf -> %lf",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 SUB_DOUBLE_2ADDR
bool VmHandleSubDouble2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SUB_DOUBLE_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble left;
    jdouble right;
    jdouble result;

    memcpy(&left, &ctx.regs[dst].longValue, sizeof(jdouble));
    memcpy(&right, &ctx.regs[src].longValue, sizeof(jdouble));

    result = left - right;

    memcpy(&ctx.regs[dst].longValue, &result, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SUB_DOUBLE_2ADDR v%d = %lf - %lf -> %lf",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 MUL_DOUBLE_2ADDR
bool VmHandleMulDouble2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_DOUBLE_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble left;
    jdouble right;
    jdouble result;

    memcpy(&left, &ctx.regs[dst].longValue, sizeof(jdouble));
    memcpy(&right, &ctx.regs[src].longValue, sizeof(jdouble));

    result = left * right;

    memcpy(&ctx.regs[dst].longValue, &result, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_DOUBLE_2ADDR v%d = %lf * %lf -> %lf",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 DIV_DOUBLE_2ADDR
bool VmHandleDivDouble2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_DOUBLE_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble left;
    jdouble right;
    jdouble result;

    memcpy(&left, &ctx.regs[dst].longValue, sizeof(jdouble));
    memcpy(&right, &ctx.regs[src].longValue, sizeof(jdouble));

    result = left / right;

    memcpy(&ctx.regs[dst].longValue, &result, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_DOUBLE_2ADDR v%d = %lf / %lf -> %lf",dst,left,right,result);

    ctx.pc++;
    return true;
}

//指令 REM_DOUBLE_2ADDR
bool VmHandleRemDouble2Addr(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_DOUBLE_2ADDR 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jdouble left;
    jdouble right;
    jdouble result;

    memcpy(&left, &ctx.regs[dst].longValue, sizeof(jdouble));
    memcpy(&right, &ctx.regs[src].longValue, sizeof(jdouble));

    result = fmod(left, right);

    memcpy(&ctx.regs[dst].longValue, &result, sizeof(jdouble));
    ctx.regs[dst].intValue = static_cast<jint>(result);
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_DOUBLE_2ADDR v%d = %lf %% %lf -> %lf",dst,left,right,result);

    ctx.pc++;
    return true;
}
//指令 ADD_INT_LIT16
bool VmHandleAddIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    int result = ctx.regs[src].intValue + literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_INT_LIT16 v%d = v%d(%d) + %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}

//指令 RSUB_INT
bool VmHandleRsubInt(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("RSUB_INT 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    int result = literal - ctx.regs[src].intValue;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("RSUB_INT v%d = %d - v%d(%d) -> %d",dst, literal, src, ctx.regs[src].intValue, result);

    ctx.pc++;
    return true;
}

//指令 MUL_INT_LIT16
bool VmHandleMulIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    int result = ctx.regs[src].intValue * literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_INT_LIT16 v%d = v%d(%d) * %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}

//指令 DIV_INT_LIT16
bool VmHandleDivIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    if (literal == 0) {
        LOGE("DIV_INT_LIT16 除数为0");
        return false;
    }

    int result = ctx.regs[src].intValue / literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_INT_LIT16 v%d = v%d(%d) / %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}

//指令 REM_INT_LIT16
bool VmHandleRemIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    if (literal == 0) {
        LOGE("REM_INT_LIT16 除数为0");
        return false;
    }

    int result = ctx.regs[src].intValue % literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_INT_LIT16 v%d = v%d(%d) %% %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}

//指令 AND_INT_LIT16
bool VmHandleAndIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("AND_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    int result = ctx.regs[src].intValue & literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("AND_INT_LIT16 v%d = v%d(%d) & %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}

//指令 OR_INT_LIT16
bool VmHandleOrIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("OR_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    int result = ctx.regs[src].intValue | literal;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("OR_INT_LIT16 v%d = v%d(%d) | %d -> %d",dst, src, ctx.regs[src].intValue, literal, result);

    ctx.pc++;
    return true;
}
//指令 XOR_INT_LIT16
bool VmHandleXorIntLit16(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("XOR_INT_LIT16 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int16_t>(insn.literalValue);

    ctx.regs[dst].intValue = ctx.regs[src].intValue ^ literal;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("XOR_INT_LIT16 v%d = v%d ^ %d -> %d",dst,src,literal,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 ADD_INT_LIT8
bool VmHandleAddIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("ADD_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int8_t>(insn.literalValue);

    jint result = static_cast<jint>(ctx.regs[src].intValue + literal);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("ADD_INT_LIT8 v%d <- v%d(%d) + #%d = %d",dst,src,ctx.regs[src].intValue,literal,result);

    ctx.pc++;
    return true;
}

//指令 RSUB_INT_LIT8
bool VmHandleRsubIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("RSUB_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int8_t>(insn.literalValue);

    jint result = static_cast<jint>(literal - ctx.regs[src].intValue);

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("RSUB_INT_LIT8 v%d <- #%d - v%d(%d) = %d",dst,literal,src,ctx.regs[src].intValue,result);

    ctx.pc++;
    return true;
}
//指令 MUL_INT_LIT8
bool VmHandleMulIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("MUL_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int8_t>(insn.literalValue);

    ctx.regs[dst].intValue = ctx.regs[src].intValue * literal;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("MUL_INT_LIT8 v%d <- v%d(%d) * #%d = %d",dst,src,ctx.regs[src].intValue,literal,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 DIV_INT_LIT8
bool VmHandleDivIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("DIV_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int left = ctx.regs[src].intValue;
    int right = static_cast<int8_t>(insn.literalValue);

    if (right == 0) {
        LOGE("DIV_INT_LIT8 除数为0");
        return false;
    }

    int result = left / right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("DIV_INT_LIT8 v%d = v%d(%d) / #%d -> %d",dst,src,left,right,result);

    ctx.pc++;
    return true;
}

//指令 REM_INT_LIT8
bool VmHandleRemIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("REM_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int left = ctx.regs[src].intValue;
    int right = static_cast<int8_t>(insn.literalValue);

    if (right == 0) {
        LOGE("REM_INT_LIT8 除数为0");
        return false;
    }

    int result = left % right;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("REM_INT_LIT8 v%d = v%d(%d) %% #%d -> %d",dst,src,left,right,result);

    ctx.pc++;
    return true;
}
//指令 AND_INT_LIT8
bool VmHandleAndIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("AND_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];
    int literal = static_cast<int8_t>(insn.literalValue);

    int value = ctx.regs[src].intValue & literal;

    ctx.regs[dst].intValue = value;
    ctx.regs[dst].longValue = value;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("AND_INT_LIT8 v%d <- v%d & %d = %d",dst,src,literal,value);

    ctx.pc++;
    return true;
}
//指令 OR_INT_LIT8
bool VmHandleOrIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("OR_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint srcValue = ctx.regs[src].intValue;
    jint litValue = static_cast<jint>(static_cast<int8_t>(insn.literalValue));
    jint result = srcValue | litValue;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("OR_INT_LIT8 v%d <- v%d(%d) | #%d = %d",dst,src,srcValue,litValue,result);

    ctx.pc++;
    return true;
}
//指令 XOR_INT_LIT8
bool VmHandleXorIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("XOR_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    int value = ctx.regs[src].intValue;
    int literal = static_cast<int8_t>(insn.literalValue);

    ctx.regs[dst].intValue = value ^ literal;
    ctx.regs[dst].longValue = ctx.regs[dst].intValue;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("XOR_INT_LIT8 v%d <- v%d ^ %d result=%d",dst,src,literal,ctx.regs[dst].intValue);

    ctx.pc++;
    return true;
}
//指令 SHL_INT_LIT8
bool VmHandleShlIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHL_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint srcValue = ctx.regs[src].intValue;
    jint shift = static_cast<jint>(insn.literalValue) & 0x1f;
    jint result = srcValue << shift;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHL_INT_LIT8 v%d <- v%d(%d) << %d = %d",dst,src,srcValue,shift,result);

    ctx.pc++;
    return true;
}

//指令 SHR_INT_LIT8
bool VmHandleShrIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("SHR_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint srcValue = ctx.regs[src].intValue;
    jint shift = static_cast<jint>(insn.literalValue) & 0x1f;
    jint result = srcValue >> shift;

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("SHR_INT_LIT8 v%d <- v%d(%d) >> %d = %d",dst,src,srcValue,shift,result);

    ctx.pc++;
    return true;
}

//指令 USHR_INT_LIT8
bool VmHandleUshrIntLit8(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.registers.size() < 2) {
        LOGE("USHR_INT_LIT8 寄存器数量不足");
        return false;
    }

    int dst = insn.registers[0];
    int src = insn.registers[1];

    jint srcValue = ctx.regs[src].intValue;
    jint shift = static_cast<jint>(insn.literalValue) & 0x1f;
    jint result = static_cast<jint>(
            static_cast<uint32_t>(srcValue) >> shift
    );

    ctx.regs[dst].intValue = result;
    ctx.regs[dst].longValue = result;
    ctx.regs[dst].objectValue = nullptr;

    //LOGI("USHR_INT_LIT8 v%d <- v%d(%d) >>> %d = %d",dst,src,srcValue,shift,result);

    ctx.pc++;
    return true;
}
//指令 UNUSED_E3
bool VmHandleUnusedE3(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E3 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E4
bool VmHandleUnusedE4(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E4 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E5
bool VmHandleUnusedE5(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E5 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E6
bool VmHandleUnusedE6(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E6 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E7
bool VmHandleUnusedE7(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E7 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E8
bool VmHandleUnusedE8(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E8 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_E9
bool VmHandleUnusedE9(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_E9 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_EA
bool VmHandleUnusedEA(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_EA offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_EB
bool VmHandleUnusedEB(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_EB offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_EC
bool VmHandleUnusedEC(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_EC offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_ED
bool VmHandleUnusedED(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_ED offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_EE
bool VmHandleUnusedEE(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_EE offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_EF
bool VmHandleUnusedEF(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_EF offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F0
bool VmHandleUnusedF0(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F0 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F1
bool VmHandleUnusedF1(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F1 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F2
bool VmHandleUnusedF2(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F2 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F3
bool VmHandleUnusedF3(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F3 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F4
bool VmHandleUnusedF4(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F4 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F5
bool VmHandleUnusedF5(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F5 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F6
bool VmHandleUnusedF6(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F6 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F7
bool VmHandleUnusedF7(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F7 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F8
bool VmHandleUnusedF8(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F8 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}

//指令 UNUSED_F9
bool VmHandleUnusedF9(VmContext &ctx, const VmpInstruction &insn) {
    LOGE("执行到未使用指令 UNUSED_F9 offset=%d", insn.codeUnitOffset);
    ctx.running = false;
    return false;
}
//指令 INVOKE_POLYMORPHIC
bool VmHandleInvokePolymorphic(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string oldSignature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, oldSignature)) {
        LOGE("INVOKE_POLYMORPHIC 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.extraReferenceData.empty()) {
        LOGE("INVOKE_POLYMORPHIC 缺少proto引用：%s", insn.referenceData.c_str());
        return false;
    }

    std::string realSignature = insn.extraReferenceData;

    if (insn.registers.empty()) {
        LOGE("INVOKE_POLYMORPHIC 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_POLYMORPHIC 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("INVOKE_POLYMORPHIC 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), realSignature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), realSignature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_POLYMORPHIC 找不到方法：%s proto=%s",
                 insn.referenceData.c_str(),
                 realSignature.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseMethodParameterTypes(realSignature);
    std::string returnType = parseMethodReturnType(realSignature);

    if (static_cast<int>(paramTypes.size()) != static_cast<int>(insn.registers.size()) - 1) {
        LOGE("INVOKE_POLYMORPHIC 参数数量不匹配 protoCount=%d regCount=%d",
             static_cast<int>(paramTypes.size()),
             static_cast<int>(insn.registers.size()) - 1);
        return false;
    }

    std::vector<jvalue> args;
    args.resize(paramTypes.size());

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        int reg = insn.registers[i + 1];
        const std::string &type = paramTypes[i];

        memset(&args[i], 0, sizeof(jvalue));

        if (type == "Z") {
            args[i].z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
        } else if (type == "B") {
            args[i].b = static_cast<jbyte>(ctx.regs[reg].intValue);
        } else if (type == "S") {
            args[i].s = static_cast<jshort>(ctx.regs[reg].intValue);
        } else if (type == "C") {
            args[i].c = static_cast<jchar>(ctx.regs[reg].intValue);
        } else if (type == "I") {
            args[i].i = static_cast<jint>(ctx.regs[reg].intValue);
        } else if (type == "J") {
            args[i].j = static_cast<jlong>(ctx.regs[reg].longValue);
        } else if (type == "F") {
            args[i].f = intBitsToFloat(static_cast<jint>(ctx.regs[reg].intValue));
        } else if (type == "D") {
            args[i].d = longBitsToDouble(static_cast<jlong>(ctx.regs[reg].longValue));
        } else {
            args[i].l = ctx.regs[reg].objectValue;
        }
    }

    jvalue *argArray = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argArray);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argArray);
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argArray);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_POLYMORPHIC 调用失败：%s proto=%s",
             insn.referenceData.c_str(),
             realSignature.c_str());
        return false;
    }

    //LOGI("INVOKE_POLYMORPHIC 调用成功 ref=%s proto=%s",insn.referenceData.c_str(),realSignature.c_str());

    ctx.pc++;
    return true;
}
//指令 INVOKE_POLYMORPHIC_RANGE
bool VmHandleInvokePolymorphicRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string oldSignature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, oldSignature)) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.extraReferenceData.empty()) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 缺少proto引用：%s", insn.referenceData.c_str());
        return false;
    }

    std::string realSignature = insn.extraReferenceData;

    if (insn.registers.empty()) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 对象为空 v%d", objReg);
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(cls, methodName.c_str(), realSignature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(objCls, methodName.c_str(), realSignature.c_str());
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_POLYMORPHIC_RANGE 找不到方法：%s proto=%s",
                 insn.referenceData.c_str(),
                 realSignature.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes = parseMethodParameterTypes(realSignature);
    std::string returnType = parseMethodReturnType(realSignature);

    if (static_cast<int>(paramTypes.size()) != static_cast<int>(insn.registers.size()) - 1) {
        LOGE("INVOKE_POLYMORPHIC_RANGE 参数数量不匹配 protoCount=%d regCount=%d",
             static_cast<int>(paramTypes.size()),
             static_cast<int>(insn.registers.size()) - 1);
        return false;
    }

    std::vector<jvalue> args;
    args.resize(paramTypes.size());

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        int reg = insn.registers[i + 1];
        const std::string &type = paramTypes[i];

        memset(&args[i], 0, sizeof(jvalue));

        if (type == "Z") {
            args[i].z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
        } else if (type == "B") {
            args[i].b = static_cast<jbyte>(ctx.regs[reg].intValue);
        } else if (type == "S") {
            args[i].s = static_cast<jshort>(ctx.regs[reg].intValue);
        } else if (type == "C") {
            args[i].c = static_cast<jchar>(ctx.regs[reg].intValue);
        } else if (type == "I") {
            args[i].i = static_cast<jint>(ctx.regs[reg].intValue);
        } else if (type == "J") {
            args[i].j = static_cast<jlong>(ctx.regs[reg].longValue);
        } else if (type == "F") {
            args[i].f = intBitsToFloat(static_cast<jint>(ctx.regs[reg].intValue));
        } else if (type == "D") {
            args[i].d = longBitsToDouble(static_cast<jlong>(ctx.regs[reg].longValue));
        } else {
            args[i].l = ctx.regs[reg].objectValue;
        }
    }

    jvalue *argArray = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argArray);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argArray);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argArray);
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argArray);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argArray);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_POLYMORPHIC_RANGE 调用失败：%s proto=%s",
             insn.referenceData.c_str(),
             realSignature.c_str());
        return false;
    }

    //LOGI("INVOKE_POLYMORPHIC_RANGE 调用成功 ref=%s proto=%s",insn.referenceData.c_str(),realSignature.c_str());

    ctx.pc++;
    return true;
}
//指令 INVOKE_CUSTOM
bool VmHandleInvokeCustom(VmContext &ctx, const VmpInstruction &insn) {
    if (insn.referenceData.empty()) {
        LOGE("INVOKE_CUSTOM 缺少CallSite引用");
        return false;
    }

    int argCount = static_cast<int>(insn.registers.size());

    jclass objectClass = ctx.env->FindClass("java/lang/Object");
    if (ctx.env->ExceptionCheck() || objectClass == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 找不到Object类");
        return false;
    }

    jobjectArray argArray = ctx.env->NewObjectArray(argCount, objectClass, nullptr);
    if (ctx.env->ExceptionCheck() || argArray == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 创建参数数组失败");
        return false;
    }

    for (int i = 0; i < argCount; i++) {
        int reg = insn.registers[i];
        jobject value = ctx.regs[reg].objectValue;

        ctx.env->SetObjectArrayElement(argArray, i, value);

        if (ctx.env->ExceptionCheck()) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_CUSTOM 设置参数失败 index=%d reg=v%d", i, reg);
            return false;
        }
    }

    jclass helperClass = ctx.env->FindClass("com/ark/jiagu/vm/VmpInvokeCustomHelper");
    if (ctx.env->ExceptionCheck() || helperClass == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 找不到辅助类 VmpInvokeCustomHelper");
        return false;
    }

    jmethodID mid = ctx.env->GetStaticMethodID(
            helperClass,
            "invokeCustom",
            "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"
    );

    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 找不到辅助方法 invokeCustom");
        return false;
    }

    jstring callSiteText = ctx.env->NewStringUTF(insn.referenceData.c_str());
    if (ctx.env->ExceptionCheck() || callSiteText == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 创建CallSite字符串失败");
        return false;
    }

    jobject result = ctx.env->CallStaticObjectMethod(
            helperClass,
            mid,
            callSiteText,
            argArray
    );

    if (ctx.env->ExceptionCheck()) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_CUSTOM 调用失败 callSite=%s", insn.referenceData.c_str());
        return false;
    }

    ctx.lastResultObject = result;

    //LOGI("INVOKE_CUSTOM 调用完成 result=%p callSite=%s",result,insn.referenceData.c_str());

    ctx.pc++;
    return true;
}



//==================================================================================
//==================================================================================

//==================================================================================指令区



//指令 INVOKE_DIRECT_RANGE
bool VmHandleInvokeDirectRange(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_DIRECT_RANGE 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    if (insn.registers.empty()) {
        LOGE("INVOKE_DIRECT_RANGE 寄存器为空");
        return false;
    }

    int objReg = insn.registers[0];
    jobject obj = ctx.regs[objReg].objectValue;

    if (obj == nullptr) {
        LOGE("INVOKE_DIRECT_RANGE 对象为空 v%d ref=%s", objReg, insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForObject(ctx.env, obj, classType);

    if (cls == nullptr) {
        LOGE("INVOKE_DIRECT_RANGE 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetMethodID(
            cls,
            methodName.c_str(),
            signature.c_str()
    );

    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();

        jclass objCls = ctx.env->GetObjectClass(obj);
        if (!ctx.env->ExceptionCheck() && objCls != nullptr && objCls != cls) {
            mid = ctx.env->GetMethodID(
                    objCls,
                    methodName.c_str(),
                    signature.c_str()
            );
        }

        if (ctx.env->ExceptionCheck() || mid == nullptr) {
            ctx.env->ExceptionClear();
            LOGE("INVOKE_DIRECT_RANGE 找不到方法：%s", insn.referenceData.c_str());
            return false;
        }
    }

    std::vector<std::string> paramTypes;
    if (!parseMethodParameterTypes(signature, paramTypes)) {
        LOGE("INVOKE_DIRECT_RANGE 参数签名解析失败：%s", signature.c_str());
        return false;
    }

    std::vector<jvalue> args;
    args.resize(paramTypes.size());

    int regIndex = 1;

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        if (regIndex >= static_cast<int>(insn.registers.size())) {
            LOGE("INVOKE_DIRECT_RANGE 参数寄存器不足 index=%d", i);
            return false;
        }

        int reg = insn.registers[regIndex];
        const std::string &type = paramTypes[i];

        memset(&args[i], 0, sizeof(jvalue));

        if (type == "Z") {
            args[i].z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
            regIndex += 1;
        } else if (type == "B") {
            args[i].b = static_cast<jbyte>(ctx.regs[reg].intValue);
            regIndex += 1;
        } else if (type == "S") {
            args[i].s = static_cast<jshort>(ctx.regs[reg].intValue);
            regIndex += 1;
        } else if (type == "C") {
            args[i].c = static_cast<jchar>(ctx.regs[reg].intValue);
            regIndex += 1;
        } else if (type == "I") {
            args[i].i = static_cast<jint>(ctx.regs[reg].intValue);
            regIndex += 1;
        } else if (type == "J") {
            args[i].j = static_cast<jlong>(ctx.regs[reg].longValue);
            regIndex += 2;
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[reg].intValue);
            memcpy(&args[i].f, &bits, sizeof(jfloat));
            regIndex += 1;
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[reg].longValue);
            memcpy(&args[i].d, &bits, sizeof(jdouble));
            regIndex += 2;
        } else {
            args[i].l = ctx.regs[reg].objectValue;
            regIndex += 1;
        }
    }

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    std::string returnType = getMethodReturnType(signature);
    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallVoidMethodA(obj, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallBooleanMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallByteMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallShortMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallCharMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallIntMethodA(obj, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallLongMethodA(obj, mid, argPtr);
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallFloatMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallDoubleMethodA(obj, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<int>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallObjectMethodA(obj, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        ctx.currentException = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();
        LOGE("INVOKE_DIRECT_RANGE 调用失败：%s", insn.referenceData.c_str());
        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }
        return false;
    }

    //LOGI("INVOKE_DIRECT_RANGE 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}


//指令 INVOKE_STATIC
bool VmHandleInvokeStatic(VmContext &ctx, const VmpInstruction &insn) {
    std::string classType;
    std::string methodName;
    std::string signature;

    if (!parseMethodReference(insn.referenceData, classType, methodName, signature)) {
        LOGE("INVOKE_STATIC 方法引用解析失败：%s", insn.referenceData.c_str());
        return false;
    }

    jclass cls = findVmClassForStatic(ctx.env, classType);

    if (cls == nullptr) {
        LOGE("INVOKE_STATIC 找不到类：%s", classType.c_str());
        return false;
    }

    jmethodID mid = ctx.env->GetStaticMethodID(cls, methodName.c_str(), signature.c_str());
    if (ctx.env->ExceptionCheck() || mid == nullptr) {
        ctx.env->ExceptionClear();
        LOGE("INVOKE_STATIC 找不到方法：%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<std::string> paramTypes = parseMethodParamTypes(signature);
    std::string returnType = parseMethodReturnType(signature);

    if (insn.registers.size() < paramTypes.size()) {
        LOGE("INVOKE_STATIC 参数寄存器数量不足 ref=%s", insn.referenceData.c_str());
        return false;
    }

    std::vector<jvalue> args;
    args.resize(paramTypes.size());

    for (int i = 0; i < static_cast<int>(paramTypes.size()); i++) {
        int reg = insn.registers[i];
        const std::string &type = paramTypes[i];

        memset(&args[i], 0, sizeof(jvalue));

        if (type == "Z") {
            args[i].z = ctx.regs[reg].intValue ? JNI_TRUE : JNI_FALSE;
        } else if (type == "B") {
            args[i].b = static_cast<jbyte>(ctx.regs[reg].intValue);
        } else if (type == "S") {
            args[i].s = static_cast<jshort>(ctx.regs[reg].intValue);
        } else if (type == "C") {
            args[i].c = static_cast<jchar>(ctx.regs[reg].intValue);
        } else if (type == "I") {
            args[i].i = static_cast<jint>(ctx.regs[reg].intValue);
        } else if (type == "J") {
            args[i].j = static_cast<jlong>(ctx.regs[reg].longValue);
        } else if (type == "F") {
            jint bits = static_cast<jint>(ctx.regs[reg].intValue);
            memcpy(&args[i].f, &bits, sizeof(jfloat));
        } else if (type == "D") {
            jlong bits = static_cast<jlong>(ctx.regs[reg].longValue);
            memcpy(&args[i].d, &bits, sizeof(jdouble));
        } else {
            args[i].l = ctx.regs[reg].objectValue;
        }
    }

    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;

    jvalue *argPtr = args.empty() ? nullptr : args.data();

    if (returnType == "V") {
        ctx.env->CallStaticVoidMethodA(cls, mid, argPtr);
    } else if (returnType == "Z") {
        ctx.lastResultInt = ctx.env->CallStaticBooleanMethodA(cls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "B") {
        ctx.lastResultInt = ctx.env->CallStaticByteMethodA(cls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "S") {
        ctx.lastResultInt = ctx.env->CallStaticShortMethodA(cls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "C") {
        ctx.lastResultInt = ctx.env->CallStaticCharMethodA(cls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "I") {
        ctx.lastResultInt = ctx.env->CallStaticIntMethodA(cls, mid, argPtr);
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "J") {
        ctx.lastResultLong = ctx.env->CallStaticLongMethodA(cls, mid, argPtr);
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else if (returnType == "F") {
        jfloat value = ctx.env->CallStaticFloatMethodA(cls, mid, argPtr);
        memcpy(&ctx.lastResultInt, &value, sizeof(jfloat));
        ctx.lastResultLong = ctx.lastResultInt;
    } else if (returnType == "D") {
        jdouble value = ctx.env->CallStaticDoubleMethodA(cls, mid, argPtr);
        memcpy(&ctx.lastResultLong, &value, sizeof(jdouble));
        ctx.lastResultInt = static_cast<jint>(ctx.lastResultLong);
    } else {
        ctx.lastResultObject = ctx.env->CallStaticObjectMethodA(cls, mid, argPtr);
    }

    if (ctx.env->ExceptionCheck()) {
        jthrowable ex = ctx.env->ExceptionOccurred();
        ctx.env->ExceptionClear();

        ctx.currentException = ex;

        LOGE("INVOKE_STATIC 调用失败：%s", insn.referenceData.c_str());

        jclass throwableCls = ctx.env->FindClass("java/lang/Throwable");
        jmethodID toStringMid = ctx.env->GetMethodID(
                throwableCls,
                "toString",
                "()Ljava/lang/String;"
        );

        if (toStringMid != nullptr && ex != nullptr) {
            jstring msg = (jstring) ctx.env->CallObjectMethod(ex, toStringMid);
            if (msg != nullptr) {
                const char *cmsg = ctx.env->GetStringUTFChars(msg, nullptr);
                LOGE("INVOKE_STATIC Java异常：%s", cmsg);
                ctx.env->ReleaseStringUTFChars(msg, cmsg);
                ctx.env->DeleteLocalRef(msg);
            }
        }

        if (VmContext_JumpToExceptionHandler(ctx, insn.codeUnitOffset)) {
            return true;
        }

        return false;
    }

    //LOGI("INVOKE_STATIC 调用完成：%s", insn.referenceData.c_str());

    ctx.pc++;
    return true;
}










//==================================================================================
//==================================================================================
bool VmHandlers_Init() {
    memset(g_handlerTable, 0, sizeof(g_handlerTable));

    return true;
}

VmHandler VmHandlers_Get(int vmOpcode) {
    if (vmOpcode < 0 || vmOpcode > 255) {
        return nullptr;
    }

    return g_handlerTable[vmOpcode];
}

