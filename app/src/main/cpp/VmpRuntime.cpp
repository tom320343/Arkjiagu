#include "VmpRuntime.h"
#include "VmpParser.h"
#include "VmpInterpreter.h"
#include <android/log.h>

#define LOG_TAG "GuardVMP_VmpRuntime"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static jobject g_context = nullptr;

void VmpRuntime_SetContext(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return;
    }

    if (g_context != nullptr) {
        env->DeleteGlobalRef(g_context);
        g_context = nullptr;
    }

    g_context = env->NewGlobalRef(context);

    //LOGI("VMP Runtime 已保存 Context");

    // 提前读取并解析 vmp.bin 的头部、opcodeMap、methodIndex
    if (!VmpParser_EnsureLoaded(env, g_context)) {
        //LOGE("提前加载 vmp.bin 失败");
        return;
    }

    //LOGI("vmp.bin 已提前加载并解析索引");
}

jobject VmpRuntime_GetContext() {
    return g_context;
}

static std::string jstringToStdString(JNIEnv *env, jstring str) {
    if (env == nullptr || str == nullptr) {
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

VmResult VmpRuntime_Execute(
        JNIEnv *env,
        jint methodId,
        jobject thiz,
        jobjectArray args
) {
    VmResult result;

    if (env == nullptr) {
        //LOGE("env为空");
        return result;
    }

    if (g_context == nullptr) {
        //LOGE("Context为空，无法读取 assets/vmp.bin");
        return result;
    }

    if (!VmpParser_EnsureLoaded(env, g_context)) {
        //LOGE("vmp.bin加载失败");
        return result;
    }

    VmpMethod method;
    if (!VmpParser_FindMethod(env, methodId, method)) {
        //LOGE("未找到 methodId=%d", methodId);
        return result;
    }

    jsize argCount = 0;
    if (args != nullptr) {
        argCount = env->GetArrayLength(args);
    }

    //LOGI("========== VMP执行入口 ==========");
    //LOGI("methodId=%d", method.methodId);
    //LOGI("dexName=%s", method.dexName.c_str());
    //LOGI("className=%s", method.className.c_str());
    //LOGI("methodName=%s", method.methodName.c_str());
    //LOGI("methodSignature=%s", method.methodSignature.c_str());
    //LOGI("accessFlags=0x%x", method.accessFlags);
    //LOGI("registerCount=%d", method.registerCount);
    //LOGI("paramCount=%d", method.paramCount);
    //LOGI("returnType=%s", method.returnType.c_str());
    //LOGI("isStatic=%d", method.isStatic ? 1 : 0);
    //LOGI("thiz=%p", thiz);
    //LOGI("args=%p", args);
    //LOGI("argsCount=%d", argCount);

    //LOGI("========== 参数类型 ==========");
    //LOGI("parameterTypeCount=%d", static_cast<int>(method.parameterTypes.size()));

    for (int i = 0; i < static_cast<int>(method.parameterTypes.size()); i++) {
        //LOGI("parameterTypes[%d]=%s", i, method.parameterTypes[i].c_str());
    }

    //LOGI("========== 指令列表 ==========");
    //LOGI("instructionCount=%d", static_cast<int>(method.instructions.size()));

    for (int i = 0; i < static_cast<int>(method.instructions.size()); i++) {
        const VmpInstruction &insn = method.instructions[i];

        //LOGI("----------------------------------------");
        //LOGI("instruction[%d]", i);
        //LOGI("codeUnitOffset=%d", insn.codeUnitOffset);
        //LOGI("vmOpcode=0x%02x", insn.vmOpcode);
        //LOGI("realOpcode=0x%x", insn.realOpcode);
        //LOGI("opcodeName=%s", insn.opcodeName.c_str());
        //LOGI("formatName=%s", insn.formatName.c_str());
        //LOGI("codeUnits=%d", insn.codeUnits);

        //LOGI("registerCount=%d", static_cast<int>(insn.registers.size()));
        for (int r = 0; r < static_cast<int>(insn.registers.size()); r++) {
            //LOGI("registers[%d]=v%d", r, insn.registers[r]);
        }

        //LOGI("literalType=%d", insn.literalType);
        //LOGI("literalValue=%lld", static_cast<long long>(insn.literalValue));
        //LOGI("offsetType=%d", insn.offsetType);
        //LOGI("offsetValue=%d", insn.offsetValue);
        //LOGI("referenceType=%d", insn.referenceType);
        //LOGI("referenceData=%s", insn.referenceData.c_str());
    }

    //LOGI("========== TryCatch列表 ==========");
    //LOGI("tryBlockCount=%d", static_cast<int>(method.tryBlocks.size()));

    for (int i = 0; i < static_cast<int>(method.tryBlocks.size()); i++) {
        const VmpTryBlock &tryBlock = method.tryBlocks[i];

        //LOGI("----------------------------------------");
        //LOGI("tryBlock[%d]", i);
        //LOGI("startCodeAddress=%d", tryBlock.startCodeAddress);
        //LOGI("codeUnitCount=%d", tryBlock.codeUnitCount);
        //LOGI("handlerCount=%d", static_cast<int>(tryBlock.handlers.size()));

        for (int h = 0; h < static_cast<int>(tryBlock.handlers.size()); h++) {
            const VmpExceptionHandler &handler = tryBlock.handlers[h];

            //LOGI("handler[%d]", h);
            //LOGI("exceptionType=%s", handler.exceptionType.c_str());
            //LOGI("handlerCodeAddress=%d", handler.handlerCodeAddress);
        }
    }

    //LOGI("========== VMP执行入口结束 ==========");

    // TODO：后续这里接解释器
    result = VmpInterpreter_Execute(env, method, thiz, args);

    return result;
}

