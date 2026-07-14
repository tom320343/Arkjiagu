#include "VmContext.h"

#include <android/log.h>

#define LOG_TAG "GuardVMP_Context"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

bool VmContext_Init(
        VmContext &ctx,
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
) {
    ctx.env = env;
    ctx.method = &method;
    ctx.thiz = thiz;
    ctx.args = args;

    ctx.pc = 0;
    ctx.running = true;
    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;
    ctx.currentException = nullptr;






    ctx.result = VmResult();

    ctx.regs.clear();
    ctx.regs.resize(method.registerCount);

    ctx.offsetToIndex.clear();
    for (int i = 0; i < static_cast<int>(method.instructions.size()); i++) {
        ctx.offsetToIndex[method.instructions[i].codeUnitOffset] = i;
    }

    int paramRegisterCount = method.isStatic ? 0 : 1;

    for (int i = 0; i < static_cast<int>(method.parameterTypes.size()); i++) {
        const std::string &type = method.parameterTypes[i];
        if (type == "J" || type == "D") {
            paramRegisterCount += 2;
        } else {
            paramRegisterCount += 1;
        }
    }

    int paramBase = method.registerCount - paramRegisterCount;
    if (paramBase < 0) {
        //LOGE("参数寄存器计算错误 registerCount=%d paramRegisterCount=%d",method.registerCount,paramRegisterCount);
        return false;
    }

    int current = paramBase;

    if (!method.isStatic) {
        ctx.regs[current].objectValue = thiz;
        current++;
    }

    if (args != nullptr) {
        int argCount = env->GetArrayLength(args);

        for (int i = 0; i < argCount && i < static_cast<int>(method.parameterTypes.size()); i++) {
            jobject arg = env->GetObjectArrayElement(args, i);
            ctx.regs[current].objectValue = arg;

            const std::string &type = method.parameterTypes[i];
            if (type == "J" || type == "D") {
                current += 2;
            } else {
                current += 1;
            }
        }
    }

    return true;
}

int VmContext_FindInstructionIndexByOffset(
        VmContext &ctx,
        int codeUnitOffset
) {
    auto it = ctx.offsetToIndex.find(codeUnitOffset);
    if (it == ctx.offsetToIndex.end()) {
        return -1;
    }

    return it->second;
}

