#include "VmpInterpreter.h"
#include "VmContext.h"
#include "VmOpcodeHandler.h"
#include <android/log.h>
#include <vector>

#define LOG_TAG "GuardVMP_Interpreter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)



VmResult VmpInterpreter_Execute(
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
) {
    VmResult emptyResult;

    VmContext ctx;
    if (!VmContext_Init(ctx, env, method, thiz, args)) {
        //LOGE("VmContext 初始化失败");
        return emptyResult;
    }
    int stepCount = 0;
    const int maxStepCount = 200000;

    while (ctx.running && ctx.pc >= 0 && ctx.pc < static_cast<int>(method.instructions.size())) {
        stepCount++;

        if (stepCount > maxStepCount) {
            //LOGE("VM执行步数超限 methodId=%d pc=%d instructionCount=%d",method.methodId,ctx.pc,(int) method.instructions.size());
            break;
        }
        const VmpInstruction &insn = method.instructions[ctx.pc];

        //LOGI("step=%d instruction[%d] offset=%d vmOpcode=0x%02x realOpcode=0x%x opcode=%s",stepCount,ctx.pc,insn.codeUnitOffset,insn.vmOpcode,insn.realOpcode,insn.opcodeName.c_str());

        VmHandler handler = getHandlerByRealOpcode(insn.realOpcode);//根据真实字节码指令，拿到对应的实现方法
        if (handler == nullptr) {
            //LOGE("未支持的指令realOpcode=0x%x opcode=%s",insn.realOpcode,insn.opcodeName.c_str());
            break;
        }

        if (!handler(ctx, insn)) {
            //LOGE("handler执行失败 realOpcode=0x%x opcode=%s",insn.realOpcode,insn.opcodeName.c_str());
            break;
        }
    }

    return ctx.result;
}

