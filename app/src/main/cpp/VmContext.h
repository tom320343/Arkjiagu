#ifndef VM_CONTEXT_H
#define VM_CONTEXT_H

#include <jni.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <stdint.h>
#include "VmpTypes.h"

enum VmRegKind {
    VM_REG_UNKNOWN = 0,
    VM_REG_INT = 1,
    VM_REG_LONG = 2,
    VM_REG_OBJECT = 3
};


struct VmRegister {
    jobject objectValue = nullptr;
    int intValue = 0;
    int64_t longValue = 0;
    VmRegKind kind = VM_REG_UNKNOWN;
};

struct VmContext {
    JNIEnv *env = nullptr;

    const VmpMethod *method = nullptr;

    jobject thiz = nullptr;
    jobjectArray args = nullptr;

    std::vector<VmRegister> regs;

    jobject lastResultObject = nullptr;
    int lastResultInt;
    int64_t lastResultLong = 0;
    jobject currentException = nullptr;



    int pc = 0;
    bool running = true;

    VmResult result;

    std::unordered_map<int, int> offsetToIndex;
};

bool VmContext_Init(
        VmContext &ctx,
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
);

int VmContext_FindInstructionIndexByOffset(
        VmContext &ctx,
        int codeUnitOffset
);

#endif

