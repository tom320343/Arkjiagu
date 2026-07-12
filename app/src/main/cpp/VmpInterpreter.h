#ifndef VMP_INTERPRETER_H
#define VMP_INTERPRETER_H

#include <jni.h>
#include "VmpTypes.h"

VmResult VmpInterpreter_Execute(
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
);

#endif

