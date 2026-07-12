#ifndef VMP_RUNTIME_H
#define VMP_RUNTIME_H

#include <jni.h>
#include "VmpTypes.h"

void VmpRuntime_SetContext(JNIEnv *env, jobject context);

jobject VmpRuntime_GetContext();

VmResult VmpRuntime_Execute(
        JNIEnv *env,
        jint methodId,
        jobject thiz,
        jobjectArray args
);

#endif

