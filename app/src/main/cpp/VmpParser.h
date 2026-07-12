#ifndef VMP_PARSER_H
#define VMP_PARSER_H

#include <jni.h>
#include "VmpTypes.h"

bool VmpParser_EnsureLoaded(JNIEnv *env, jobject context);

bool VmpParser_FindMethod(
        JNIEnv *env,
        int methodId,
        VmpMethod &outMethod
);

#endif

