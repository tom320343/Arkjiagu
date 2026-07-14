#ifndef GUARD_ENV_GUARD_H
#define GUARD_ENV_GUARD_H

#include <jni.h>

typedef bool (*GuardEnvGuardFunc)(JNIEnv *env, jobject context);

GuardEnvGuardFunc GuardEnvGuard_GetEntry();

GuardEnvGuardFunc GuardEnvGuard_GetStartRealApplicationEntry();

GuardEnvGuardFunc GuardEnvGuard_GetFullGuardEntry();

#endif
