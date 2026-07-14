#ifndef GUARD_VMP_H
#define GUARD_VMP_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void GuardVMP_SetContext(JNIEnv *env, jobject context);
int GuardVMP_OnLoad(JavaVM *vm);
extern const char g_guard_vmp_section[];

#ifdef __cplusplus
}
#endif

#endif
