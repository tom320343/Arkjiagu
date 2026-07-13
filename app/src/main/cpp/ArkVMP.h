#ifndef ARK_VMP_H
#define ARK_VMP_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void ArkVMP_SetContext(JNIEnv *env, jobject context);
int ArkVMP_OnLoad(JavaVM *vm);
extern const char g_ark_vmp_section[];

#ifdef __cplusplus
}
#endif

#endif
