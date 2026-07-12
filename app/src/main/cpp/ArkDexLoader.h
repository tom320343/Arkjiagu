#ifndef ARK_DEX_LOADER_H
#define ARK_DEX_LOADER_H

#include <jni.h>

typedef bool (*ArkDexLoaderFunc)(JNIEnv *env, jobject context);
typedef bool (*ArkDexLoaderFactoryFunc)(JNIEnv *env, jobject parentClassLoader);
typedef bool (*ArkRealApplicationStarterFunc)(JNIEnv *env, jobject context);
const char *ArkDexLoader_GetRealAppComponentFactoryName();
ArkDexLoaderFunc ArkDexLoader_GetEntry();

ArkDexLoaderFactoryFunc ArkDexLoader_GetFactoryEntry();

ArkRealApplicationStarterFunc ArkDexLoader_GetStartRealApplicationEntry();

#endif

