#ifndef GUARD_DEX_LOADER_H
#define GUARD_DEX_LOADER_H

#include <jni.h>

typedef bool (*GuardDexLoaderFunc)(JNIEnv *env, jobject context);
typedef bool (*GuardDexLoaderFactoryFunc)(JNIEnv *env, jobject parentClassLoader);
typedef bool (*GuardRealApplicationStarterFunc)(JNIEnv *env, jobject context);
const char *GuardDexLoader_GetRealAppComponentFactoryName();
GuardDexLoaderFunc GuardDexLoader_GetEntry();

GuardDexLoaderFactoryFunc GuardDexLoader_GetFactoryEntry();

GuardRealApplicationStarterFunc GuardDexLoader_GetStartRealApplicationEntry();

#endif

