// ArkSelfHash.cpp
#include <jni.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <errno.h>
#include "GuardSelfHash.h"


extern "C"
jboolean ark_get_self_cert_sha256(JNIEnv *env, jbyteArray outSha256) {

    /*env->SetByteArrayRegion(
            outSha256,
            0,
            32,
            (jbyte *) sha32);*/

    //GUARD_LOGI("[ArkSelfHash] Java byte[] 回写成功");

    //GUARD_LOGI("[ArkSelfHash] ===== 获取自身证书SHA256成功 =====");

    return JNI_TRUE;
}