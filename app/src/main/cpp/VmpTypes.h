#ifndef VMP_TYPES_H
#define VMP_TYPES_H

#include <jni.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdint.h>

struct VmResult {
    jobject objectValue = nullptr;
    jint intValue = 0;
    jlong longValue = 0;
    jfloat floatValue = 0;
    jdouble doubleValue = 0;
    jboolean booleanValue = JNI_FALSE;
    jbyte byteValue = 0;
    jshort shortValue = 0;
    jchar charValue = 0;
};

struct VmpMethodIndex {
    int methodId = 0;
    uint64_t offset = 0;
    uint32_t size = 0;
};

struct VmpOpcodeMapEntry {
    int vmOpcode = 0;
    int realOpcode = 0;
    std::string realOpcodeName;
};

struct VmpExceptionHandler {
    std::string exceptionType;
    int handlerCodeAddress = 0;
};

struct VmpTryBlock {
    int startCodeAddress = 0;
    int codeUnitCount = 0;
    std::vector<VmpExceptionHandler> handlers;
};

struct VmpInstruction {
    int codeUnitOffset = 0;
    int vmOpcode = 0;

    // 只从 opcode 映射表恢复，不从方法块读取
    int realOpcode = 0;
    std::string opcodeName;

    std::string formatName;
    int codeUnits = 0;

    std::vector<int> registers;

    int literalType = 0;
    int64_t literalValue = 0;

    int offsetType = 0;
    int offsetValue = 0;

    int referenceType = 0;
    std::string referenceData;

    int extraReferenceType = 0;
    std::string extraReferenceData;
};

struct VmpMethod {
    int methodId = 0;
    std::string dexName;
    std::string className;
    std::string methodName;
    std::string methodSignature;
    int accessFlags = 0;
    int registerCount = 0;
    int paramCount = 0;
    std::string returnType;
    bool isStatic = false;
    std::vector<VmpTryBlock> tryBlocks;
    std::vector<std::string> parameterTypes;
    std::vector<VmpInstruction> instructions;
};

struct VmpBinContext {
    bool loaded = false;
    int version = 0;

    std::vector<unsigned char> rawData;

    // 随机 vmOpcode -> 真实 opcode / 真实 opname
    std::unordered_map<int, VmpOpcodeMapEntry> vmOpcodeMap;

    std::unordered_map<int, VmpMethodIndex> methodIndexMap;

    std::unordered_map<int, VmpMethod> methodCache;
};

#endif

