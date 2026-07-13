package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.PackedSwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.formats.SparseSwitchPayload;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.instruction.DualReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodProtoReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodHandleReference;
import com.android.tools.smali.dexlib2.iface.reference.CallSiteReference;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.TypeEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodTypeEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodHandleEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.LongEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.FloatEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.DoubleEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.BooleanEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.ByteEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.ShortEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.CharEncodedValue;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class VmpUtils {
    static final Map<String, ExtractedMethodInfo> EXTRACTED_METHOD_MAP = new LinkedHashMap<>();
    private static native int a(String opcodeName);//根据OpcodeName获取对应Opcode指令的
    static void VMPextractEntry(ZipFile zipFile, String entryName, File outFile) throws IOException {
        ZipEntry entry = zipFile.getEntry(entryName);
        if (entry == null) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("创建目录失败：" + parent.getAbsolutePath());
        }

        try (InputStream in = zipFile.getInputStream(entry);
             FileOutputStream out = new FileOutputStream(outFile)) {

            byte[] buffer = new byte[8192];
            int len;

            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }

    static String buildMethodSignature(Method method) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : method.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(method.getReturnType());

        return sb.toString();
    }

    static String buildMethodReferenceSignature(MethodReference methodRef) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : methodRef.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(methodRef.getReturnType());

        return sb.toString();
    }

    static List<MethodRule> parseMethodRules(String... methodRules) {
        List<MethodRule> rules = new ArrayList<>();

        if (methodRules == null) {
            return rules;
        }

        for (String ruleText : methodRules) {
            if (ruleText == null) {
                continue;
            }

            ruleText = ruleText.trim();
            if (ruleText.isEmpty()) {
                continue;
            }

            String[] parts = ruleText.split("\\.");
            if (parts.length < 3) {
                System.out.println("跳过非法规则：" + ruleText);
                continue;
            }

            String methodName = parts[parts.length - 1];
            String className = parts[parts.length - 2];

            StringBuilder pkg = new StringBuilder();
            for (int i = 0; i < parts.length - 2; i++) {
                if (i > 0) {
                    pkg.append(".");
                }
                pkg.append(parts[i]);
            }

            MethodRule rule = new MethodRule();
            rule.raw = ruleText;
            rule.packageName = pkg.toString();
            rule.className = className;
            rule.methodName = methodName;

            rules.add(rule);

            System.out.println("添加抽取规则：" + rule.raw
                    + " 包名=" + rule.packageName
                    + " 类名=" + rule.className
                    + " 方法=" + rule.methodName);
        }

        return rules;
    }

    static boolean matchAnyRule(List<MethodRule> rules, String javaClassName, String methodName) {
        for (MethodRule rule : rules) {
            if (matchRule(rule, javaClassName, methodName)) {
                return true;
            }
        }
        return false;
    }

    static boolean matchRule(MethodRule rule, String javaClassName, String methodName) {
        if (rule == null || javaClassName == null || methodName == null) {
            return false;
        }

        int lastDot = javaClassName.lastIndexOf('.');
        String pkg = lastDot >= 0 ? javaClassName.substring(0, lastDot) : "";
        String cls = lastDot >= 0 ? javaClassName.substring(lastDot + 1) : javaClassName;

        return matchPart(rule.packageName, pkg)
                && matchPart(rule.className, cls)
                && matchPart(rule.methodName, methodName);
    }

    static boolean matchPart(String rulePart, String value) {
        if ("*".equals(rulePart)) {
            return true;
        }
        return rulePart.equals(value);
    }

    static String dexTypeToJavaName(String dexType) {
        if (dexType == null) {
            return "";
        }

        if (dexType.startsWith("L") && dexType.endsWith(";")) {
            dexType = dexType.substring(1, dexType.length() - 1);
        }

        return dexType.replace('/', '.');
    }

    static boolean isForbiddenExtractMethod(Method method) {
        if (method == null) {
            return true;
        }

        String name = method.getName();
        int flags = method.getAccessFlags();

        if ("<init>".equals(name) || "<clinit>".equals(name)) {
            return true;
        }

        if ((flags & AccessFlags.ABSTRACT.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.NATIVE.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.BRIDGE.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.SYNTHETIC.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.DECLARED_SYNCHRONIZED.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.SYNCHRONIZED.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.VARARGS.getValue()) != 0) {
            return true;
        }

        return false;
    }

    static boolean hasUnsupportedInvokeDynamicInstruction(MethodImplementation impl) {
        if (impl == null) {
            return true;
        }

        for (Instruction instruction : impl.getInstructions()) {
            Opcode opcode = instruction.getOpcode();

            if (opcode == Opcode.INVOKE_POLYMORPHIC
                    || opcode == Opcode.INVOKE_POLYMORPHIC_RANGE
                    || opcode == Opcode.INVOKE_CUSTOM
                    || opcode == Opcode.INVOKE_CUSTOM_RANGE
                    || opcode == Opcode.CONST_METHOD_HANDLE
                    || opcode == Opcode.CONST_METHOD_TYPE) {

                System.out.println("跳过抽取：方法包含暂不支持的动态调用相关指令 opcode=" + opcode.name());
                return true;
            }
        }

        return false;
    }

    /*private static int getRealDexOpcodeValue(Opcode opcode) {
        switch (opcode) {

            case NOP: return 0x00;
            case MOVE: return 0x01;
            case MOVE_FROM16: return 0x02;
            case MOVE_16: return 0x03;
            case MOVE_WIDE: return 0x04;
            case MOVE_WIDE_FROM16: return 0x05;
            case MOVE_WIDE_16: return 0x06;
            case MOVE_OBJECT: return 0x07;
            case MOVE_OBJECT_FROM16: return 0x08;
            case MOVE_OBJECT_16: return 0x09;
            case MOVE_RESULT: return 0x0a;
            case MOVE_RESULT_WIDE: return 0x0b;
            case MOVE_RESULT_OBJECT: return 0x0c;
            case MOVE_EXCEPTION: return 0x0d;
            case RETURN_VOID: return 0x0e;
            case RETURN: return 0x0f;
            case RETURN_WIDE: return 0x10;
            case RETURN_OBJECT: return 0x11;
            case CONST_4: return 0x12;
            case CONST_16: return 0x13;
            case CONST: return 0x14;
            case CONST_HIGH16: return 0x15;
            case CONST_WIDE_16: return 0x16;
            case CONST_WIDE_32: return 0x17;
            case CONST_WIDE: return 0x18;
            case CONST_WIDE_HIGH16: return 0x19;
            case CONST_STRING: return 0x1a;
            case CONST_STRING_JUMBO: return 0x1b;
            case CONST_CLASS: return 0x1c;
            case MONITOR_ENTER: return 0x1d;
            case MONITOR_EXIT: return 0x1e;
            case CHECK_CAST: return 0x1f;
            case INSTANCE_OF: return 0x20;
            case ARRAY_LENGTH: return 0x21;
            case NEW_INSTANCE: return 0x22;
            case NEW_ARRAY: return 0x23;
            case FILLED_NEW_ARRAY: return 0x24;
            case FILLED_NEW_ARRAY_RANGE: return 0x25;
            case FILL_ARRAY_DATA: return 0x26;
            case THROW: return 0x27;
            case GOTO: return 0x28;
            case GOTO_16: return 0x29;
            case GOTO_32: return 0x2a;
            case PACKED_SWITCH: return 0x2b;
            case SPARSE_SWITCH: return 0x2c;
            case CMPL_FLOAT: return 0x2d;
            case CMPG_FLOAT: return 0x2e;
            case CMPL_DOUBLE: return 0x2f;
            case CMPG_DOUBLE: return 0x30;
            case CMP_LONG: return 0x31;
            case IF_EQ: return 0x32;
            case IF_NE: return 0x33;
            case IF_LT: return 0x34;
            case IF_GE: return 0x35;
            case IF_GT: return 0x36;
            case IF_LE: return 0x37;
            case IF_EQZ: return 0x38;
            case IF_NEZ: return 0x39;
            case IF_LTZ: return 0x3a;
            case IF_GEZ: return 0x3b;
            case IF_GTZ: return 0x3c;
            case IF_LEZ: return 0x3d;
            case AGET: return 0x44;
            case AGET_WIDE: return 0x45;
            case AGET_OBJECT: return 0x46;
            case AGET_BOOLEAN: return 0x47;
            case AGET_BYTE: return 0x48;
            case AGET_CHAR: return 0x49;
            case AGET_SHORT: return 0x4a;
            case APUT: return 0x4b;
            case APUT_WIDE: return 0x4c;
            case APUT_OBJECT: return 0x4d;
            case APUT_BOOLEAN: return 0x4e;
            case APUT_BYTE: return 0x4f;
            case APUT_CHAR: return 0x50;
            case APUT_SHORT: return 0x51;
            case IGET: return 0x52;
            case IGET_WIDE: return 0x53;
            case IGET_OBJECT: return 0x54;
            case IGET_BOOLEAN: return 0x55;
            case IGET_BYTE: return 0x56;
            case IGET_CHAR: return 0x57;
            case IGET_SHORT: return 0x58;
            case IPUT: return 0x59;
            case IPUT_WIDE: return 0x5a;
            case IPUT_OBJECT: return 0x5b;
            case IPUT_BOOLEAN: return 0x5c;
            case IPUT_BYTE: return 0x5d;
            case IPUT_CHAR: return 0x5e;
            case IPUT_SHORT: return 0x5f;
            case SGET: return 0x60;
            case SGET_WIDE: return 0x61;
            case SGET_OBJECT: return 0x62;
            case SGET_BOOLEAN: return 0x63;
            case SGET_BYTE: return 0x64;
            case SGET_CHAR: return 0x65;
            case SGET_SHORT: return 0x66;
            case SPUT: return 0x67;
            case SPUT_WIDE: return 0x68;
            case SPUT_OBJECT: return 0x69;
            case SPUT_BOOLEAN: return 0x6a;
            case SPUT_BYTE: return 0x6b;
            case SPUT_CHAR: return 0x6c;
            case SPUT_SHORT: return 0x6d;
            case INVOKE_VIRTUAL: return 0x6e;
            case INVOKE_SUPER: return 0x6f;
            case INVOKE_DIRECT: return 0x70;
            case INVOKE_STATIC: return 0x71;
            case INVOKE_INTERFACE: return 0x72;
            case INVOKE_VIRTUAL_RANGE: return 0x74;
            case INVOKE_SUPER_RANGE: return 0x75;
            case INVOKE_DIRECT_RANGE: return 0x76;
            case INVOKE_STATIC_RANGE: return 0x77;
            case INVOKE_INTERFACE_RANGE: return 0x78;
            case NEG_INT: return 0x7b;
            case NOT_INT: return 0x7c;
            case NEG_LONG: return 0x7d;
            case NOT_LONG: return 0x7e;
            case NEG_FLOAT: return 0x7f;
            case NEG_DOUBLE: return 0x80;
            case INT_TO_LONG: return 0x81;
            case INT_TO_FLOAT: return 0x82;
            case INT_TO_DOUBLE: return 0x83;
            case LONG_TO_INT: return 0x84;
            case LONG_TO_FLOAT: return 0x85;
            case LONG_TO_DOUBLE: return 0x86;
            case FLOAT_TO_INT: return 0x87;
            case FLOAT_TO_LONG: return 0x88;
            case FLOAT_TO_DOUBLE: return 0x89;
            case DOUBLE_TO_INT: return 0x8a;
            case DOUBLE_TO_LONG: return 0x8b;
            case DOUBLE_TO_FLOAT: return 0x8c;
            case INT_TO_BYTE: return 0x8d;
            case INT_TO_CHAR: return 0x8e;
            case INT_TO_SHORT: return 0x8f;
            case ADD_INT: return 0x90;
            case SUB_INT: return 0x91;
            case MUL_INT: return 0x92;
            case DIV_INT: return 0x93;
            case REM_INT: return 0x94;
            case AND_INT: return 0x95;
            case OR_INT: return 0x96;
            case XOR_INT: return 0x97;
            case SHL_INT: return 0x98;
            case SHR_INT: return 0x99;
            case USHR_INT: return 0x9a;
            case ADD_LONG: return 0x9b;
            case SUB_LONG: return 0x9c;
            case MUL_LONG: return 0x9d;
            case DIV_LONG: return 0x9e;
            case REM_LONG: return 0x9f;
            case AND_LONG: return 0xa0;
            case OR_LONG: return 0xa1;
            case XOR_LONG: return 0xa2;
            case SHL_LONG: return 0xa3;
            case SHR_LONG: return 0xa4;
            case USHR_LONG: return 0xa5;
            case ADD_FLOAT: return 0xa6;
            case SUB_FLOAT: return 0xa7;
            case MUL_FLOAT: return 0xa8;
            case DIV_FLOAT: return 0xa9;
            case REM_FLOAT: return 0xaa;
            case ADD_DOUBLE: return 0xab;
            case SUB_DOUBLE: return 0xac;
            case MUL_DOUBLE: return 0xad;
            case DIV_DOUBLE: return 0xae;
            case REM_DOUBLE: return 0xaf;
            case ADD_INT_2ADDR: return 0xb0;
            case SUB_INT_2ADDR: return 0xb1;
            case MUL_INT_2ADDR: return 0xb2;
            case DIV_INT_2ADDR: return 0xb3;
            case REM_INT_2ADDR: return 0xb4;
            case AND_INT_2ADDR: return 0xb5;
            case OR_INT_2ADDR: return 0xb6;
            case XOR_INT_2ADDR: return 0xb7;
            case SHL_INT_2ADDR: return 0xb8;
            case SHR_INT_2ADDR: return 0xb9;
            case USHR_INT_2ADDR: return 0xba;
            case ADD_LONG_2ADDR: return 0xbb;
            case SUB_LONG_2ADDR: return 0xbc;
            case MUL_LONG_2ADDR: return 0xbd;
            case DIV_LONG_2ADDR: return 0xbe;
            case REM_LONG_2ADDR: return 0xbf;
            case AND_LONG_2ADDR: return 0xc0;
            case OR_LONG_2ADDR: return 0xc1;
            case XOR_LONG_2ADDR: return 0xc2;
            case SHL_LONG_2ADDR: return 0xc3;
            case SHR_LONG_2ADDR: return 0xc4;
            case USHR_LONG_2ADDR: return 0xc5;
            case ADD_FLOAT_2ADDR: return 0xc6;
            case SUB_FLOAT_2ADDR: return 0xc7;
            case MUL_FLOAT_2ADDR: return 0xc8;
            case DIV_FLOAT_2ADDR: return 0xc9;
            case REM_FLOAT_2ADDR: return 0xca;
            case ADD_DOUBLE_2ADDR: return 0xcb;
            case SUB_DOUBLE_2ADDR: return 0xcc;
            case MUL_DOUBLE_2ADDR: return 0xcd;
            case DIV_DOUBLE_2ADDR: return 0xce;
            case REM_DOUBLE_2ADDR: return 0xcf;
            case ADD_INT_LIT16: return 0xd0;
            case RSUB_INT: return 0xd1;
            case MUL_INT_LIT16: return 0xd2;
            case DIV_INT_LIT16: return 0xd3;
            case REM_INT_LIT16: return 0xd4;
            case AND_INT_LIT16: return 0xd5;
            case OR_INT_LIT16: return 0xd6;
            case XOR_INT_LIT16: return 0xd7;
            case ADD_INT_LIT8: return 0xd8;
            case RSUB_INT_LIT8: return 0xd9;
            case MUL_INT_LIT8: return 0xda;
            case DIV_INT_LIT8: return 0xdb;
            case REM_INT_LIT8: return 0xdc;
            case AND_INT_LIT8: return 0xdd;
            case OR_INT_LIT8: return 0xde;
            case XOR_INT_LIT8: return 0xdf;
            case SHL_INT_LIT8: return 0xe0;
            case SHR_INT_LIT8: return 0xe1;
            case USHR_INT_LIT8: return 0xe2;
            case INVOKE_POLYMORPHIC: return 0xfa;
            case INVOKE_POLYMORPHIC_RANGE: return 0xfb;
            case INVOKE_CUSTOM: return 0xfc;
            case INVOKE_CUSTOM_RANGE: return 0xfd;
            case CONST_METHOD_HANDLE: return 0xfe;
            case CONST_METHOD_TYPE: return 0xff;

            default:
                throw new RuntimeException(
                        "未支持的Opcode: "
                                + opcode.name()
                                + " ordinal="
                                + opcode.ordinal()
                );
        }
    }*/

    static int getOrCreateVmOpcode(Opcode opcode) {
        if (opcode == null) {
            throw new RuntimeException("opcode为空");
        }

        int realOpcode = a(opcode.name());

        if (realOpcode < 0) {
            throw new RuntimeException("native未支持的Opcode: " + opcode.name());
        }

        System.out.println("写入真实opcode: 0x"
                + Integer.toHexString(realOpcode)
                + " -> 真实指令=" + opcode.name());

        return realOpcode;
    }

    static boolean isValidDexFile(File file) {
        if (file == null || !file.isFile() || file.length() < 0x70) {
            return false;
        }

        try (FileInputStream in = new FileInputStream(file)) {
            byte[] magic = new byte[4];
            int read = in.read(magic);

            if (read != 4) {
                return false;
            }

            return magic[0] == 'd'
                    && magic[1] == 'e'
                    && magic[2] == 'x'
                    && magic[3] == '\n';
        } catch (Exception e) {
            return false;
        }
    }

    static ExtractInstruction buildExtractInstruction(Instruction instruction,
                                                      int codeUnitOffset) {
        ExtractInstruction out = new ExtractInstruction();

        out.codeUnitOffset = codeUnitOffset;

        if (instruction instanceof ArrayPayload) {
            ArrayPayload payload = (ArrayPayload) instruction;

            out.vmOpcode = getOrCreateVmOpcode(Opcode.NOP);
            out.formatName = "ArrayPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 100;
            out.literalValue = payload.getElementWidth();

            out.offsetType = 100;
            out.offsetValue = payload.getArrayElements().size();

            out.referenceType = 100;

            StringBuilder sb = new StringBuilder();
            List<Number> elements = payload.getArrayElements();

            for (int i = 0; i < elements.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(elements.get(i).longValue());
            }

            out.referenceData = sb.toString();

            return out;
        }

        if (instruction instanceof PackedSwitchPayload) {
            PackedSwitchPayload payload = (PackedSwitchPayload) instruction;

            out.vmOpcode = getOrCreateVmOpcode(Opcode.NOP);
            out.formatName = "PackedSwitchPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 101;
            out.literalValue = 0;

            out.offsetType = 101;
            out.offsetValue = payload.getSwitchElements().size();

            out.referenceType = 101;

            StringBuilder sb = new StringBuilder();
            List<? extends SwitchElement> elements = payload.getSwitchElements();

            for (int i = 0; i < elements.size(); i++) {
                SwitchElement element = elements.get(i);

                if (i > 0) {
                    sb.append(",");
                }

                sb.append(element.getKey());
                sb.append(":");
                sb.append(element.getOffset());
            }

            out.referenceData = sb.toString();

            return out;
        }

        if (instruction instanceof SparseSwitchPayload) {
            SparseSwitchPayload payload = (SparseSwitchPayload) instruction;

            out.vmOpcode = getOrCreateVmOpcode(Opcode.NOP);
            out.formatName = "SparseSwitchPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 102;
            out.literalValue = 0;

            out.offsetType = 102;
            out.offsetValue = payload.getSwitchElements().size();

            out.referenceType = 102;

            StringBuilder sb = new StringBuilder();
            List<? extends SwitchElement> elements = payload.getSwitchElements();

            for (int i = 0; i < elements.size(); i++) {
                SwitchElement element = elements.get(i);

                if (i > 0) {
                    sb.append(",");
                }

                sb.append(element.getKey());
                sb.append(":");
                sb.append(element.getOffset());
            }

            out.referenceData = sb.toString();

            return out;
        }

        out.vmOpcode = getOrCreateVmOpcode(instruction.getOpcode());
        out.formatName = String.valueOf(instruction.getOpcode().format);
        out.codeUnits = instruction.getCodeUnits();

        if (instruction instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction insn = (FiveRegisterInstruction) instruction;
            int count = insn.getRegisterCount();
            if (count >= 1) out.registers.add(insn.getRegisterC());
            if (count >= 2) out.registers.add(insn.getRegisterD());
            if (count >= 3) out.registers.add(insn.getRegisterE());
            if (count >= 4) out.registers.add(insn.getRegisterF());
            if (count >= 5) out.registers.add(insn.getRegisterG());
        } else if (instruction instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction insn = (RegisterRangeInstruction) instruction;
            for (int i = 0; i < insn.getRegisterCount(); i++) {
                out.registers.add(insn.getStartRegister() + i);
            }
        } else if (instruction instanceof ThreeRegisterInstruction) {
            ThreeRegisterInstruction insn = (ThreeRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
            out.registers.add(insn.getRegisterB());
            out.registers.add(insn.getRegisterC());
        } else if (instruction instanceof TwoRegisterInstruction) {
            TwoRegisterInstruction insn = (TwoRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
            out.registers.add(insn.getRegisterB());
        } else if (instruction instanceof OneRegisterInstruction) {
            OneRegisterInstruction insn = (OneRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
        }

        if (instruction instanceof WideLiteralInstruction) {
            WideLiteralInstruction insn = (WideLiteralInstruction) instruction;
            out.literalType = 2;
            out.literalValue = insn.getWideLiteral();
        } else if (instruction instanceof NarrowLiteralInstruction) {
            NarrowLiteralInstruction insn = (NarrowLiteralInstruction) instruction;
            out.literalType = 1;
            out.literalValue = insn.getNarrowLiteral();
        }

        if (instruction instanceof OffsetInstruction) {
            OffsetInstruction insn = (OffsetInstruction) instruction;
            out.offsetType = 1;
            out.offsetValue = insn.getCodeOffset();
        }

        if (instruction instanceof ReferenceInstruction) {
            Reference reference = ((ReferenceInstruction) instruction).getReference();

            out.referenceType = getReferenceTypeCode(reference);
            out.referenceData = buildReferenceText(reference);
        }

        if (instruction instanceof DualReferenceInstruction) {
            Reference reference2 = ((DualReferenceInstruction) instruction).getReference2();

            out.extraReferenceType = getReferenceTypeCode(reference2);
            out.extraReferenceData = buildReferenceText(reference2);
        }

        return out;
    }

    static List<ExtractTryBlock> buildExtractTryBlocks(MethodImplementation impl) {
        List<ExtractTryBlock> result = new ArrayList<>();

        if (impl == null || impl.getTryBlocks() == null) {
            return result;
        }

        for (TryBlock<? extends ExceptionHandler> tryBlock : impl.getTryBlocks()) {
            ExtractTryBlock out = new ExtractTryBlock();
            out.startCodeAddress = tryBlock.getStartCodeAddress();
            out.codeUnitCount = tryBlock.getCodeUnitCount();

            for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                ExtractExceptionHandler h = new ExtractExceptionHandler();
                h.exceptionType = handler.getExceptionType();
                h.handlerCodeAddress = handler.getHandlerCodeAddress();
                out.handlers.add(h);
            }

            result.add(out);
        }

        return result;
    }

    static List<ClassIndexEntry> writeVmpBinary(File outFile,
                                                List<ExtractMethodBlock> blocks) throws IOException {
        List<ClassIndexEntry> indexEntries = new ArrayList<>();

        try (RandomAccessFile raf = new RandomAccessFile(outFile, "rw")) {
            raf.setLength(0);

            writeBytes(raf, new byte[]{'A', 'V', 'M', 'P'});
            writeIntLE(raf, 6);

            writeIntLE(raf, blocks.size());

            long indexTableOffset = raf.getFilePointer();
            for (int i = 0; i < blocks.size(); i++) {
                writeIntLE(raf, 0);
                writeLongLE(raf, 0);
                writeIntLE(raf, 0);
            }

            for (ExtractMethodBlock block : blocks) {
                long blockOffset = raf.getFilePointer();

                writeIntLE(raf, block.methodId);
                writeStringLE(raf, block.dexName);
                writeStringLE(raf, block.className);
                writeStringLE(raf, block.methodName);
                writeStringLE(raf, block.methodSignature);
                writeIntLE(raf, block.accessFlags);
                writeIntLE(raf, block.registerCount);
                writeIntLE(raf, block.paramCount);
                writeStringLE(raf, block.returnType);
                writeIntLE(raf, block.isStatic ? 1 : 0);

                writeIntLE(raf, block.parameterTypes.size());
                for (String paramType : block.parameterTypes) {
                    writeStringLE(raf, paramType);
                }

                writeIntLE(raf, block.instructions.size());

                for (ExtractInstruction insn : block.instructions) {
                    writeIntLE(raf, insn.codeUnitOffset);

                    // 这里现在直接写真实dex opcode，不再写随机vm opcode
                    writeIntLE(raf, insn.vmOpcode);

                    writeStringLE(raf, insn.formatName);
                    writeIntLE(raf, insn.codeUnits);

                    writeIntLE(raf, insn.registers.size());
                    for (Integer reg : insn.registers) {
                        writeIntLE(raf, reg);
                    }

                    writeIntLE(raf, insn.literalType);
                    writeLongLE(raf, insn.literalValue);

                    writeIntLE(raf, insn.offsetType);
                    writeIntLE(raf, insn.offsetValue);

                    writeIntLE(raf, insn.referenceType);
                    writeStringLE(raf, insn.referenceData);

                    writeIntLE(raf, insn.extraReferenceType);
                    writeStringLE(raf, insn.extraReferenceData);
                }

                writeIntLE(raf, block.tryBlocks.size());
                for (ExtractTryBlock tryBlock : block.tryBlocks) {
                    writeIntLE(raf, tryBlock.startCodeAddress);
                    writeIntLE(raf, tryBlock.codeUnitCount);

                    writeIntLE(raf, tryBlock.handlers.size());
                    for (ExtractExceptionHandler handler : tryBlock.handlers) {
                        writeStringLE(raf, handler.exceptionType);
                        writeIntLE(raf, handler.handlerCodeAddress);
                    }
                }

                long blockEnd = raf.getFilePointer();

                ClassIndexEntry index = new ClassIndexEntry();
                index.methodId = block.methodId;
                index.offset = blockOffset;
                index.size = (int) (blockEnd - blockOffset);
                indexEntries.add(index);
            }

            long fileEnd = raf.getFilePointer();

            raf.seek(indexTableOffset);
            for (ClassIndexEntry index : indexEntries) {
                writeIntLE(raf, index.methodId);
                writeLongLE(raf, index.offset);
                writeIntLE(raf, index.size);
            }

            raf.seek(fileEnd);

            System.out.println("bin版本=6");
            System.out.println("已移除opcode映射表，instruction.vmOpcode直接保存真实opcode");
            System.out.println("method索引表偏移=" + indexTableOffset);
            System.out.println("bin文件总大小=" + fileEnd);
        }

        return indexEntries;
    }

    static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    static final int[] INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    static void xorEncryptVmpBinFile(File plainFile, File encryptedFile) throws IOException {
        if (plainFile == null || !plainFile.isFile()) {
            throw new IOException("明文vmp文件不存在");
        }

        if (encryptedFile == null) {
            throw new IOException("加密vmp输出文件为空");
        }

        byte[] plainData = readAllBytes(plainFile);

        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);

        int keyLen = key.length;
        int halfLen = keyLen / 2;

        byte[] data = new byte[plainData.length];

        for (int i = 0; i < plainData.length; i++) {
            data[i] = (byte) (plainData[i] ^ key[i % keyLen]);
        }

        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) SBOX[data[i] & 0xFF];
        }

        int shift = (key[0] & 0x7) + 1;
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xFF;
            data[i] = (byte) (((b >>> shift) | (b << (8 - shift))) & 0xFF);
        }

        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ key[(i + halfLen) % keyLen]);
        }

        try (FileOutputStream out = new FileOutputStream(encryptedFile)) {
            out.write(new byte[]{'A', 'V', 'M', 'X'});
            writeIntLE(out, 3);
            writeIntLE(out, data.length);
            out.write(data);
            out.write(key);
            writeIntLE(out, keyLen);
        }
    }
    static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int offset = 0;

            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);

                if (read == -1) {
                    break;
                }

                offset += read;
            }

            if (offset != data.length) {
                throw new IOException("读取文件不完整：" + file.getAbsolutePath());
            }

            return data;
        }
    }
    static void writeIntLE(FileOutputStream out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }

    static void writeVmpText(File outFile,
                             List<ClassIndexEntry> indexEntries,
                             List<ExtractMethodBlock> blocks) throws IOException {
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outFile), StandardCharsets.UTF_8))) {

            pw.println("magic=AVMP");
            pw.println("version=6");

            pw.println();
            pw.println("methodIndexCount=" + indexEntries.size());

            pw.println();
            pw.println("========== methodId索引表 ==========");
            for (int i = 0; i < indexEntries.size(); i++) {
                ClassIndexEntry index = indexEntries.get(i);

                pw.println("index[" + i + "] {");
                pw.println("  methodId=" + index.methodId);
                pw.println("  offset=" + index.offset);
                pw.println("  size=" + index.size);
                pw.println("}");
            }

            pw.println();
            pw.println("========== 方法数据块 ==========");
            for (int blockIndex = 0; blockIndex < blocks.size(); blockIndex++) {
                ExtractMethodBlock block = blocks.get(blockIndex);

                pw.println();
                pw.println("methodBlock[" + blockIndex + "] {");

                pw.println("  methodId=" + block.methodId);
                pw.println("  dexName=" + block.dexName);
                pw.println("  className=" + block.className);
                pw.println("  methodName=" + block.methodName);
                pw.println("  methodSignature=" + block.methodSignature);
                pw.println("  accessFlags=0x" + Integer.toHexString(block.accessFlags));
                pw.println("  registerCount=" + block.registerCount);
                pw.println("  paramCount=" + block.paramCount);
                pw.println("  returnType=" + block.returnType);
                pw.println("  isStatic=" + (block.isStatic ? 1 : 0));

                pw.println();
                pw.println("  parameterTypeCount=" + block.parameterTypes.size());
                for (int i = 0; i < block.parameterTypes.size(); i++) {
                    pw.println("  parameterType[" + i + "]=" + block.parameterTypes.get(i));
                }

                pw.println();
                pw.println("  instructionCount=" + block.instructions.size());

                for (int insnIndex = 0; insnIndex < block.instructions.size(); insnIndex++) {
                    ExtractInstruction insn = block.instructions.get(insnIndex);

                    pw.println();
                    pw.println("  instruction[" + insnIndex + "] {");

                    pw.println("    codeUnitOffset=" + insn.codeUnitOffset);

                    // 这里和 vmp.bin 一样，vmOpcode 字段里直接保存真实 dex opcode
                    pw.println("    vmOpcode=0x" + String.format("%02x", insn.vmOpcode));

                    pw.println("    formatName=" + insn.formatName);
                    pw.println("    codeUnits=" + insn.codeUnits);

                    pw.println("    registerCount=" + insn.registers.size());
                    for (int i = 0; i < insn.registers.size(); i++) {
                        pw.println("    register[" + i + "]=" + insn.registers.get(i));
                    }

                    pw.println("    literalType=" + insn.literalType);
                    pw.println("    literalValue=" + insn.literalValue);

                    pw.println("    offsetType=" + insn.offsetType);
                    pw.println("    offsetValue=" + insn.offsetValue);

                    pw.println("    referenceType=" + insn.referenceType);
                    pw.println("    referenceData=" + insn.referenceData);

                    pw.println("    extraReferenceType=" + insn.extraReferenceType);
                    pw.println("    extraReferenceData=" + insn.extraReferenceData);

                    pw.println("  }");
                }

                pw.println();
                pw.println("  tryBlockCount=" + block.tryBlocks.size());

                for (int tryIndex = 0; tryIndex < block.tryBlocks.size(); tryIndex++) {
                    ExtractTryBlock tryBlock = block.tryBlocks.get(tryIndex);

                    pw.println();
                    pw.println("  tryBlock[" + tryIndex + "] {");
                    pw.println("    startCodeAddress=" + tryBlock.startCodeAddress);
                    pw.println("    codeUnitCount=" + tryBlock.codeUnitCount);

                    pw.println("    handlerCount=" + tryBlock.handlers.size());
                    for (int handlerIndex = 0; handlerIndex < tryBlock.handlers.size(); handlerIndex++) {
                        ExtractExceptionHandler handler = tryBlock.handlers.get(handlerIndex);

                        pw.println("    handler[" + handlerIndex + "] {");
                        pw.println("      exceptionType=" + handler.exceptionType);
                        pw.println("      handlerCodeAddress=" + handler.handlerCodeAddress);
                        pw.println("    }");
                    }

                    pw.println("  }");
                }

                pw.println("}");
            }
        }
    }

    private static void writeStringLE(RandomAccessFile out, String value) throws IOException {
        if (value == null) {
            writeIntLE(out, -1);
            return;
        }

        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        writeIntLE(out, data.length);
        writeBytes(out, data);
    }

    private static void writeIntLE(RandomAccessFile out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }

    private static void writeLongLE(RandomAccessFile out, long value) throws IOException {
        out.write((int) (value & 0xff));
        out.write((int) ((value >> 8) & 0xff));
        out.write((int) ((value >> 16) & 0xff));
        out.write((int) ((value >> 24) & 0xff));
        out.write((int) ((value >> 32) & 0xff));
        out.write((int) ((value >> 40) & 0xff));
        out.write((int) ((value >> 48) & 0xff));
        out.write((int) ((value >> 56) & 0xff));
    }

    private static void writeBytes(RandomAccessFile out, byte[] data) throws IOException {
        out.write(data);
    }

    static int readIntLE(RandomAccessFile in) throws IOException {
        int b0 = in.read();
        int b1 = in.read();
        int b2 = in.read();
        int b3 = in.read();

        if ((b0 | b1 | b2 | b3) < 0) {
            throw new IOException("读取int失败，文件长度不足");
        }

        return (b0 & 0xff)
                | ((b1 & 0xff) << 8)
                | ((b2 & 0xff) << 16)
                | ((b3 & 0xff) << 24);
    }

    static long readLongLE(RandomAccessFile in) throws IOException {
        long b0 = in.read();
        long b1 = in.read();
        long b2 = in.read();
        long b3 = in.read();
        long b4 = in.read();
        long b5 = in.read();
        long b6 = in.read();
        long b7 = in.read();

        if ((b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7) < 0) {
            throw new IOException("读取long失败，文件长度不足");
        }

        return (b0 & 0xff)
                | ((b1 & 0xff) << 8)
                | ((b2 & 0xff) << 16)
                | ((b3 & 0xff) << 24)
                | ((b4 & 0xff) << 32)
                | ((b5 & 0xff) << 40)
                | ((b6 & 0xff) << 48)
                | ((b7 & 0xff) << 56);
    }

    static String readStringLE(RandomAccessFile in) throws IOException {
        int len = readIntLE(in);

        if (len == -1) {
            return null;
        }

        if (len < 0) {
            throw new IOException("字符串长度非法：" + len);
        }

        byte[] data = new byte[len];
        readFully(in, data);

        return new String(data, StandardCharsets.UTF_8);
    }

    static void readFully(RandomAccessFile in, byte[] data) throws IOException {
        int offset = 0;

        while (offset < data.length) {
            int read = in.read(data, offset, data.length - offset);
            if (read == -1) {
                throw new IOException("读取文件失败，文件长度不足");
            }
            offset += read;
        }
    }

    static String buildExtractedMethodKey(String dexName, String className, String methodName, String methodSignature) {
        return dexName + "|" + className + "->" + methodName + methodSignature;
    }

    static void recordExtractedMethod(ExtractMethodBlock block) {
        if (block == null) {
            return;
        }

        ExtractedMethodInfo info = new ExtractedMethodInfo();
        info.methodId = block.methodId;
        info.dexName = block.dexName;
        info.className = block.className;
        info.methodName = block.methodName;
        info.methodSignature = block.methodSignature;
        info.accessFlags = block.accessFlags;
        info.registerCount = block.registerCount;
        info.paramCount = block.paramCount;
        info.returnType = block.returnType;

        String key = buildExtractedMethodKey(
                block.dexName,
                block.className,
                block.methodName,
                block.methodSignature
        );

        EXTRACTED_METHOD_MAP.put(key, info);

        System.out.println("记录待native重写方法 key=" + key
                + " methodId=" + block.methodId
                + " accessFlags=0x" + Integer.toHexString(block.accessFlags)
                + " returnType=" + block.returnType);
    }
    private static ExtractedMethodInfo getExtractedMethodInfo(String dexName,
                                                              String className,
                                                              String methodName,
                                                              String methodSignature) {
        String key = buildExtractedMethodKey(dexName, className, methodName, methodSignature);
        return EXTRACTED_METHOD_MAP.get(key);
    }
    /**
     * :TODO
     * 生成一个VMP的入口类。
     */
    public static ClassDef createVmpClass(String soName, String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) {
            throw new IllegalArgumentException("包名不能为空");
        }

        String cleanPackageName = packageName.trim();
        String classType = "L" + cleanPackageName.replace('.', '/') + "/VMP;";

        List<Method> methods = new ArrayList<>();

        // public VMP()
        MethodImplementation initImpl = new ImmutableMethodImplementation(
                1,
                Arrays.asList(
                        new ImmutableInstruction35c(
                                Opcode.INVOKE_DIRECT,
                                1,
                                0,
                                0,
                                0,
                                0,
                                0,
                                new ImmutableMethodReference(
                                        "Ljava/lang/Object;",
                                        "<init>",
                                        Collections.emptyList(),
                                        "V"
                                )
                        ),
                        new ImmutableInstruction10x(Opcode.RETURN_VOID)
                ),
                null,
                null
        );

        methods.add(new ImmutableMethod(
                classType,
                "<init>",
                Collections.emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                initImpl
        ));

        List<MethodParameter> commonParams = Arrays.asList(
                new ImmutableMethodParameter("I", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Collections.emptySet(), null),
                new ImmutableMethodParameter("[Ljava/lang/Object;", Collections.emptySet(), null)
        );

        int nativeFlags = AccessFlags.PUBLIC.getValue()
                | AccessFlags.STATIC.getValue()
                | AccessFlags.NATIVE.getValue();

        methods.add(new ImmutableMethod(
                classType,
                "callVoid",
                commonParams,
                "V",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callBoolean",
                commonParams,
                "Z",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callByte",
                commonParams,
                "B",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callShort",
                commonParams,
                "S",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callChar",
                commonParams,
                "C",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callInt",
                commonParams,
                "I",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callLong",
                commonParams,
                "J",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callFloat",
                commonParams,
                "F",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callDouble",
                commonParams,
                "D",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callObject",
                commonParams,
                "Ljava/lang/Object;",
                nativeFlags,
                null,
                null,
                null
        ));

        return new ImmutableClassDef(
                classType,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                "VMP.java",
                null,
                Collections.emptyList(),
                methods
        );
    }
    public static ClassDef createVmpClass2(String soName, String packageName) {
        if (soName == null || soName.trim().isEmpty()) {
            throw new IllegalArgumentException("so库名称不能为空");
        }

        if (packageName == null || packageName.trim().isEmpty()) {
            throw new IllegalArgumentException("包名不能为空");
        }

        String cleanPackageName = packageName.trim();
        String classType = "L" + cleanPackageName.replace('.', '/') + "/VMP;";

        List<Method> methods = new ArrayList<>();

        // public VMP()
        MethodImplementation initImpl = new ImmutableMethodImplementation(
                1,
                Arrays.asList(
                        new ImmutableInstruction35c(
                                Opcode.INVOKE_DIRECT,
                                1,
                                0,
                                0,
                                0,
                                0,
                                0,
                                new ImmutableMethodReference(
                                        "Ljava/lang/Object;",
                                        "<init>",
                                        Collections.emptyList(),
                                        "V"
                                )
                        ),
                        new ImmutableInstruction10x(Opcode.RETURN_VOID)
                ),
                null,
                null
        );

        methods.add(new ImmutableMethod(
                classType,
                "<init>",
                Collections.emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                initImpl
        ));

        // static { System.loadLibrary("传入的so库名称"); }
        MethodImplementation clinitImpl = new ImmutableMethodImplementation(
                1,
                Arrays.asList(
                        new ImmutableInstruction21c(
                                Opcode.CONST_STRING,
                                0,
                                new ImmutableStringReference(soName)
                        ),
                        new ImmutableInstruction35c(
                                Opcode.INVOKE_STATIC,
                                1,
                                0,
                                0,
                                0,
                                0,
                                0,
                                new ImmutableMethodReference(
                                        "Ljava/lang/System;",
                                        "loadLibrary",
                                        Collections.singletonList("Ljava/lang/String;"),
                                        "V"
                                )
                        ),
                        new ImmutableInstruction10x(Opcode.RETURN_VOID)
                ),
                null,
                null
        );

        methods.add(new ImmutableMethod(
                classType,
                "<clinit>",
                Collections.emptyList(),
                "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                clinitImpl
        ));

        List<MethodParameter> commonParams = Arrays.asList(
                new ImmutableMethodParameter("I", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Collections.emptySet(), null),
                new ImmutableMethodParameter("[Ljava/lang/Object;", Collections.emptySet(), null)
        );

        int nativeFlags = AccessFlags.PUBLIC.getValue()
                | AccessFlags.STATIC.getValue()
                | AccessFlags.NATIVE.getValue();

        methods.add(new ImmutableMethod(
                classType,
                "callVoid",
                commonParams,
                "V",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callBoolean",
                commonParams,
                "Z",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callByte",
                commonParams,
                "B",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callShort",
                commonParams,
                "S",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callChar",
                commonParams,
                "C",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callInt",
                commonParams,
                "I",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callLong",
                commonParams,
                "J",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callFloat",
                commonParams,
                "F",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callDouble",
                commonParams,
                "D",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callObject",
                commonParams,
                "Ljava/lang/Object;",
                nativeFlags,
                null,
                null,
                null
        ));

        return new ImmutableClassDef(
                classType,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                "VMP.java",
                null,
                Collections.emptyList(),
                methods
        );
    }
    /**
     * :TODO
     * 返回一个带 VMP 入口调用的DEX
     * */
    public static DexFile createVmpShellDex(String soName, String packageName) {
        ClassDef vmpClass = createVmpClass(soName, packageName);

        List<ClassDef> classes = new ArrayList<>();
        classes.add(vmpClass);

        return new ImmutableDexFile(
                Opcodes.getDefault(),
                classes
        );
    }

    static ClassDef rewriteClassForVmCall(String dexName, ClassDef classDef, String vmpClassType) {
        if (classDef == null) {
            return null;
        }

        boolean isInterface = (classDef.getAccessFlags() & AccessFlags.INTERFACE.getValue()) != 0;
        if (isInterface) {
            return classDef;
        }

        String classType = classDef.getType();

        // 关键优化：
        // 如果当前类没有任何被抽取的方法，直接返回原始 classDef，
        // 不再创建 newMethods，也不再遍历所有方法。
        if (!hasExtractedMethodInClass(dexName, classType)) {
            return classDef;
        }

        List<Method> newMethods = new ArrayList<>(countClassMethods(classDef));
        boolean changed = false;

        for (Method method : classDef.getMethods()) {
            String signature = buildMethodSignature(method);

            ExtractedMethodInfo info = getExtractedMethodInfo(
                    dexName,
                    classType,
                    method.getName(),
                    signature
            );

            if (info == null) {
                newMethods.add(method);
                continue;
            }

            // 二次保险：这些方法即使 map 里有，也不能重写
            if (isForbiddenExtractMethod(method) || method.getImplementation() == null) {
                newMethods.add(method);
                System.out.println("跳过VM重写非法方法："
                        + dexName + " "
                        + classType + "->"
                        + method.getName()
                        + signature);
                continue;
            }

            Method newMethod = buildVmCallMethod(method, info, vmpClassType);
            newMethods.add(newMethod);
            changed = true;

            System.out.println("方法重写为VM调用壳："
                    + dexName
                    + " "
                    + classType
                    + "->"
                    + method.getName()
                    + signature
                    + " methodId=" + info.methodId
                    + " returnType=" + method.getReturnType());
        }

        if (!changed) {
            return classDef;
        }

        return new ImmutableClassDef(
                classDef.getType(),
                classDef.getAccessFlags(),
                classDef.getSuperclass(),
                classDef.getInterfaces(),
                classDef.getSourceFile(),
                classDef.getAnnotations(),
                classDef.getFields(),
                newMethods
        );
    }

    private static boolean hasExtractedMethodInClass(String dexName, String classType) {
        if (dexName == null || classType == null || EXTRACTED_METHOD_MAP.isEmpty()) {
            return false;
        }

        String prefix = dexName + "|" + classType + "->";

        for (String key : EXTRACTED_METHOD_MAP.keySet()) {
            if (key != null && key.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }
    private static Method buildVmCallMethod(Method oldMethod,
                                            ExtractedMethodInfo info,
                                            String vmpClassType) {
        String returnType = oldMethod.getReturnType();
        boolean isStatic = (oldMethod.getAccessFlags() & AccessFlags.STATIC.getValue()) != 0;

        List<String> parameterTypes = new ArrayList<>();
        for (CharSequence type : oldMethod.getParameterTypes()) {
            parameterTypes.add(String.valueOf(type));
        }

        int localCount = 8;
        int paramRegisterCount = isStatic ? 0 : 1;

        for (String type : parameterTypes) {
            paramRegisterCount += getTypeRegisterCount(type);
        }

        int totalRegisterCount = localCount + paramRegisterCount;

        List<Instruction> instructions = new ArrayList<>(16 + parameterTypes.size() * 4);

        int regMethodId = 0;
        int regThis = 1;
        int regArgs = 2;
        int regIndex = 3;
        int regTempObj = 4;
        int regReturn = 4;

        int pBase = localCount;
        int thisRegister = isStatic ? -1 : pBase;
        int firstParamRegister = isStatic ? pBase : pBase + 1;

        instructions.add(new ImmutableInstruction31i(
                Opcode.CONST,
                regMethodId,
                info.methodId
        ));

        if (isStatic) {
            instructions.add(new ImmutableInstruction11n(
                    Opcode.CONST_4,
                    regThis,
                    0
            ));
        } else {
            instructions.add(new ImmutableInstruction22x(
                    Opcode.MOVE_OBJECT_FROM16,
                    regThis,
                    thisRegister
            ));
        }

        appendBuildArgsArrayInstructions(
                instructions,
                parameterTypes,
                firstParamRegister,
                regArgs,
                regIndex,
                regTempObj
        );

        appendCallAndReturnInstructions(
                instructions,
                returnType,
                vmpClassType,
                regMethodId,
                regThis,
                regArgs,
                regReturn
        );

        MethodImplementation impl = new ImmutableMethodImplementation(
                totalRegisterCount,
                instructions,
                null,
                null
        );

        int newAccessFlags = oldMethod.getAccessFlags();
        newAccessFlags &= ~AccessFlags.NATIVE.getValue();
        newAccessFlags &= ~AccessFlags.ABSTRACT.getValue();

        return new ImmutableMethod(
                oldMethod.getDefiningClass(),
                oldMethod.getName(),
                oldMethod.getParameters(),
                oldMethod.getReturnType(),
                newAccessFlags,
                oldMethod.getAnnotations(),
                null,
                impl
        );
    }
    private static void appendBuildArgsArrayInstructions(List<Instruction> instructions,
                                                         List<String> parameterTypes,
                                                         int firstParamRegister,
                                                         int regArgs,
                                                         int regIndex,
                                                         int regTempObj) {
        instructions.add(new ImmutableInstruction31i(
                Opcode.CONST,
                regIndex,
                parameterTypes.size()
        ));

        instructions.add(new ImmutableInstruction22c(
                Opcode.NEW_ARRAY,
                regArgs,
                regIndex,
                new ImmutableTypeReference("[Ljava/lang/Object;")
        ));

        int currentParamRegister = firstParamRegister;

        for (int i = 0; i < parameterTypes.size(); i++) {
            String type = parameterTypes.get(i);

            instructions.add(new ImmutableInstruction31i(
                    Opcode.CONST,
                    regIndex,
                    i
            ));

            if (isPrimitiveType(type)) {
                appendBoxPrimitiveInstruction(
                        instructions,
                        type,
                        currentParamRegister,
                        regTempObj
                );

                instructions.add(new ImmutableInstruction23x(
                        Opcode.APUT_OBJECT,
                        regTempObj,
                        regArgs,
                        regIndex
                ));
            } else {
                instructions.add(new ImmutableInstruction23x(
                        Opcode.APUT_OBJECT,
                        currentParamRegister,
                        regArgs,
                        regIndex
                ));
            }

            currentParamRegister += getTypeRegisterCount(type);
        }
    }
    static void writeCombinedDexStreaming(File dexDir,
                                          int outDexIndex,
                                          final String dexName,
                                          final DexFile sourceDex,
                                          final String vmpClassType) throws IOException {
        String outName = outDexIndex == 1 ? "classes_c.dex" : "classes" + outDexIndex + "_c.dex";
        File outFile = new File(dexDir, outName);

        final Set<? extends ClassDef> sourceClasses = sourceDex.getClasses();

        DexFile outDex = new DexFile() {
            @Override
            public Set<? extends ClassDef> getClasses() {
                return new AbstractSet<ClassDef>() {
                    @Override
                    public Iterator<ClassDef> iterator() {
                        final Iterator<? extends ClassDef> it = sourceClasses.iterator();

                        return new Iterator<ClassDef>() {
                            @Override
                            public boolean hasNext() {
                                return it.hasNext();
                            }

                            @Override
                            public ClassDef next() {
                                ClassDef oldClass = it.next();
                                return rewriteClassForVmCall(dexName, oldClass, vmpClassType);
                            }

                            @Override
                            public void remove() {
                                throw new UnsupportedOperationException("不支持删除class");
                            }
                        };
                    }

                    @Override
                    public int size() {
                        return sourceClasses.size();
                    }
                };
            }

            @Override
            public Opcodes getOpcodes() {
                return sourceDex.getOpcodes();
            }
        };

        DexFileFactory.writeDexFile(outFile.getAbsolutePath(), outDex);

        System.out.println("写出重组dex：" + outFile.getAbsolutePath()
                + " classCount=" + sourceClasses.size());
    }
    private static void appendBoxPrimitiveInstruction(List<Instruction> instructions,
                                                      String type,
                                                      int paramRegister,
                                                      int regTempObj) {
        String owner;
        String methodName = "valueOf";
        List<String> params;
        String ret;

        if ("Z".equals(type)) {
            owner = "Ljava/lang/Boolean;";
            params = Collections.singletonList("Z");
            ret = "Ljava/lang/Boolean;";
        } else if ("B".equals(type)) {
            owner = "Ljava/lang/Byte;";
            params = Collections.singletonList("B");
            ret = "Ljava/lang/Byte;";
        } else if ("S".equals(type)) {
            owner = "Ljava/lang/Short;";
            params = Collections.singletonList("S");
            ret = "Ljava/lang/Short;";
        } else if ("C".equals(type)) {
            owner = "Ljava/lang/Character;";
            params = Collections.singletonList("C");
            ret = "Ljava/lang/Character;";
        } else if ("I".equals(type)) {
            owner = "Ljava/lang/Integer;";
            params = Collections.singletonList("I");
            ret = "Ljava/lang/Integer;";
        } else if ("J".equals(type)) {
            owner = "Ljava/lang/Long;";
            params = Collections.singletonList("J");
            ret = "Ljava/lang/Long;";
        } else if ("F".equals(type)) {
            owner = "Ljava/lang/Float;";
            params = Collections.singletonList("F");
            ret = "Ljava/lang/Float;";
        } else if ("D".equals(type)) {
            owner = "Ljava/lang/Double;";
            params = Collections.singletonList("D");
            ret = "Ljava/lang/Double;";
        } else {
            throw new IllegalArgumentException("不支持的基础类型：" + type);
        }

        if ("J".equals(type) || "D".equals(type)) {
            instructions.add(new ImmutableInstruction3rc(
                    Opcode.INVOKE_STATIC_RANGE,
                    paramRegister,
                    2,
                    new ImmutableMethodReference(
                            owner,
                            methodName,
                            params,
                            ret
                    )
            ));
        } else {
            instructions.add(new ImmutableInstruction3rc(
                    Opcode.INVOKE_STATIC_RANGE,
                    paramRegister,
                    1,
                    new ImmutableMethodReference(
                            owner,
                            methodName,
                            params,
                            ret
                    )
            ));
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.MOVE_RESULT_OBJECT,
                regTempObj
        ));
    }
    private static void appendCallAndReturnInstructions(List<Instruction> instructions,
                                                        String returnType,
                                                        String vmpClassType,
                                                        int regMethodId,
                                                        int regThis,
                                                        int regArgs,
                                                        int regReturn) {
        String callMethodName = getCallMethodNameByReturnType(returnType);
        String callReturnType = getCallReturnType(returnType);

        instructions.add(new ImmutableInstruction3rc(
                Opcode.INVOKE_STATIC_RANGE,
                regMethodId,
                3,
                new ImmutableMethodReference(
                        vmpClassType,
                        callMethodName,
                        Arrays.asList(
                                "I",
                                "Ljava/lang/Object;",
                                "[Ljava/lang/Object;"
                        ),
                        callReturnType
                )
        ));

        if ("V".equals(returnType)) {
            instructions.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
            return;
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            instructions.add(new ImmutableInstruction11x(
                    Opcode.MOVE_RESULT_WIDE,
                    regReturn
            ));

            instructions.add(new ImmutableInstruction11x(
                    Opcode.RETURN_WIDE,
                    regReturn
            ));
            return;
        }

        if (isPrimitiveType(returnType)) {
            instructions.add(new ImmutableInstruction11x(
                    Opcode.MOVE_RESULT,
                    regReturn
            ));

            instructions.add(new ImmutableInstruction11x(
                    Opcode.RETURN,
                    regReturn
            ));
            return;
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.MOVE_RESULT_OBJECT,
                regReturn
        ));

        if (!"Ljava/lang/Object;".equals(returnType)) {
            instructions.add(new ImmutableInstruction21c(
                    Opcode.CHECK_CAST,
                    regReturn,
                    new ImmutableTypeReference(returnType)
            ));
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.RETURN_OBJECT,
                regReturn
        ));
    }
    private static String getCallMethodNameByReturnType(String returnType) {
        if ("V".equals(returnType)) {
            return "callVoid";
        }

        if ("Z".equals(returnType)) {
            return "callBoolean";
        }

        if ("B".equals(returnType)) {
            return "callByte";
        }

        if ("S".equals(returnType)) {
            return "callShort";
        }

        if ("C".equals(returnType)) {
            return "callChar";
        }

        if ("I".equals(returnType)) {
            return "callInt";
        }

        if ("J".equals(returnType)) {
            return "callLong";
        }

        if ("F".equals(returnType)) {
            return "callFloat";
        }

        if ("D".equals(returnType)) {
            return "callDouble";
        }

        return "callObject";
    }

    private static String getCallReturnType(String returnType) {
        if ("V".equals(returnType)) {
            return "V";
        }

        if (isPrimitiveType(returnType)) {
            return returnType;
        }

        return "Ljava/lang/Object;";
    }
    private static int getTypeRegisterCount(String type) {
        if ("J".equals(type) || "D".equals(type)) {
            return 2;
        }

        return 1;
    }
    private static boolean isPrimitiveType(String type) {
        return "Z".equals(type)
                || "B".equals(type)
                || "S".equals(type)
                || "C".equals(type)
                || "I".equals(type)
                || "J".equals(type)
                || "F".equals(type)
                || "D".equals(type);
    }
    static void writeCombinedDex(File dexDir,
                                 int outDexIndex,
                                 List<ClassDef> classes) throws IOException {
        String outName = outDexIndex == 1 ? "classes_c.dex" : "classes" + outDexIndex + "_c.dex";
        File outFile = new File(dexDir, outName);

        DexFile outDex = new ImmutableDexFile(
                Opcodes.getDefault(),
                classes
        );

        DexFileFactory.writeDexFile(outFile.getAbsolutePath(), outDex);

        System.out.println("写出重组dex：" + outFile.getAbsolutePath()
                + " classCount=" + classes.size());
    }
    static int countClassMethods(ClassDef classDef) {
        int count = 0;
        for (Method ignored : classDef.getMethods()) {
            count++;
        }
        return count;
    }

    static class ExtractedMethodInfo {
        int methodId;
        String dexName;
        String className;
        String methodName;
        String methodSignature;
        int accessFlags;
        int registerCount;
        int paramCount;
        String returnType;
    }
    static class MethodRule {
        String raw;
        String packageName;
        String className;
        String methodName;
    }

    static class ExtractMethodBlock {
        int methodId;
        String dexName;
        String className;
        String methodName;
        String methodSignature;
        int accessFlags;
        int registerCount;
        int paramCount;
        String returnType;

        boolean isStatic;
        List<String> parameterTypes = new ArrayList<>();

        List<ExtractInstruction> instructions = new ArrayList<>();
        List<ExtractTryBlock> tryBlocks = new ArrayList<>();
    }

    static class OpcodeMapEntry {
        int vmOpcode;
        int realOpcode;
        String realOpcodeName;
    }

    private static class ExtractInstruction {
        int codeUnitOffset;
        int vmOpcode;

        String formatName;
        int codeUnits;

        List<Integer> registers = new ArrayList<>();

        int literalType = 0;
        long literalValue = 0;

        int offsetType = 0;
        int offsetValue = 0;

        int referenceType = 0;
        String referenceData = null;

        int extraReferenceType = 0;
        String extraReferenceData = null;
    }

    static class ClassIndexEntry {
        int methodId;
        long offset;
        int size;
    }

    static class ExtractTryBlock {
        int startCodeAddress;
        int codeUnitCount;
        List<ExtractExceptionHandler> handlers = new ArrayList<>();
    }

    static class ExtractExceptionHandler {
        String exceptionType;
        int handlerCodeAddress;
    }

    static void replaceOriginalDexWithCombinedDex(File dexDir) throws IOException {
        if (dexDir == null || !dexDir.isDirectory()) {
            throw new IOException("dex目录不存在");
        }

        // 1. 删除原始 dex：classes.dex、classes2.dex、classes3.dex...
        int oldIndex = 1;
        while (true) {
            String oldName = oldIndex == 1 ? "classes.dex" : "classes" + oldIndex + ".dex";
            File oldDex = new File(dexDir, oldName);

            if (!oldDex.exists()) {
                break;
            }

            if (!oldDex.delete()) {
                throw new IOException("删除原始dex失败：" + oldDex.getAbsolutePath());
            }

            System.out.println("已删除原始dex：" + oldDex.getName());
            oldIndex++;
        }

        // 2. 将新生成的 dex 改名为标准 dex 名称
        int newIndex = 1;
        while (true) {
            String tempName = newIndex == 1 ? "classes_c.dex" : "classes" + newIndex + "_c.dex";
            File tempDex = new File(dexDir, tempName);

            if (!tempDex.exists()) {
                break;
            }

            String finalName = newIndex == 1 ? "classes.dex" : "classes" + newIndex + ".dex";
            File finalDex = new File(dexDir, finalName);

            if (!tempDex.renameTo(finalDex)) {
                throw new IOException("重命名dex失败："
                        + tempDex.getAbsolutePath()
                        + " -> "
                        + finalDex.getAbsolutePath());
            }

            System.out.println("已重命名dex：" + tempDex.getName() + " -> " + finalDex.getName());
            newIndex++;
        }

        if (newIndex == 1) {
            throw new IOException("未找到新生成的 *_c.dex 文件");
        }
    }
    static String buildMethodProtoSignature(MethodProtoReference protoRef) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : protoRef.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(protoRef.getReturnType());

        return sb.toString();
    }

    static String buildReferenceText(Reference reference) {
        if (reference == null) {
            return null;
        }

        if (reference instanceof StringReference) {
            return ((StringReference) reference).getString();
        }

        if (reference instanceof TypeReference) {
            return ((TypeReference) reference).getType();
        }

        if (reference instanceof FieldReference) {
            FieldReference field = (FieldReference) reference;
            return field.getDefiningClass()
                    + "->" + field.getName()
                    + ":" + field.getType();
        }

        if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            return method.getDefiningClass()
                    + "->" + method.getName()
                    + buildMethodReferenceSignature(method);
        }

        if (reference instanceof MethodProtoReference) {
            return buildMethodProtoSignature((MethodProtoReference) reference);
        }

        if (reference instanceof MethodHandleReference) {
            return buildMethodHandleText((MethodHandleReference) reference);
        }

        if (reference instanceof CallSiteReference) {
            CallSiteReference callSite = (CallSiteReference) reference;

            StringBuilder sb = new StringBuilder();

            sb.append("name=").append(vmpEscape(callSite.getName())).append("\n");
            sb.append("methodName=").append(vmpEscape(callSite.getMethodName())).append("\n");
            sb.append("methodProto=").append(vmpEscape(buildMethodProtoSignature(callSite.getMethodProto()))).append("\n");
            sb.append("methodHandle=").append(vmpEscape(buildMethodHandleText(callSite.getMethodHandle()))).append("\n");

            List<? extends EncodedValue> extraArgs = callSite.getExtraArguments();
            sb.append("extraCount=").append(extraArgs.size()).append("\n");

            for (int i = 0; i < extraArgs.size(); i++) {
                sb.append("extra").append(i).append("=")
                        .append(vmpEscape(buildEncodedValueText(extraArgs.get(i))))
                        .append("\n");
            }

            return sb.toString();
        }

        return String.valueOf(reference);
    }

    static int getReferenceTypeCode(Reference reference) {
        if (reference instanceof StringReference) {
            return 1;
        }

        if (reference instanceof TypeReference) {
            return 2;
        }

        if (reference instanceof FieldReference) {
            return 3;
        }

        if (reference instanceof MethodReference) {
            return 4;
        }

        if (reference instanceof MethodProtoReference) {
            return 5;
        }

        if (reference instanceof MethodHandleReference) {
            return 6;
        }

        if (reference instanceof CallSiteReference) {
            return 7;
        }

        return 9;
    }

    static String vmpEscape(String s) {
        if (s == null) {
            return "";
        }

        return s.replace("%", "%25")
                .replace("\n", "%0A")
                .replace("=", "%3D")
                .replace("|", "%7C")
                .replace(";", "%3B");
    }

    static String buildMethodHandleText(MethodHandleReference handle) {
        if (handle == null) {
            return "";
        }

        Reference member = handle.getMemberReference();

        return handle.getMethodHandleType()
                + "|" + getReferenceTypeCode(member)
                + "|" + vmpEscape(buildReferenceText(member));
    }

    static String buildEncodedValueText(EncodedValue value) {
        if (value == null) {
            return "null|";
        }

        if (value instanceof StringEncodedValue) {
            return "string|" + vmpEscape(((StringEncodedValue) value).getValue());
        }

        if (value instanceof TypeEncodedValue) {
            return "type|" + vmpEscape(((TypeEncodedValue) value).getValue());
        }

        if (value instanceof MethodTypeEncodedValue) {
            return "proto|" + vmpEscape(buildMethodProtoSignature(((MethodTypeEncodedValue) value).getValue()));
        }

        if (value instanceof MethodHandleEncodedValue) {
            return "handle|" + vmpEscape(buildMethodHandleText(((MethodHandleEncodedValue) value).getValue()));
        }

        if (value instanceof IntEncodedValue) {
            return "int|" + ((IntEncodedValue) value).getValue();
        }

        if (value instanceof LongEncodedValue) {
            return "long|" + ((LongEncodedValue) value).getValue();
        }

        if (value instanceof FloatEncodedValue) {
            return "float|" + ((FloatEncodedValue) value).getValue();
        }

        if (value instanceof DoubleEncodedValue) {
            return "double|" + ((DoubleEncodedValue) value).getValue();
        }

        if (value instanceof BooleanEncodedValue) {
            return "boolean|" + (((BooleanEncodedValue) value).getValue() ? "1" : "0");
        }

        if (value instanceof ByteEncodedValue) {
            return "byte|" + ((ByteEncodedValue) value).getValue();
        }

        if (value instanceof ShortEncodedValue) {
            return "short|" + ((ShortEncodedValue) value).getValue();
        }

        if (value instanceof CharEncodedValue) {
            return "char|" + (int) ((CharEncodedValue) value).getValue();
        }

        return "unknown|" + vmpEscape(String.valueOf(value));
    }





}
