package com.ark.jiagu.vm;

import java.lang.invoke.CallSite;
import java.lang.invoke.LambdaMetafactory;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.MutableCallSite;
import java.lang.invoke.StringConcatFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class VmpInvokeCustomHelper {

    public static Object invokeCustom(String callSiteData, Object[] args) throws Throwable {
        CallSiteInfo info = parseCallSiteInfo(callSiteData);

        MethodHandle bootstrap = parseMethodHandle(info.methodHandle);
        MethodHandles.Lookup lookup = MethodHandles.lookup();

        Object[] extraArgs = buildExtraArgs(info);

        CallSite callSite;

        if (isLambdaMetafactory(info.methodHandle)) {
            MethodType invokedType = methodTypeFromDexProto(info.methodProto);

            MethodType samMethodType = extraArgs.length > 0 && extraArgs[0] instanceof MethodType
                    ? (MethodType) extraArgs[0]
                    : MethodType.methodType(Object.class);

            MethodHandle implMethod = extraArgs.length > 1 && extraArgs[1] instanceof MethodHandle
                    ? (MethodHandle) extraArgs[1]
                    : null;

            MethodType instantiatedMethodType = extraArgs.length > 2 && extraArgs[2] instanceof MethodType
                    ? (MethodType) extraArgs[2]
                    : samMethodType;

            if (implMethod == null) {
                throw new UnsupportedOperationException("LambdaMetafactory 缺少 implMethod");
            }

            callSite = LambdaMetafactory.metafactory(
                    lookup,
                    info.methodName,
                    invokedType,
                    samMethodType,
                    implMethod,
                    instantiatedMethodType
            );
        } else if (isStringConcatFactory(info.methodHandle)) {
            MethodType invokedType = methodTypeFromDexProto(info.methodProto);

            String recipe = "";
            Object[] constants = new Object[0];

            if (extraArgs.length > 0 && extraArgs[0] instanceof String) {
                recipe = (String) extraArgs[0];
            }

            if (extraArgs.length > 1) {
                constants = new Object[extraArgs.length - 1];
                System.arraycopy(extraArgs, 1, constants, 0, constants.length);
            }

            callSite = makeConcatCallSite(
                    lookup,
                    info.methodName,
                    invokedType,
                    recipe,
                    constants
            );
        } else {
            Object[] bootstrapArgs = new Object[3 + extraArgs.length];
            bootstrapArgs[0] = lookup;
            bootstrapArgs[1] = info.methodName;
            bootstrapArgs[2] = methodTypeFromDexProto(info.methodProto);
            System.arraycopy(extraArgs, 0, bootstrapArgs, 3, extraArgs.length);

            Object result = bootstrap.invokeWithArguments(bootstrapArgs);

            if (!(result instanceof CallSite)) {
                throw new UnsupportedOperationException("bootstrap返回值不是CallSite: " + result);
            }

            callSite = (CallSite) result;
        }

        MethodHandle target = callSite.getTarget();

        if (args == null || args.length == 0) {
            return target.invokeWithArguments();
        }

        return target.invokeWithArguments(args);
    }

    private static boolean isLambdaMetafactory(String methodHandleText) {
        return methodHandleText != null
                && methodHandleText.contains("Ljava/lang/invoke/LambdaMetafactory;->metafactory");
    }

    private static boolean isStringConcatFactory(String methodHandleText) {
        return methodHandleText != null
                && methodHandleText.contains("Ljava/lang/invoke/StringConcatFactory;");
    }

    private static Object[] buildExtraArgs(CallSiteInfo info) throws Throwable {
        Object[] result = new Object[info.extraCount];

        for (int i = 0; i < info.extraCount; i++) {
            String text = info.extras.get("extra" + i);
            result[i] = parseEncodedValue(text);
        }

        return result;
    }

    private static Object parseEncodedValue(String text) throws Throwable {
        if (text == null || text.length() == 0) {
            return null;
        }

        int p = text.indexOf('|');
        if (p < 0) {
            return text;
        }

        String type = text.substring(0, p);
        String value = text.substring(p + 1);

        if ("null".equals(type)) {
            return null;
        }

        if ("string".equals(type)) {
            return value;
        }

        if ("type".equals(type)) {
            return classFromDexType(value);
        }

        if ("proto".equals(type)) {
            return methodTypeFromDexProto(value);
        }

        if ("handle".equals(type)) {
            return parseMethodHandle(value);
        }

        if ("int".equals(type)) {
            return Integer.parseInt(value);
        }

        if ("long".equals(type)) {
            return Long.parseLong(value);
        }

        if ("float".equals(type)) {
            return Float.parseFloat(value);
        }

        if ("double".equals(type)) {
            return Double.parseDouble(value);
        }

        if ("boolean".equals(type)) {
            return "1".equals(value);
        }

        if ("byte".equals(type)) {
            return Byte.parseByte(value);
        }

        if ("short".equals(type)) {
            return Short.parseShort(value);
        }

        if ("char".equals(type)) {
            return (char) Integer.parseInt(value);
        }

        return value;
    }

    private static MethodHandle parseMethodHandle(String text) throws Throwable {
        if (text == null || text.length() == 0) {
            throw new IllegalArgumentException("methodHandle为空");
        }

        String[] parts = text.split("\\|", 3);
        if (parts.length < 3) {
            throw new IllegalArgumentException("methodHandle格式错误: " + text);
        }

        int handleType = Integer.parseInt(parts[0]);
        int refType = Integer.parseInt(parts[1]);
        String member = parts[2];

        MethodHandles.Lookup lookup = MethodHandles.lookup();

        if (refType == 4) {
            MethodRef methodRef = parseMethodRef(member);
            Class<?> owner = classFromDexType(methodRef.owner);
            MethodType methodType = methodTypeFromDexProto(methodRef.proto);

            if (handleType == 4) {
                return lookup.findStatic(owner, methodRef.name, methodType);
            }

            if (handleType == 5 || handleType == 8) {
                return lookup.findVirtual(owner, methodRef.name, methodType);
            }

            if (handleType == 6) {
                return lookup.findConstructor(owner, methodType);
            }

            if (handleType == 7) {
                Method method = findDeclaredMethod(owner, methodRef.name, methodType);
                method.setAccessible(true);
                return lookup.unreflectSpecial(method, owner);
            }
        }

        if (refType == 3) {
            FieldRef fieldRef = parseFieldRef(member);
            Class<?> owner = classFromDexType(fieldRef.owner);
            Class<?> fieldType = classFromDexType(fieldRef.type);

            if (handleType == 0) {
                return lookup.findStaticSetter(owner, fieldRef.name, fieldType);
            }

            if (handleType == 1) {
                return lookup.findStaticGetter(owner, fieldRef.name, fieldType);
            }

            if (handleType == 2) {
                return lookup.findSetter(owner, fieldRef.name, fieldType);
            }

            if (handleType == 3) {
                return lookup.findGetter(owner, fieldRef.name, fieldType);
            }
        }

        throw new UnsupportedOperationException("不支持的methodHandle: " + text);
    }

    private static Method findDeclaredMethod(Class<?> owner, String name, MethodType type)
            throws NoSuchMethodException {
        Class<?>[] params = type.parameterArray();

        Class<?> c = owner;
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, params);
            } catch (NoSuchMethodException ignored) {
                c = c.getSuperclass();
            }
        }

        throw new NoSuchMethodException(owner.getName() + "." + name + type);
    }

    private static MethodType methodTypeFromDexProto(String proto) throws ClassNotFoundException {
        int start = proto.indexOf('(');
        int end = proto.indexOf(')');

        if (start < 0 || end < 0 || end <= start) {
            throw new IllegalArgumentException("proto格式错误: " + proto);
        }

        String paramsText = proto.substring(start + 1, end);
        String returnText = proto.substring(end + 1);

        Class<?> returnType = classFromDexType(returnText);

        java.util.ArrayList<Class<?>> params = new java.util.ArrayList<>();

        int i = 0;
        while (i < paramsText.length()) {
            TypeParseResult r = parseOneDexType(paramsText, i);
            params.add(classFromDexType(r.type));
            i = r.next;
        }

        return MethodType.methodType(returnType, params);
    }

    private static TypeParseResult parseOneDexType(String text, int index) {
        int i = index;

        while (i < text.length() && text.charAt(i) == '[') {
            i++;
        }

        if (i >= text.length()) {
            throw new IllegalArgumentException("类型格式错误: " + text);
        }

        char c = text.charAt(i);

        if (c == 'L') {
            int semi = text.indexOf(';', i);
            if (semi < 0) {
                throw new IllegalArgumentException("对象类型格式错误: " + text);
            }

            return new TypeParseResult(text.substring(index, semi + 1), semi + 1);
        }

        return new TypeParseResult(text.substring(index, i + 1), i + 1);
    }

    private static Class<?> classFromDexType(String type) throws ClassNotFoundException {
        if ("V".equals(type)) return void.class;
        if ("Z".equals(type)) return boolean.class;
        if ("B".equals(type)) return byte.class;
        if ("S".equals(type)) return short.class;
        if ("C".equals(type)) return char.class;
        if ("I".equals(type)) return int.class;
        if ("J".equals(type)) return long.class;
        if ("F".equals(type)) return float.class;
        if ("D".equals(type)) return double.class;

        if (type.startsWith("[")) {
            return Class.forName(type.replace('/', '.'));
        }

        if (type.startsWith("L") && type.endsWith(";")) {
            String name = type.substring(1, type.length() - 1).replace('/', '.');
            return Class.forName(name);
        }

        return Class.forName(type);
    }

    private static MethodRef parseMethodRef(String text) {
        int arrow = text.indexOf("->");
        int sig = text.indexOf('(', arrow + 2);

        if (arrow < 0 || sig < 0) {
            throw new IllegalArgumentException("方法引用格式错误: " + text);
        }

        MethodRef out = new MethodRef();
        out.owner = text.substring(0, arrow);
        out.name = text.substring(arrow + 2, sig);
        out.proto = text.substring(sig);
        return out;
    }

    private static FieldRef parseFieldRef(String text) {
        int arrow = text.indexOf("->");
        int colon = text.indexOf(':', arrow + 2);

        if (arrow < 0 || colon < 0) {
            throw new IllegalArgumentException("字段引用格式错误: " + text);
        }

        FieldRef out = new FieldRef();
        out.owner = text.substring(0, arrow);
        out.name = text.substring(arrow + 2, colon);
        out.type = text.substring(colon + 1);
        return out;
    }

    private static CallSiteInfo parseCallSiteInfo(String data) {
        CallSiteInfo info = new CallSiteInfo();

        if (data == null) {
            throw new IllegalArgumentException("callSiteData为空");
        }

        String[] lines = data.split("\n");

        for (String line : lines) {
            if (line == null || line.length() == 0) {
                continue;
            }

            int p = line.indexOf('=');
            if (p < 0) {
                continue;
            }

            String key = line.substring(0, p);
            String value = vmpUnescape(line.substring(p + 1));

            if ("name".equals(key)) {
                info.name = value;
            } else if ("methodName".equals(key)) {
                info.methodName = value;
            } else if ("methodProto".equals(key)) {
                info.methodProto = value;
            } else if ("methodHandle".equals(key)) {
                info.methodHandle = value;
            } else if ("extraCount".equals(key)) {
                info.extraCount = Integer.parseInt(value);
            } else if (key.startsWith("extra")) {
                info.extras.put(key, vmpUnescape(value));
            }
        }

        return info;
    }

    private static String vmpUnescape(String s) {
        if (s == null) {
            return "";
        }

        return s.replace("%0A", "\n")
                .replace("%3B", ";")
                .replace("%7C", "|")
                .replace("%3D", "=")
                .replace("%25", "%");
    }

    private static CallSite makeConcatCallSite(
            MethodHandles.Lookup lookup,
            String name,
            MethodType concatType,
            String recipe,
            Object[] constants) throws Throwable {
        if (recipe == null || recipe.isEmpty()) {
            recipe = "\u0001";
        }
        MethodHandle mh = MethodHandles.constant(String.class, "");
        if (constants != null && constants.length > 0) {
            StringBuilder sb = new StringBuilder();
            int constIdx = 0;
            for (int i = 0; i < recipe.length(); i++) {
                char c = recipe.charAt(i);
                if (c == '\u0001' && constIdx < constants.length) {
                    sb.append(constants[constIdx++] != null ? constants[constIdx].toString() : "null");
                } else if (c == '\u0002') {
                    constIdx++;
                } else {
                    sb.append(c);
                }
            }
            MethodHandle concatHandle = MethodHandles.constant(String.class, sb.toString());
            return new MutableCallSite(concatHandle);
        }
        return new MutableCallSite(MethodHandles.constant(String.class, ""));
    }

    private static class CallSiteInfo {
        String name;
        String methodName;
        String methodProto;
        String methodHandle;
        int extraCount;
        Map<String, String> extras = new HashMap<>();
    }

    private static class MethodRef {
        String owner;
        String name;
        String proto;
    }

    private static class FieldRef {
        String owner;
        String name;
        String type;
    }

    private static class TypeParseResult {
        String type;
        int next;

        TypeParseResult(String type, int next) {
            this.type = type;
            this.next = next;
        }
    }
}

