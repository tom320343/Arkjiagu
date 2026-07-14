# 安卓加固 3.0 (APK Protector)

APK离线加固工具，支持 DEX 加密、VMP 代码虚拟化、多层签名校验与环境检测。

## 核心功能

- **DEX 整体加密**: 对 DEX 文件进行多层加密 (XOR + AES S-Box + 字节旋转 + 双Xor)
- **VMP 代码抽取**: 将关键方法指令抽取到 Native 层虚拟执行
- **签名校验**: 支持证书 SHA256 校验，防止二次打包
- **环境检测**: Root、Xposed/LSPosed、多开分身、调试器检测
- **企业伪装**: 自定义加固签名名称，隐藏保护特征

## 架构说明

```
native 入口 → 注册 VMP call 方法 → 解析 vmp.bin → 缓存指令映射表
方法调用时 → 根据方法 ID 查索引表 → 获取偏移 → 还原真实指令 → 执行
```

关键源文件:

| 文件 | 作用 |
|------|------|
| `GuardStub.cpp` | Native 入口，初始化虚拟机 |
| `GuardVMP.cpp` | VMP 注册与 call 方法分发 |
| `VmpRuntime.cpp` | 运行时执行入口 |
| `VmpInterpreter.cpp` | 虚拟机指令分发器 |
| `VmHandlers.cpp` | 256 条 Dalvik 指令的 C 层实现 |

## 构建

```bash
# 配置 local.properties 指定 SDK/NDK 路径
echo "sdk.dir=/opt/android-sdk" > local.properties
echo "ndk.dir=/opt/android-sdk/ndk/27.0.12077973" >> local.properties

# 编译
./gradlew assembleDebug
```

## 调试

在 Android Studio LogCat 中筛选 `tag:GuardEngine` 查看虚拟机执行日志。

## 声明

本项目仅供 Android 安全学习和合法应用保护研究使用，请勿用于非法目的。
