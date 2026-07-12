Ark加固2.0 By：菜鸟八哥
主要更新：新增了抽代码到VMP，加固的时候会读取AndroidManifest.xml中的所有Activity类，并抽取里面的onCreate方法到vmp.bin

注意：此次开源的demo版本，vmp.bin里面存放着被抽取的原始指令，未做任何加密，仅用作学习

原始代码：
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    this.editTextInput = (EditText) findViewById(R.id.editTextInput);
    Button button = (Button) findViewById(R.id.buttonTest);
    this.buttonTest = button;
    button.setOnClickListener(new 1(this));
}

抽vmp之后的代码：
protected void onCreate(Bundle bundle) {
    VMP.callVoid(1, this, new Object[]{bundle});
}

源码文件说明：
VmOpcodeDef.h       存放着虚拟机的指令和OpcodeName对照表，需要和VmpUtils类中的getRealDexOpcodeValue方法一致

VmHandlers.h        存放着指令调用方法声明
VmHandlers.cpp      存放着dalvik指令的实现,每一个指令全部由C层手动实现(最大的一份源码)
VmOpcodeHandler.cpp 存放着OpcodeName的映射方法
新增指令实现，就要同步在上面3份源码中新增

VmpInterpreter.cpp  虚拟机的入口执行方法

在 MainActivity 类顶部有声明一个 DEBUG_MODE 属性，设置为1之后，生成在 ArkJiagu 目录中会保留所有的信息:原始dex，抽vmp后的dex，vmp.bin的二进制文件，vmp.txt 的明文对照文件

源码调用关系：
ArkStub.cpp 依旧是统一的原始入口
ArkStub.cpp 在初始化阶段会调用 ArkVMP.cpp 中的 ArkVMP_OnLoad 方法进行call方法注册
同时 attachBaseContext 初始化阶段会将 Context 传给 ArkVMP.cpp
每个call方法注册到 VmpRuntime.cpp 的 VmpRuntime_Execute 方法
VmpRuntime_Execute方法的作用就是根据方法id去 assets/vmp.bin 中寻找对应的方法
找到方法之后就执行 VmpInterpreter.cpp 的 VmpInterpreter_Execute 方法，这个方法就是最终执行指令分发的方法

VM虚拟机的执行逻辑：
native层启动→注册call方法→解析vmp.bin文件→从里面拿到指令映射表以及方法索引表进行缓存
当某个方法执行的时候会传入一个方法id，也就是call的第一个数字参数
然后虚拟机会根据id从方法索引表中拿到方法的数据偏移地址
然后拿到方法的详细数据，并根据映射表还原每个虚拟指令的实际指令
然后执行这个方法

如何调试：
在 AndroidStudio 中的 LogCat 中 筛选 tag:ArkVMP 的日志就可以看到虚拟机执行指令的详细信息了

声明：
256条dalvik指令，已经实现250条，最后6条实现起来有点复杂懒得实现了，同时抽代码的时候会检测，如果存在这6条指令的方法不会被抽
其他指令也未做任何测试，只是用我的空壳demo进行了测试，是正常的
另外，抽代码的时候是没有代理AndroidManifest.xml中的AppComponentFactory入口的，对于存在有AppComponentFactory的应用加固后会闪退，会提示找不到类

特别说明：本源码属于半成品，仅仅用作学习交流使用，VMP指令未做任何测试，加固后大概率会有问题，需要自己看日志，看是哪个指令的问题，然后在 VmHandlers.cpp 找到对应的指令实现并修复

