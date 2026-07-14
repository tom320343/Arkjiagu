package com.apk.guard;

public class GuardSettingsManager {
    public static final String SP_SETTINGS = "guard_settings";
    public static final String KEY_SO_NAME = "so_name";
    public static final String KEY_SAVE_PATH = "save_path";
    public static final String KEY_ENABLE_VMP_EXTRACT = "enable_vmp_extract";
    public static final String KEY_DEBUG = "debug";
    public static final String KEY_AUTO_SIGN = "auto_sign";
    public static final String DEFAULT_SO_NAME = "ApkGuard";
    public static final String KEY_USE_CUSTOM_JKS = "use_custom_jks";
    public static final String KEY_JKS_PATH = "jks_path";
    public static final String KEY_JKS_STORE_PASS = "jks_store_pass";
    public static final String KEY_JKS_ALIAS = "jks_alias";
    public static final String KEY_JKS_KEY_PASS = "jks_key_pass";
    public static final String KEY_STUB_CLASS_NAME = "stub_class_name";
    public static final String DEFAULT_STUB_CLASS_NAME = "com.apk.guard.safe.StubApp";
    public static final String KEY_DISGUISE_NAME = "disguise_name";
    public static final String DEFAULT_DISGUISE_NAME = "安卓加固";
    public static final String KEY_HIDE_GUARD_FEATURES = "hide_ark_features";
    public static final boolean DEFAULT_HIDE_GUARD_FEATURES = false;
    public static final String TEMP_DIR_NAME = "ArkJiagu";//临时工作目录名称，不要乱改，这个目录是会被清空的
    public static final int REQ_STORAGE_PERMISSION = 10086;
    public static final String DEBUG_RAW_DEX_DIR = "Appdex";
    public static final String DEBUG_VMP_DEX_DIR = "VMPdex";
    public static final String ARK_VMP_SECTION_NAME = ".gvmp";
}
