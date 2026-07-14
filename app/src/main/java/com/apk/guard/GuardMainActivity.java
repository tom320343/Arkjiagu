package com.apk.guard;
import static com.apk.guard.GuardSettingsManager.*;
import static com.apk.guard.GuardJiaguUtils.*;
import static com.apk.guard.vm.VmpJiaguEntry.extractMethodsToBin;
import static com.apk.guard.vm.VmpJiaguEntry.rewriteExtractedMethodsToVmCallDex;

import android.app.AlertDialog;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.apk.guard.jar.xml2axml.test.Xml2AxmlTool;
import com.apk.guard.vm.VmpJiaguEntry;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.ComponentActivity;
import androidx.activity.EdgeToEdge;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class GuardMainActivity extends ComponentActivity {
    private Button btnSelectApk;
    private TextView tvLog;
    private ScrollView logScrollView;
    private static final int REQ_SELECT_APK = 1001;

    private boolean isPermissionDialogShowing = false;
    private boolean hasInitMain = false;
    private ImageButton btnSettings;
    private ImageButton btnAbout;


    static {
        System.loadLibrary("GuardTool");
    }

    /*private native byte[] buildEncryptedBlock(byte[] plainData);

    private native byte[] fixDexHeader(byte[] dexData);

    private native boolean isValidDex(byte[] data);

    private native byte[] intToLe4(int value);*/
    private SoNamePreset[] SO_NAME_PRESETS;
    //加密dex的方法
    private native void b(File dexDir, File shellDexFile, String realApplicationName, String  appComponentFactory, byte[] signHash64) throws Exception;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        initWindowInsets();
        checkPermissionOrShowDialog();
        SO_NAME_PRESETS = loadSoNamePresets();
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (hasInitMain) {
            return;
        }

        if (hasAllFilePermission()) {
            initMainPage();
        } else {
            showPermissionDialog();
        }
    }

    private void checkPermissionOrShowDialog() {
        if (hasAllFilePermission()) {
            initMainPage();
            return;
        }

        showPermissionDialog();
    }




    private void showPermissionDialog() {
        if (hasAllFilePermission()) {
            initMainPage();
            return;
        }

        if (isPermissionDialogShowing) {
            return;
        }

        isPermissionDialogShowing = true;

        new android.app.AlertDialog.Builder(this)
                .setTitle(R.string.permission_required_title)
                .setMessage(R.string.permission_required_message)
                .setCancelable(false)
                .setPositiveButton(R.string.grant_permission, (dialog, which) -> {
                    isPermissionDialogShowing = false;
                    dialog.dismiss();
                    openAllFilePermissionPage();
                })
                .show();
    }

    private SoNamePreset[] loadSoNamePresets() {
        java.util.ArrayList<SoNamePreset> list = new java.util.ArrayList<>();

        try {
            java.io.InputStream is = getAssets().open("so_name_presets.json");
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }

            is.close();

            String json = baos.toString("UTF-8");
            org.json.JSONArray array = new org.json.JSONArray(json);

            for (int i = 0; i < array.length(); i++) {
                org.json.JSONObject obj = array.getJSONObject(i);

                String title = obj.optString("title", "").trim();
                String name = obj.optString("name", "").trim();

                if (title.length() == 0 || name.length() == 0) {
                    continue;
                }

                list.add(new SoNamePreset(title, name));
            }

        } catch (Exception e) {
            e.printStackTrace();

            list.add(new SoNamePreset("默认", "ApkGuard"));
        }

        return list.toArray(new SoNamePreset[0]);
    }

    private void initWindowInsets() {
        View main = findViewById(R.id.main);

        int left = main.getPaddingLeft();
        int top = main.getPaddingTop();
        int right = main.getPaddingRight();
        int bottom = main.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(main, (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());

            v.setPadding(
                    left + systemBars.left,
                    top + systemBars.top,
                    right + systemBars.right,
                    bottom + systemBars.bottom
            );

            return insets;
        });
    }


    private void initMainPage() {
        if (hasInitMain) {
            return;
        }

        hasInitMain = true;

        File workDir = getWorkDir();
        cleanWorkDirOnStart(workDir);

        btnSelectApk = findViewById(R.id.btnSelectApk);
        tvLog = findViewById(R.id.tvLog);
        logScrollView = findViewById(R.id.logScrollView);
        btnSettings = findViewById(R.id.btnSettings);
        btnAbout = findViewById(R.id.btnAbout);
        appendLog(getString(R.string.log_init));
        appendLog(getString(R.string.log_wait_apk));

        btnSelectApk.setOnClickListener(v -> openApkSelector());
        btnSettings.setOnClickListener(v -> showSettingsDialog());
        btnAbout.setOnClickListener(v -> showAboutDialog());
    }
    private void showAboutDialog() {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_about, null);

        Button btnAboutClose = dialogView.findViewById(R.id.btnAboutClose);

        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setView(dialogView)
                .setCancelable(true)
                .create();

        btnAboutClose.setOnClickListener(v -> dialog.dismiss());

        dialog.show();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
    }
    private void cleanWorkDirOnStart(File workDir) {
        if (workDir == null || !workDir.exists()) {
            return;
        }

        cleanTempFiles(workDir);
    }


    private void saveSettings(
            String soName,
            String stubClassName,
            String savePath,
            boolean enableVmpExtract,
            boolean Debug,
            boolean autoSign,
            boolean useCustomJks,
            String jksPath,
            String jksStorePass,
            String jksAlias,
            String jksKeyPass,
            String disguiseName,
            boolean hideGuardFeatures
    ) {
        android.content.SharedPreferences sp = getSharedPreferences(SP_SETTINGS, MODE_PRIVATE);

        sp.edit()
                .putString(KEY_SO_NAME, soName)
                .putString(KEY_STUB_CLASS_NAME, stubClassName)
                .putString(KEY_SAVE_PATH, savePath)
                .putBoolean(KEY_ENABLE_VMP_EXTRACT, enableVmpExtract)
                .putBoolean(KEY_DEBUG, Debug)
                .putBoolean(KEY_AUTO_SIGN, autoSign)
                .putBoolean(KEY_USE_CUSTOM_JKS, useCustomJks)
                .putString(KEY_JKS_PATH, jksPath)
                .putString(KEY_JKS_STORE_PASS, jksStorePass)
                .putString(KEY_JKS_ALIAS, jksAlias)
                .putString(KEY_JKS_KEY_PASS, jksKeyPass)
                .putString(KEY_DISGUISE_NAME, disguiseName)
                .putBoolean(KEY_HIDE_GUARD_FEATURES, hideGuardFeatures)
                .apply();
    }



    private boolean isValidJksSettings(String jksPath, String storePass, String alias, String keyPass) {
        if (jksPath == null || jksPath.trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.jks_path_empty), Toast.LENGTH_LONG).show();
            return false;
        }

        File jksFile = new File(jksPath.trim());
        if (!jksFile.exists() || !jksFile.isFile()) {
            Toast.makeText(this, getString(R.string.jks_file_not_found), Toast.LENGTH_LONG).show();
            return false;
        }

        if (storePass == null || storePass.trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.jks_store_pass_empty), Toast.LENGTH_LONG).show();
            return false;
        }

        if (alias == null || alias.trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.jks_alias_empty), Toast.LENGTH_LONG).show();
            return false;
        }

        if (keyPass == null || keyPass.trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.jks_alias_pass_empty), Toast.LENGTH_LONG).show();
            return false;
        }

        return true;
    }






    private void showSettingsDialog() {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_settings, null);

        android.widget.EditText etSoName = dialogView.findViewById(R.id.etSoName);
        android.widget.EditText etSavePath = dialogView.findViewById(R.id.etSavePath);
        android.widget.Switch swAutoSign = dialogView.findViewById(R.id.swAutoSign);
        android.widget.Switch swEnableVmpExtract = dialogView.findViewById(R.id.swEnableVmpExtract);
        android.widget.Switch swDebug = dialogView.findViewById(R.id.swDebug);

        android.widget.Switch swUseCustomJks = dialogView.findViewById(R.id.swUseCustomJks);
        android.widget.LinearLayout llCustomJksForm = dialogView.findViewById(R.id.llCustomJksForm);
        android.widget.EditText etJksPath = dialogView.findViewById(R.id.etJksPath);
        android.widget.EditText etJksStorePass = dialogView.findViewById(R.id.etJksStorePass);
        android.widget.EditText etJksAlias = dialogView.findViewById(R.id.etJksAlias);
        android.widget.EditText etJksKeyPass = dialogView.findViewById(R.id.etJksKeyPass);
        android.widget.ImageButton btnSoNamePreset = dialogView.findViewById(R.id.btnSoNamePreset);
        Button btnSaveSettings = dialogView.findViewById(R.id.btnSaveSettings);
        android.widget.EditText etStubClassName = dialogView.findViewById(R.id.etStubClassName);
        android.widget.ImageButton btnClearStubClassName = dialogView.findViewById(R.id.btnClearStubClassName);
        android.widget.ImageButton btnClearSavePath = dialogView.findViewById(R.id.btnClearSavePath);
        android.widget.EditText etDisguiseName = dialogView.findViewById(R.id.etDisguiseName);
        android.widget.Switch swHideGuardFeatures = dialogView.findViewById(R.id.swHideGuardFeatures);


        ArkSettings settings = readSettings(this);
        etStubClassName.setText(settings.stubClassName);
        etSoName.setText(settings.soName);
        etSavePath.setText(settings.savePath);
        swAutoSign.setChecked(settings.autoSign);
        swEnableVmpExtract.setChecked(settings.enableVmpExtract);
        swDebug.setChecked(settings.Debug);

        swUseCustomJks.setChecked(settings.useCustomJks);
        etJksPath.setText(settings.jksPath);
        etJksStorePass.setText(settings.jksStorePass);
        etJksAlias.setText(settings.jksAlias);
        etJksKeyPass.setText(settings.jksKeyPass);

        etDisguiseName.setText(settings.disguiseName);
        swHideGuardFeatures.setChecked(settings.hideGuardFeatures);

        llCustomJksForm.setVisibility(settings.useCustomJks ? View.VISIBLE : View.GONE);

        swUseCustomJks.setOnCheckedChangeListener((buttonView, isChecked) -> {
            llCustomJksForm.setVisibility(isChecked ? View.VISIBLE : View.GONE);
        });

        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setView(dialogView)
                .setCancelable(true)
                .create();
        btnSoNamePreset.setOnClickListener(v -> showSoNamePresetDialog(etSoName));
        btnClearStubClassName.setOnClickListener(v -> {
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.confirm_clear_title)
                    .setMessage(R.string.confirm_clear_stub_class)
                    .setPositiveButton(R.string.confirm, (d, w) -> etStubClassName.setText(""))
                    .setNegativeButton(R.string.cancel, null)
                    .show();
        });

        btnClearSavePath.setOnClickListener(v -> {
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.confirm_clear_title)
                    .setMessage(R.string.confirm_clear_save_path)
                    .setPositiveButton(R.string.confirm, (d, w) -> etSavePath.setText(""))
                    .setNegativeButton(R.string.cancel, null)
                    .show();
        });
        btnSaveSettings.setOnClickListener(v -> {
            String soName = etSoName.getText().toString().trim();
            String stubClassName = etStubClassName.getText().toString().trim();
            String savePath = etSavePath.getText().toString().trim();
            boolean enableVmpExtract = swEnableVmpExtract.isChecked();
            boolean Debug = swDebug.isChecked();
            boolean autoSign = swAutoSign.isChecked();


            boolean useCustomJks = swUseCustomJks.isChecked();
            String jksPath = etJksPath.getText().toString().trim();
            String jksStorePass = etJksStorePass.getText().toString();
            String jksAlias = etJksAlias.getText().toString().trim();
            String jksKeyPass = etJksKeyPass.getText().toString();
            String disguiseName = etDisguiseName.getText().toString().trim();
            boolean hideGuardFeatures = swHideGuardFeatures.isChecked();

            if (!isValidSoName(soName)) {
                Toast.makeText(
                        this,
                        getString(R.string.invalid_so_name),
                        Toast.LENGTH_LONG
                ).show();
                return;
            }
            if (!isValidStubClassName(stubClassName)) {
                new android.app.AlertDialog.Builder(this)
                        .setTitle(R.string.invalid_stub_class_title)
                        .setMessage(R.string.invalid_stub_class_message)
                        .setPositiveButton(R.string.confirm, null)
                        .show();
                return;
            }
            if (!isValidSavePath(savePath)) {
                Toast.makeText(this, getString(R.string.invalid_save_path), Toast.LENGTH_LONG).show();
                return;
            }

            if (isPathInCacheDir(this, savePath)) {
                Toast.makeText(this, getString(R.string.cache_save_path_not_allowed), Toast.LENGTH_LONG).show();
                return;
            }

            if (useCustomJks && !isValidJksSettings(jksPath, jksStorePass, jksAlias, jksKeyPass)) {
                return;
            }

            saveSettings(
                    soName,
                    stubClassName,
                    savePath,
                    enableVmpExtract,
                    Debug,
                    autoSign,
                    useCustomJks,
                    jksPath,
                    jksStorePass,
                    jksAlias,
                    jksKeyPass,
                    disguiseName,
                    hideGuardFeatures
            );

            Toast.makeText(this, getString(R.string.settings_saved), Toast.LENGTH_SHORT).show();
            dialog.dismiss();
        });

        dialog.show();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
    }
    private static class SoNamePreset {
        String feature;
        String soName;

        SoNamePreset(String feature, String soName) {
            this.feature = feature;
            this.soName = soName;
        }
    }


    private void showSoNamePresetDialog(android.widget.EditText etSoName) {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_so_name_preset, null);

        android.widget.RadioGroup rgSoNamePreset = dialogView.findViewById(R.id.rgSoNamePreset);
        Button btnConfirmSoNamePreset = dialogView.findViewById(R.id.btnConfirmSoNamePreset);

        for (int i = 0; i < SO_NAME_PRESETS.length; i++) {
            SoNamePreset item = SO_NAME_PRESETS[i];

            android.widget.RadioButton radioButton = new android.widget.RadioButton(this);
            radioButton.setId(10000 + i);
            radioButton.setText(
                    getString(
                            R.string.so_feature_item,
                            item.feature,
                            item.soName
                    )
            );
            radioButton.setTextColor(android.graphics.Color.parseColor("#374151"));
            radioButton.setTextSize(14);
            radioButton.setPadding(8, 10, 8, 10);
            radioButton.setSingleLine(false);

            rgSoNamePreset.addView(radioButton);
        }

        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setView(dialogView)
                .setCancelable(true)
                .create();

        btnConfirmSoNamePreset.setOnClickListener(v -> {
            int checkedId = rgSoNamePreset.getCheckedRadioButtonId();

            if (checkedId == -1) {
                Toast.makeText(this, getString(R.string.select_preset_so_name), Toast.LENGTH_SHORT).show();
                return;
            }

            int index = checkedId - 10000;

            if (index < 0 || index >= SO_NAME_PRESETS.length) {
                Toast.makeText(this, getString(R.string.invalid_selection), Toast.LENGTH_SHORT).show();
                return;
            }

            etSoName.setText(SO_NAME_PRESETS[index].soName);
            etSoName.setSelection(etSoName.getText().length());

            dialog.dismiss();
        });

        dialog.show();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
    }





    private boolean hasAllFilePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED
                    && checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED;
        }

        return true;
    }
    private void openAllFilePermissionPage() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivity(intent);
            }
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            requestPermissions(
                    new String[]{
                            android.Manifest.permission.READ_EXTERNAL_STORAGE,
                            android.Manifest.permission.WRITE_EXTERNAL_STORAGE
                    },
                    REQ_STORAGE_PERMISSION
            );
        }
    }
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == REQ_STORAGE_PERMISSION) {
            if (hasAllFilePermission()) {
                initMainPage();
            } else {
                Toast.makeText(this, R.string.file_access_permission_denied, Toast.LENGTH_LONG).show();
                showPermissionDialog();
            }
        }
    }
    private void appendLog(String text) {
        if (tvLog == null) {
            return;
        }

        tvLog.append(text + "\n");

        if (logScrollView != null) {
            logScrollView.post(() -> logScrollView.fullScroll(View.FOCUS_DOWN));
        }
    }

    private void deleteLog(){
        if (tvLog == null) {
            return;
        }
        tvLog.setText("");
    }





    private void openApkSelector() {
        ArkSettings settings = readSettings(this);

        if (settings != null && isPathInCacheDir(this, settings.savePath)) {
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.invalid_save_path_title)
                    .setMessage(R.string.invalid_save_path_message)
                    .setCancelable(false)
                    .setPositiveButton(R.string.modify, (dialog, which) -> {
                        dialog.dismiss();
                        showSettingsDialog();
                    })
                    .setNegativeButton(R.string.cancel, null)
                    .show();
            return;
        }

        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/vnd.android.package-archive");
        startActivityForResult(intent, REQ_SELECT_APK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQ_SELECT_APK && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri == null) {
                appendLog("选择文件失败：Uri为空");
                return;
            }

            handleSelectedApk(uri);
        }
    }

    private void handleSelectedApk(Uri uri) {
        btnSelectApk.setEnabled(false);
        deleteLog();//清空日志
        new Thread(() -> {
            File workDir = getWorkDir();
            cleanTempFiles(workDir);
            ArkSettings settings = readSettings(this);
            try {
                appendLogOnUi("开始处理 APK");

                if (!workDir.exists() && !workDir.mkdirs()) {
                    throw new RuntimeException("创建临时目录失败：" + workDir.getAbsolutePath());
                }

                appendLogOnUi("临时目录：" + workDir.getAbsolutePath());

                String originalApkName = getFileNameFromUri(this, uri);
                if (originalApkName == null || originalApkName.trim().isEmpty()) {
                    originalApkName = "未知APK.apk";
                }

                File copiedApk = new File(workDir, "待加固.apk");
                copyUriToFile(this, uri, copiedApk);

                String appName = readApplicationName(this, copiedApk);
                String appComponentFactory = readAppComponentFactoryName(this, copiedApk);
                appendLogOnUi("原始入口：" + appName);
                if (appComponentFactory != null) {
                    appendLogOnUi("Factory：" + appComponentFactory);
                } else {
                    appendLogOnUi("Factory：无");
                }

                appendLogOnUi("开始解压原始 dex");
                VmpJiaguEntry.extractManifestAndDex(copiedApk, workDir);
                appendLogOnUi("原始 dex 解压完成");

                if (settings.Debug) {
                    File rawDexDebugDir = new File(workDir, DEBUG_RAW_DEX_DIR);
                    copyDexFilesToDir(workDir, rawDexDebugDir);
                    appendLogOnUi("调试模式：已备份原始 dex 到：" + rawDexDebugDir.getAbsolutePath());
                }




                appendLogOnUi("开始执行 VMP 抽取");

                List<String> activityOnCreateList = readActivityOnCreateMethods(this, copiedApk, this::appendLogOnUi);

                if (activityOnCreateList.isEmpty()) {
                    appendLogOnUi("未读取到 Activity，使用默认 onCreate 抽取规则");
                    activityOnCreateList.add("*.*.onCreate");
                } else {
                    appendLogOnUi("读取到 Activity 数量：" + activityOnCreateList.size());
                    /*for (String methodName : activityOnCreateList) {
                        appendLogOnUi("Activity onCreate：" + methodName);
                    }*/
                }


                boolean enableVmpExtract = settings != null && settings.enableVmpExtract;
                if (!enableVmpExtract) {
                    activityOnCreateList.clear();//清空规则，以此不抽
                    activityOnCreateList.add("3.2.1");//设置一个不可能存在的抽取规则
                }

                extractMethodsToBin(
                        workDir,
                        this::appendLogOnUi,
                        activityOnCreateList.toArray(new String[0])
                );

                appendLogOnUi("VMP 抽取完成");

                appendLogOnUi("开始重写 VMP dex");

                String stubClassName = getValidStubClassNameFromSettings(this);

                rewriteExtractedMethodsToVmCallDex(
                        workDir,
                        this::appendLogOnUi,
                        getValidSoNameFromSettings(this, this::appendLogOnUi),
                        stubClassName
                );

                appendLogOnUi("VMP dex 重写完成");

                if (settings.Debug) {
                    File vmpDexDebugDir = new File(workDir, DEBUG_VMP_DEX_DIR);
                    copyDexFilesToDir(workDir, vmpDexDebugDir);
                    appendLogOnUi("调试模式：已备份 VMP dex 到：" + vmpDexDebugDir.getAbsolutePath());
                }

                File shellDexDir = new File(workDir, "shell");
                if (!shellDexDir.exists() && !shellDexDir.mkdirs()) {
                    throw new RuntimeException("创建壳dex目录失败：" + shellDexDir.getAbsolutePath());
                }

                File shellDex = generateShellDex(this, shellDexDir, this::appendLogOnUi);

                byte[] signHash64 = getSignHash64ForShell();

                b(workDir, shellDex, appName, appComponentFactory, signHash64);//在native层加密方法，这里名称改成b防止根据名称知道意思

                File finalShellDex = new File(workDir, "classes.dex");

                try (FileInputStream in = new FileInputStream(shellDex);
                     FileOutputStream out = new FileOutputStream(finalShellDex, false)) {

                    byte[] buffer = new byte[8192];
                    int len;

                    while ((len = in.read(buffer)) != -1) {
                        out.write(buffer, 0, len);
                    }

                    out.flush();
                }

                appendLogOnUi("加密完成：" + finalShellDex.getAbsolutePath());

                extractStubSoByTargetAbi(copiedApk, workDir);

                patchStubSoWithVmpBin(workDir);//将vmp.bin写so文件中

                File newManifest = modifyAndroidManifest(copiedApk, workDir);

                File protectedApk = rebuildProtectedApk(copiedApk, workDir, originalApkName);//开始打包APK

                appendLogOnUi("开始进行 ZIPALIGN");
                protectedApk = zipAlignApk(protectedApk);
                appendLogOnUi("ZIPALIGN 完成");


                boolean autoSign = settings != null && settings.autoSign;

                if (autoSign) {
                    appendLogOnUi("检测到已开启自动签名");

                    if (settings.useCustomJks) {
                        protectedApk = ApkSignUtil.signApk(
                                this,
                                protectedApk,
                                new File(settings.jksPath),
                                settings.jksStorePass,
                                settings.jksAlias,
                                settings.jksKeyPass
                        );
                    } else {
                        protectedApk = ApkSignUtil.signApk(this, protectedApk);
                    }

                    appendLogOnUi("APK 签名完成");
                } else {
                    appendLogOnUi("未开启自动签名，跳过签名");
                }

                appendLogOnUi(getString(
                        R.string.protected_apk_output,
                        protectedApk.getAbsolutePath()
                ));
                appendLogOnUi(getString(R.string.protection_completed));

                //只有开启了自动签名的APK，才会弹出提示让安装
                if (autoSign) {
                    File finalProtectedApk = protectedApk;
                    runOnUiThread(() -> {
                        AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                                .setTitle(R.string.protection_complete_title)
                                .setMessage(R.string.install_prompt_message)
                                .setPositiveButton(R.string.install, null)
                                .setNegativeButton(R.string.cancel, (d, w) -> d.dismiss())
                                .setCancelable(false)
                                .create();

                        dialog.show();

                        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
                                .setOnClickListener(v -> installApk(finalProtectedApk));
                    });
                }else{
                    runOnUiThread(() -> {
                        AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                                .setTitle(R.string.protection_complete_title)
                                .setMessage(R.string.manual_sign_message)
                                .setNegativeButton(R.string.ok, (d, w) -> d.dismiss())
                                .setCancelable(false)
                                .create();

                        dialog.show();
                    });
                }

            } catch (Exception e) {
                appendLogOnUi("处理失败：" + e.getMessage());
            } finally {
                if (!settings.Debug) {
                    //appendLogOnUi("非调试模式，开始清理临时目录");
                    cleanTempFiles(workDir);
                    //appendLogOnUi("临时目录清理完成");
                } else {
                    //appendLogOnUi("调试模式，保留临时目录：" + workDir.getAbsolutePath());
                }

                runOnUiThread(() -> btnSelectApk.setEnabled(true));
            }
        }).start();
    }


    private void patchStubSoWithVmpBin(File workDir) throws Exception {
        File vmpBin = new File(workDir, "vmp.bin");
        File libDir = new File(workDir, "lib");
        String soFileName = getValidSoFileNameFromSettings(this, this::appendLogOnUi);

        appendLogOnUi("开始处理字节码文件");//将字节码文件写入到so中
        appendLogOnUi("vmp.bin路径：" + vmpBin.getAbsolutePath());
        appendLogOnUi("so文件名：" + soFileName);

        if (!vmpBin.exists() || !vmpBin.isFile() || vmpBin.length() <= 0) {
            throw new RuntimeException("vmp.bin不存在或为空：" + vmpBin.getAbsolutePath());
        }

        if (!libDir.exists() || !libDir.isDirectory()) {
            throw new RuntimeException("lib目录不存在：" + libDir.getAbsolutePath());
        }

        File[] abiDirs = libDir.listFiles();
        if (abiDirs == null || abiDirs.length == 0) {
            throw new RuntimeException("lib目录下没有ABI目录");
        }

        int successCount = 0;

        for (File abiDir : abiDirs) {
            if (abiDir == null || !abiDir.isDirectory()) {
                continue;
            }

            String abi = abiDir.getName();
            File soFile = new File(abiDir, soFileName);

            appendLogOnUi("检查ABI：" + abi);

            if (!soFile.exists() || !soFile.isFile()) {
                appendLogOnUi("未找到so，跳过：" + soFile.getAbsolutePath());
                continue;
            }

            File tmpFile = new File(abiDir, soFileName + ".section.tmp");

            try {
                appendLogOnUi("开始处理so：" + soFile.getAbsolutePath());
                //appendLogOnUi("原始so大小：" + soFile.length());

                writeVmpBinToElfSection(soFile, vmpBin, tmpFile);

                if (!tmpFile.exists() || tmpFile.length() <= 0) {
                    throw new RuntimeException("临时so生成失败");
                }

                if (!soFile.delete()) {
                    throw new RuntimeException("删除旧so失败：" + soFile.getAbsolutePath());
                }

                if (!tmpFile.renameTo(soFile)) {
                    throw new RuntimeException("替换新so失败：" + soFile.getAbsolutePath());
                }

                appendLogOnUi("so写入完成：" + abi);
                //appendLogOnUi("新so大小：" + soFile.length());

                successCount++;

            } catch (Exception e) {
                appendLogOnUi("so写入失败：" + abi + "，原因：" + e.getMessage());

                if (tmpFile.exists()) {
                    tmpFile.delete();
                }

                if (soFile.exists()) {
                    boolean deleted = soFile.delete();
                    appendLogOnUi("已删除未写入成功的so：" + soFile.getAbsolutePath() + "，结果：" + deleted);
                }
            }
        }

        if (successCount <= 0) {
            throw new RuntimeException("没有任何so成功写入");
        }

        appendLogOnUi("so写入全部完成，成功数量：" + successCount);
    }

    private byte[] getSignHash64ForShell() {
        //由于已移除签名校验的c代码，因此这里不能再返回证书信息，否则so层无法解密
        return null;

        /*try {
            ArkSettings settings = readSettings(this);

            if (settings == null || !settings.autoSign) {
                appendLogOnUi("未开启自动签名，签名证书绑定值为空");
                return null;
            }

            String sha256;

            if (settings.useCustomJks) {
                appendLogOnUi("使用自定义证书获取指纹");

                if (!isValidJksSettings(
                        settings.jksPath,
                        settings.jksStorePass,
                        settings.jksAlias,
                        settings.jksKeyPass
                )) {
                    return null;
                }

                sha256 = JksSha256Util.getJksSha256FromFile(
                        new File(settings.jksPath),
                        settings.jksStorePass,
                        settings.jksAlias,
                        settings.jksKeyPass,
                        getCacheDir()
                );
            } else {
                appendLogOnUi("使用内置 guard.jks 获取 指纹");

                sha256 = JksSha256Util.getJksSha256(this);
            }

            if (sha256 == null) {
                appendLogOnUi("证书指纹获取失败：结果为空");
                return null;
            }

            sha256 = sha256.trim();
            sha256 = sha256.toLowerCase(java.util.Locale.ROOT);

            if (sha256.length() != 64) {
                appendLogOnUi("证书指纹长度异常：" + sha256.length());
                return null;
            }

            appendLogOnUi("证书指纹获取成功");
            appendLogOnUi("证书指纹：" + sha256);

            return sha256.getBytes("UTF-8");

        } catch (Exception e) {
            appendLogOnUi("证书指纹获取失败：" + e.getMessage());
            return null;
        }*/
    }

    private void installApk(File apkFile) {
        if (apkFile == null || !apkFile.exists()) {
            Toast.makeText(this, "APK文件不存在", Toast.LENGTH_SHORT).show();
            return;
        }

        // Android 8.0+ 需要检查“安装未知应用”权限
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            if (!getPackageManager().canRequestPackageInstalls()) {
                new android.app.AlertDialog.Builder(this)
                        .setTitle("需要安装权限")
                        .setMessage("请先允许本应用安装未知来源应用")
                        .setPositiveButton("去授权", (dialog, which) -> {
                            dialog.dismiss();

                            Intent intent = new Intent(
                                    android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES
                            );
                            intent.setData(android.net.Uri.parse("package:" + getPackageName()));
                            startActivity(intent);
                        })
                        .setNegativeButton("取消", null)
                        .show();
                return;
            }
        }

        doInstallApk(apkFile);
    }

    private void doInstallApk(File apkFile) {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        android.net.Uri apkUri;

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            apkUri = androidx.core.content.FileProvider.getUriForFile(
                    this,
                    getPackageName() + ".fileprovider",
                    apkFile
            );
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } else {
            apkUri = android.net.Uri.fromFile(apkFile);
        }

        intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
        startActivity(intent);
    }



    private void appendLogOnUi(String text) {
        System.out.println("[log] " + text);
        runOnUiThread(() -> appendLog(text));
    }





    private File rebuildProtectedApk(File apkFile, File workDir, String originalApkName) throws Exception {
        appendLogOnUi("开始重打包 APK");

        File newClassesDex = new File(workDir, "classes.dex");
        File newManifest = new File(workDir, "AndroidManifest.xml");
        File libDir = new File(workDir, "lib");
        File vmpBin = new File(workDir, "vmp.bin");

        if (!newClassesDex.exists()) {
            throw new RuntimeException("未找到新的 classes.dex");
        }

        if (!newManifest.exists()) {
            throw new RuntimeException("未找到修改后的 AndroidManifest.xml");
        }

        Set<String> skipNames = new HashSet<>();

        ZipFile checkZip = new ZipFile(apkFile);
        try {
            for (int i = 1; ; i++) {
                String dexName = i == 1 ? "classes.dex" : "classes" + i + ".dex";
                ZipEntry entry = checkZip.getEntry(dexName);

                if (entry == null) {
                    break;
                }

                skipNames.add(dexName);
            }
        } finally {
            checkZip.close();
        }

        skipNames.add("AndroidManifest.xml");

        if (libDir.exists() && libDir.isDirectory()) {
            collectLibSkipNames(libDir, libDir, skipNames);
        }

        File outApk = new File(
                getFinalOutputDir(this, workDir, this::appendLogOnUi),
                buildProtectedApkName(originalApkName)
        );

        ZipFile zipFile = new ZipFile(apkFile);
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outApk));

        try {
            zos.setLevel(9);

            Enumeration<? extends ZipEntry> entries = zipFile.entries();

            while (entries.hasMoreElements()) {
                ZipEntry oldEntry = entries.nextElement();
                String name = oldEntry.getName();
                if (skipNames.contains(name)) {
                    continue;
                }
                if (oldEntry.isDirectory()) {
                    addDirectoryZipEntry(zos, name, oldEntry);
                    continue;
                }
                InputStream in = zipFile.getInputStream(oldEntry);
                addZipEntryStream(this, zos, name, in, oldEntry);
            }

            addZipEntryStream(this, zos, "classes.dex", new FileInputStream(newClassesDex), null);
            appendLogOnUi("已写入新 classes.dex");

            addZipEntryStream(this, zos, "AndroidManifest.xml", new FileInputStream(newManifest), null);
            appendLogOnUi("已写入新 AndroidManifest.xml");

            /*if (!vmpBin.exists()) {
                throw new RuntimeException("未找到 vmp.bin：" + vmpBin.getAbsolutePath());
            }
            addZipEntryStream(this, zos, "assets/vmp.bin", new FileInputStream(vmpBin), null);
            appendLogOnUi("已写入 assets/vmp.bin");*/

            if (libDir.exists() && libDir.isDirectory()) {
                addLibDirToZipStream(this, zos, libDir, libDir);
            }

            zos.finish();
        } finally {
            try {
                zos.close();
            } catch (Exception ignored) {
            }

            try {
                zipFile.close();
            } catch (Exception ignored) {
            }
        }

        appendLogOnUi("重打包完成：" + outApk.getAbsolutePath());
        return outApk;
    }







    private void extractStubSoByTargetAbi(File apkFile, File workDir) throws Exception {
        appendLogOnUi("开始读取目标 APK ABI");

        //ArrayList<String> assetAbiList = getAssetAbiList();
        ArrayList<String> selfAbiList = getSelfApkStubAbiList();
        if (selfAbiList.isEmpty()) {
            throw new RuntimeException("/lib 下没有可用 ABI");
        }

        //appendLogOnUi("壳内可用 ABI：" + assetAbiList.toString());

        ArrayList<String> targetAbiList = readApkAbiList(apkFile);
        ArrayList<String> finalAbiList = new ArrayList<>();

        if (targetAbiList.isEmpty()) {
            appendLogOnUi("目标 APK 没有 lib 目录，使用 /lib 下全部 ABI");

            for (String abi : selfAbiList) {
                if ("armeabi".equals(abi)) {
                    appendLogOnUi("跳过 armeabi");
                    continue;
                }
                finalAbiList.add(abi);
            }
        } else {
            appendLogOnUi("目标 APK ABI：" + targetAbiList.toString());
            for (String abi : targetAbiList) {
                if ("armeabi".equals(abi)) {
                    appendLogOnUi("跳过目标 armeabi");
                    continue;
                }
                if (!selfAbiList.contains(abi)) {
                    appendLogOnUi("不支持该 ABI，跳过：" + abi);
                    continue;
                }
                finalAbiList.add(abi);
            }
        }
        if (finalAbiList.isEmpty()) {
            throw new RuntimeException("没有匹配到可解压的 ABI");
        }
        for (String abi : finalAbiList) {
            String soFileName = getValidSoFileNameFromSettings(this, this::appendLogOnUi);
            File outFile = new File(workDir, "lib/" + abi + "/" + soFileName);
            File parent = outFile.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new RuntimeException("创建 so 输出目录失败：" + parent.getAbsolutePath());
            }
            copySelfApkStubSoToFile(abi, outFile);
        }
    }


    private ArrayList<String> getSelfApkStubAbiList() throws Exception {
        ArrayList<String> abiList = new ArrayList<>();

        String selfApkPath = getApplicationInfo().sourceDir;

        ZipFile zipFile = new ZipFile(selfApkPath);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();

        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();

            if (!name.startsWith("lib/")) {
                continue;
            }

            String[] parts = name.split("/");
            if (parts.length != 3) {
                continue;
            }

            String abi = parts[1];
            String fileName = parts[2];

            if ("armeabi".equals(abi)) {
                continue;
            }

            if (!"libApkGuard.so".equals(fileName)) {
                continue;
            }

            if (!abiList.contains(abi)) {
                abiList.add(abi);
            }
        }

        zipFile.close();
        return abiList;
    }
    private void copySelfApkStubSoToFile(String abi, File outFile) throws Exception {
        String selfApkPath = getApplicationInfo().sourceDir;
        String zipPath = "lib/" + abi + "/libApkGuard.so";

        ZipFile zipFile = new ZipFile(selfApkPath);
        ZipEntry entry = zipFile.getEntry(zipPath);

        if (entry == null) {
            zipFile.close();
            throw new RuntimeException("自身 APK 中未找到：" + zipPath);
        }

        InputStream in = zipFile.getInputStream(entry);

        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            in.close();
            zipFile.close();
            throw new RuntimeException("创建 so 输出目录失败：" + parent.getAbsolutePath());
        }

        FileOutputStream out = new FileOutputStream(outFile);

        byte[] buffer = new byte[8192];
        int len;
        while ((len = in.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }

        out.flush();
        out.close();
        in.close();
        zipFile.close();
    }

    private File modifyAndroidManifest(File apkFile, File workDir) throws Exception {
        appendLogOnUi("开始处理 AndroidManifest.xml");

        File manifestAxml = new File(workDir, "AndroidManifest_origin.xml");
        File manifestXml = new File(workDir, "AndroidManifest_decode.xml");
        File manifestNewXml = new File(workDir, "AndroidManifest_modify.xml");
        File manifestNewAxml = new File(workDir, "AndroidManifest.xml");

        try {
            ZipFile zipFile = new ZipFile(apkFile);
            ZipEntry entry = zipFile.getEntry("AndroidManifest.xml");

            if (entry == null) {
                zipFile.close();
                throw new RuntimeException("APK 中未找到 AndroidManifest.xml");
            }

            InputStream in = zipFile.getInputStream(entry);
            FileOutputStream out = new FileOutputStream(manifestAxml);

            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }

            out.flush();
            out.close();
            in.close();
            zipFile.close();

            appendLogOnUi("已提取 AndroidManifest.xml");

            Xml2AxmlTool.decode(
                    manifestAxml.getAbsolutePath(),
                    manifestXml.getAbsolutePath()
            );

            //appendLogOnUi("Manifest 反编译完成");

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(manifestXml);

            Element manifest = document.getDocumentElement();
            if (manifest == null || !"manifest".equals(manifest.getNodeName())) {
                throw new RuntimeException("Manifest XML 结构异常");
            }

            Element application = null;
            for (int i = 0; i < manifest.getChildNodes().getLength(); i++) {
                if (manifest.getChildNodes().item(i) instanceof Element) {
                    Element item = (Element) manifest.getChildNodes().item(i);
                    if ("application".equals(item.getNodeName())) {
                        application = item;
                        break;
                    }
                }
            }
            if (application == null) {
                throw new RuntimeException("Manifest 中未找到 application 标签");
            }
            rewriteApplicationAttributes(this, application);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "utf-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.transform(
                    new DOMSource(document),
                    new StreamResult(manifestNewXml)
            );
            Xml2AxmlTool.encode2(
                    this,
                    manifestNewXml.getAbsolutePath(),
                    manifestNewAxml.getAbsolutePath()
            );
            return manifestNewAxml;
        } finally {
            deleteFileQuietly(manifestAxml);
            deleteFileQuietly(manifestXml);
            deleteFileQuietly(manifestNewXml);
        }
    }

}