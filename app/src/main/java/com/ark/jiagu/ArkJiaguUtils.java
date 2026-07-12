package com.ark.jiagu;

import static android.content.Context.MODE_PRIVATE;
import static com.ark.jiagu.ArkSettingsManager.*;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Environment;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class ArkJiaguUtils {
    public interface LogCallback {
        void log(String msg);
    }
    private static void log(LogCallback callback, String text) {
        if (callback != null) {
            callback.log(text);
        }
    }
    public static boolean isValidSoName(String soName) {
        if (soName == null) {
            return false;
        }

        soName = soName.trim();

        if (soName.isEmpty()) {
            return false;
        }

        if (soName.startsWith("lib")) {
            return false;
        }

        if (soName.endsWith(".so")) {
            return false;
        }

        return soName.matches("[A-Za-z0-9_]+");
    }
    public static boolean isValidSavePath(String savePath) {
        if (savePath == null || savePath.trim().isEmpty()) {
            return false;
        }

        File dir = new File(savePath.trim());

        if (dir.exists()) {
            return dir.isDirectory() && dir.canWrite();
        }

        return dir.mkdirs() && dir.isDirectory() && dir.canWrite();
    }
    public static boolean isPathInCacheDir(Context context, String path) {
        if (path == null || path.trim().isEmpty()) {
            return false;
        }

        try {
            File targetDir = new File(path.trim()).getCanonicalFile();
            File workDir = getWorkDir().getCanonicalFile();

            String targetPath = targetDir.getAbsolutePath()
                    .toLowerCase(java.util.Locale.ROOT);
            String workPath = workDir.getAbsolutePath()
                    .toLowerCase(java.util.Locale.ROOT);

            return targetPath.equals(workPath)
                    || targetPath.startsWith(workPath + File.separator);

        } catch (Exception ignored) {
            return false;
        }
    }
    public static boolean isValidStubClassName(String className) {
        if (className == null) {
            return false;
        }

        className = className.trim();

        if (className.isEmpty()) {
            return false;
        }

        if (className.startsWith(".")) {
            return false;
        }

        if (className.endsWith(".")) {
            return false;
        }

        if (className.contains("..")) {
            return false;
        }

        String[] parts = className.split("\\.");

        if (parts.length < 2) {
            return false;
        }

        for (String part : parts) {

            if (part == null || part.isEmpty()) {
                return false;
            }

            char first = part.charAt(0);

            // 首字符不能数字
            if (Character.isDigit(first)) {
                return false;
            }

            // 首字符必须是合法Java标识符开始
            if (!Character.isJavaIdentifierStart(first)) {
                return false;
            }

            for (int i = 1; i < part.length(); i++) {
                if (!Character.isJavaIdentifierPart(part.charAt(i))) {
                    return false;
                }
            }
        }

        return true;
    }
    public static void copyFile(File sourceFile, File targetFile) throws IOException {
        if (sourceFile == null || !sourceFile.isFile()) {
            throw new IOException("源文件不存在：" + sourceFile);
        }

        File parent = targetFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("创建目录失败：" + parent.getAbsolutePath());
        }

        try (FileInputStream in = new FileInputStream(sourceFile);
             FileOutputStream out = new FileOutputStream(targetFile, false)) {

            byte[] buffer = new byte[8192];
            int len;

            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }

            out.flush();
        }
    }
    public static String getPackageNameFromClassName(String className) {
        if (className == null) {
            return "";
        }

        className = className.trim();

        int lastDot = className.lastIndexOf(".");
        if (lastDot <= 0) {
            return "";
        }

        return className.substring(0, lastDot);
    }

    public static void copyDexFilesToDir(File sourceDir, File targetDir) throws IOException {
        if (sourceDir == null || !sourceDir.isDirectory()) {
            throw new IOException("源dex目录不存在");
        }

        if (targetDir == null) {
            throw new IOException("目标dex目录为空");
        }

        if (targetDir.exists()) {
            deleteFileOrDir(targetDir);
        }

        if (!targetDir.mkdirs()) {
            throw new IOException("创建目标dex目录失败：" + targetDir.getAbsolutePath());
        }

        int index = 1;

        while (true) {
            String dexName = index == 1 ? "classes.dex" : "classes" + index + ".dex";
            File dexFile = new File(sourceDir, dexName);

            if (!dexFile.exists()) {
                break;
            }

            if (!dexFile.isFile()) {
                break;
            }

            File outFile = new File(targetDir, dexName);
            copyFile(dexFile, outFile);

            //appendLogOnUi("已备份dex：" + dexName);

            index++;
        }
    }
    public static void deleteFileOrDir(File file) {
        if (file == null || !file.exists()) {
            return;
        }

        if (file.isDirectory()) {
            File[] children = file.listFiles();

            if (children != null) {
                for (File child : children) {
                    deleteFileOrDir(child);
                }
            }
        }

        if (!file.delete()) {
            //appendLogOnUi("删除失败：" + file.getAbsolutePath());
        }
    }
    public static byte[] readAllBytes(File file) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        byte[] data = readAllBytes(fis);
        fis.close();
        return data;
    }

    public static byte[] readAllBytes(InputStream inputStream) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] buffer = new byte[8192];
        int len;
        while ((len = inputStream.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }

        inputStream.close();
        return out.toByteArray();
    }

    public static void writeAllBytes(File file, byte[] data) throws Exception {
        FileOutputStream out = new FileOutputStream(file, false);
        try {
            out.write(data);
            out.flush();
        } finally {
            out.close();
        }
    }

    public static byte[] copyRange(byte[] data, int offset, int size) {
        byte[] out = new byte[size];
        System.arraycopy(data, offset, out, 0, size);
        return out;
    }

    public static long align(long value, long align) {
        if (align <= 1) {
            return value;
        }

        long mod = value % align;
        if (mod == 0) {
            return value;
        }

        return value + align - mod;
    }

    public static int readU16LE(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8);
    }

    public static int readIntLE(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    public static long readUIntLE(byte[] data, int offset) {
        return readIntLE(data, offset) & 0xffffffffL;
    }

    public static long readLongLE(byte[] data, int offset) {
        return (readUIntLE(data, offset))
                | (readUIntLE(data, offset + 4) << 32);
    }

    public static void writeU16LE(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xff);
        data[offset + 1] = (byte) ((value >> 8) & 0xff);
    }

    public static void writeIntLE(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xff);
        data[offset + 1] = (byte) ((value >> 8) & 0xff);
        data[offset + 2] = (byte) ((value >> 16) & 0xff);
        data[offset + 3] = (byte) ((value >> 24) & 0xff);
    }

    public static void writeLongLE(byte[] data, int offset, long value) {
        writeIntLE(data, offset, (int) (value & 0xffffffffL));
        writeIntLE(data, offset + 4, (int) ((value >> 32) & 0xffffffffL));
    }

    public static String readCString(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) {
            return "";
        }

        int end = offset;
        while (end < data.length && data[end] != 0) {
            end++;
        }

        try {
            return new String(data, offset, end - offset, "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }
    public static void deleteFileQuietly(File file) {
        if (file == null) {
            return;
        }

        try {
            if (file.exists() && file.isFile()) {
                if (file.delete()) {
                    //appendLogOnUi("已删除临时文件：" + file.getName());
                }
            }
        } catch (Exception ignored) {
        }
    }
    public static void deleteDirQuietly(File dir) {
        if (dir == null || !dir.exists()) {
            return;
        }

        try {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirQuietly(file);
                    } else {
                        deleteFileQuietly(file);
                    }
                }
            }

            if (dir.delete()) {
                //appendLogOnUi("已删除目录：" + dir.getName());
            }
        } catch (Exception ignored) {
        }
    }
    public static void cleanTempFiles(File dir) {
        if (dir == null || !dir.exists()) {
            return;
        }

        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            deleteFileOrDir(file);
        }
    }
    public static String buildProtectedApkName(String originalName) {
        if (originalName == null || originalName.trim().isEmpty()) {
            return "已加固.apk";
        }

        String name = originalName.trim();

        if (name.toLowerCase().endsWith(".apk")) {
            return name.substring(0, name.length() - 4) + "(已加固).apk";
        }

        return name + "(已加固).apk";
    }
    public static String getRelativePath(File root, File file) {
        String rootPath = root.getAbsolutePath();
        String filePath = file.getAbsolutePath();

        String relative = filePath.substring(rootPath.length());

        if (relative.startsWith("/") || relative.startsWith("\\")) {
            relative = relative.substring(1);
        }

        return relative.replace("\\", "/");
    }
    public static boolean shouldStoreEntry(String name, ZipEntry oldEntry) {
        if (oldEntry.getMethod() == ZipEntry.STORED) {
            return true;
        }

        String lower = name.toLowerCase();

        return lower.endsWith(".arsc")
                || lower.endsWith(".png")
                || lower.endsWith(".jpg")
                || lower.endsWith(".jpeg")
                || lower.endsWith(".webp")
                || lower.endsWith(".mp3")
                || lower.endsWith(".mp4")
                || lower.endsWith(".ogg")
                || lower.endsWith(".wav");
    }
    public static void collectLibSkipNames(File rootLibDir, File current, Set<String> skipNames) {
        File[] files = current.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                collectLibSkipNames(rootLibDir, file, skipNames);
            } else {
                String relative = getRelativePath(rootLibDir, file);
                skipNames.add("lib/" + relative);
            }
        }
    }
    public static File zipAlignApk(File inputApk) throws Exception {
        if (inputApk == null || !inputApk.exists()) {
            throw new RuntimeException("待对齐 APK 不存在");
        }

        File parentDir = inputApk.getParentFile();
        if (parentDir == null || !parentDir.exists()) {
            throw new RuntimeException("APK 所在目录不存在");
        }

        File alignedApk = new File(parentDir, inputApk.getName() + ".aligning");

        deleteFileQuietly(alignedApk);

        boolean success = ZipAlign.doZipAlign(
                inputApk.getAbsolutePath(),
                alignedApk.getAbsolutePath(),
                4,
                true,
                true
        );

        if (!success || !alignedApk.exists()) {
            throw new RuntimeException("zipalign 对齐失败");
        }

        boolean verified = ZipAlign.isZipAligned(
                alignedApk.getAbsolutePath(),
                4,
                true
        );

        if (!verified) {
            deleteFileQuietly(alignedApk);
            throw new RuntimeException("zipalign 校验失败");
        }

        if (!inputApk.delete()) {
            deleteFileQuietly(alignedApk);
            throw new RuntimeException("删除原 APK 失败");
        }

        if (!alignedApk.renameTo(inputApk)) {
            deleteFileQuietly(alignedApk);
            throw new RuntimeException("重命名对齐 APK 失败");
        }

        return inputApk;
    }
    public static  void writeVmpBinToElfSection(File soFile, File vmpBin, File outFile) throws Exception {
        byte[] elf = readAllBytes(soFile);
        byte[] vmp = readAllBytes(vmpBin);

        if (elf.length < 0x40) {
            throw new RuntimeException("ELF文件过小");
        }

        if (elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
            throw new RuntimeException("不是有效ELF文件");
        }

        int elfClass = elf[4] & 0xff;
        int elfData = elf[5] & 0xff;

        if (elfData != 1) {
            throw new RuntimeException("暂不支持非小端ELF");
        }

        if (elfClass == 2) {
            writeVmpBinToElf64Section(elf, vmp, outFile);
        } else if (elfClass == 1) {
            writeVmpBinToElf32Section(elf, vmp, outFile);
        } else {
            throw new RuntimeException("未知ELF位数：" + elfClass);
        }
    }
    public static void writeVmpBinToElf64Section(byte[] elf, byte[] vmp, File outFile) throws Exception {
        long oldShOff = readLongLE(elf, 0x28);
        int shEntSize = readU16LE(elf, 0x3A);
        int shNum = readU16LE(elf, 0x3C);
        int shStrIndex = readU16LE(elf, 0x3E);

        if (oldShOff <= 0 || shNum <= 0) {
            throw new RuntimeException("ELF64没有有效Section Header Table");
        }

        if (shEntSize != 64) {
            throw new RuntimeException("ELF64 Section Header大小异常：" + shEntSize);
        }

        if (shStrIndex < 0 || shStrIndex >= shNum) {
            throw new RuntimeException("ELF64 shstrndx非法：" + shStrIndex);
        }

        if (oldShOff + (long) shNum * shEntSize > elf.length) {
            throw new RuntimeException("ELF64 Section Header Table越界");
        }

        int shStrHeaderOff = (int) oldShOff + shStrIndex * shEntSize;
        long oldShStrOff = readLongLE(elf, shStrHeaderOff + 24);
        long oldShStrSize = readLongLE(elf, shStrHeaderOff + 32);

        if (oldShStrOff <= 0 || oldShStrSize <= 0 || oldShStrOff + oldShStrSize > elf.length) {
            throw new RuntimeException("ELF64 shstrtab越界");
        }

        byte[] oldShStr = copyRange(elf, (int) oldShStrOff, (int) oldShStrSize);

        for (int i = 0; i < shNum; i++) {
            int shOff = (int) oldShOff + i * shEntSize;
            int nameOff = readIntLE(elf, shOff);
            String name = readCString(oldShStr, nameOff);

            if (ARK_VMP_SECTION_NAME.equals(name)) {
                throw new RuntimeException("ELF64已存在section：" + ARK_VMP_SECTION_NAME);
            }
        }

        int arkNameOffset = oldShStr.length;
        byte[] arkNameBytes = (ARK_VMP_SECTION_NAME + "\0").getBytes("UTF-8");
        byte[] newShStr = new byte[oldShStr.length + arkNameBytes.length];
        System.arraycopy(oldShStr, 0, newShStr, 0, oldShStr.length);
        System.arraycopy(arkNameBytes, 0, newShStr, oldShStr.length, arkNameBytes.length);

        long arkOffset = align(elf.length, 16);
        long newShStrOffset = align(arkOffset + vmp.length, 1);
        long newShOff = align(newShStrOffset + newShStr.length, 8);

        int newShNum = shNum + 1;
        long newFileSize = newShOff + (long) newShNum * shEntSize;

        if (newFileSize > Integer.MAX_VALUE) {
            throw new RuntimeException("写入section后文件过大");
        }

        byte[] out = new byte[(int) newFileSize];

        System.arraycopy(elf, 0, out, 0, elf.length);
        System.arraycopy(vmp, 0, out, (int) arkOffset, vmp.length);
        System.arraycopy(newShStr, 0, out, (int) newShStrOffset, newShStr.length);

        int newShTableOff = (int) newShOff;
        System.arraycopy(elf, (int) oldShOff, out, newShTableOff, shNum * shEntSize);

        int newShStrHeaderOff = newShTableOff + shStrIndex * shEntSize;
        writeLongLE(out, newShStrHeaderOff + 24, newShStrOffset);
        writeLongLE(out, newShStrHeaderOff + 32, newShStr.length);

        int arkHeaderOff = newShTableOff + shNum * shEntSize;

        writeIntLE(out, arkHeaderOff, arkNameOffset);
        writeIntLE(out, arkHeaderOff + 4, 1);
        writeLongLE(out, arkHeaderOff + 8, 0);
        writeLongLE(out, arkHeaderOff + 16, 0);
        writeLongLE(out, arkHeaderOff + 24, arkOffset);
        writeLongLE(out, arkHeaderOff + 32, vmp.length);
        writeIntLE(out, arkHeaderOff + 40, 0);
        writeIntLE(out, arkHeaderOff + 44, 0);
        writeLongLE(out, arkHeaderOff + 48, 16);
        writeLongLE(out, arkHeaderOff + 56, 0);

        writeLongLE(out, 0x28, newShOff);
        writeU16LE(out, 0x3C, newShNum);
        writeU16LE(out, 0x3E, shStrIndex);

        writeAllBytes(outFile, out);

        /*appendLogOnUi("ELF64写入完成");
        appendLogOnUi("section名称：" + ARK_VMP_SECTION_NAME);
        appendLogOnUi("vmp偏移：" + arkOffset);
        appendLogOnUi("vmp大小：" + vmp.length);
        appendLogOnUi("新shstrtab偏移：" + newShStrOffset);
        appendLogOnUi("新SectionHeader偏移：" + newShOff);
        appendLogOnUi("Section数量：" + shNum + " -> " + newShNum);*/
    }

    public static void writeVmpBinToElf32Section(byte[] elf, byte[] vmp, File outFile) throws Exception {
        long oldShOff = readUIntLE(elf, 0x20);
        int shEntSize = readU16LE(elf, 0x2E);
        int shNum = readU16LE(elf, 0x30);
        int shStrIndex = readU16LE(elf, 0x32);

        if (oldShOff <= 0 || shNum <= 0) {
            throw new RuntimeException("ELF32没有有效Section Header Table");
        }

        if (shEntSize != 40) {
            throw new RuntimeException("ELF32 Section Header大小异常：" + shEntSize);
        }

        if (shStrIndex < 0 || shStrIndex >= shNum) {
            throw new RuntimeException("ELF32 shstrndx非法：" + shStrIndex);
        }

        if (oldShOff + (long) shNum * shEntSize > elf.length) {
            throw new RuntimeException("ELF32 Section Header Table越界");
        }

        int shStrHeaderOff = (int) oldShOff + shStrIndex * shEntSize;
        long oldShStrOff = readUIntLE(elf, shStrHeaderOff + 16);
        long oldShStrSize = readUIntLE(elf, shStrHeaderOff + 20);

        if (oldShStrOff <= 0 || oldShStrSize <= 0 || oldShStrOff + oldShStrSize > elf.length) {
            throw new RuntimeException("ELF32 shstrtab越界");
        }

        byte[] oldShStr = copyRange(elf, (int) oldShStrOff, (int) oldShStrSize);

        for (int i = 0; i < shNum; i++) {
            int shOff = (int) oldShOff + i * shEntSize;
            int nameOff = readIntLE(elf, shOff);
            String name = readCString(oldShStr, nameOff);

            if (ARK_VMP_SECTION_NAME.equals(name)) {
                throw new RuntimeException("ELF32已存在section：" + ARK_VMP_SECTION_NAME);
            }
        }

        int arkNameOffset = oldShStr.length;
        byte[] arkNameBytes = (ARK_VMP_SECTION_NAME + "\0").getBytes("UTF-8");
        byte[] newShStr = new byte[oldShStr.length + arkNameBytes.length];
        System.arraycopy(oldShStr, 0, newShStr, 0, oldShStr.length);
        System.arraycopy(arkNameBytes, 0, newShStr, oldShStr.length, arkNameBytes.length);

        long arkOffset = align(elf.length, 16);
        long newShStrOffset = align(arkOffset + vmp.length, 1);
        long newShOff = align(newShStrOffset + newShStr.length, 4);

        int newShNum = shNum + 1;
        long newFileSize = newShOff + (long) newShNum * shEntSize;

        if (newFileSize > Integer.MAX_VALUE) {
            throw new RuntimeException("写入section后文件过大");
        }

        byte[] out = new byte[(int) newFileSize];

        System.arraycopy(elf, 0, out, 0, elf.length);
        System.arraycopy(vmp, 0, out, (int) arkOffset, vmp.length);
        System.arraycopy(newShStr, 0, out, (int) newShStrOffset, newShStr.length);

        int newShTableOff = (int) newShOff;
        System.arraycopy(elf, (int) oldShOff, out, newShTableOff, shNum * shEntSize);

        int newShStrHeaderOff = newShTableOff + shStrIndex * shEntSize;
        writeIntLE(out, newShStrHeaderOff + 16, (int) newShStrOffset);
        writeIntLE(out, newShStrHeaderOff + 20, newShStr.length);

        int arkHeaderOff = newShTableOff + shNum * shEntSize;

        writeIntLE(out, arkHeaderOff, arkNameOffset);
        writeIntLE(out, arkHeaderOff + 4, 1);
        writeIntLE(out, arkHeaderOff + 8, 0);
        writeIntLE(out, arkHeaderOff + 12, 0);
        writeIntLE(out, arkHeaderOff + 16, (int) arkOffset);
        writeIntLE(out, arkHeaderOff + 20, vmp.length);
        writeIntLE(out, arkHeaderOff + 24, 0);
        writeIntLE(out, arkHeaderOff + 28, 0);
        writeIntLE(out, arkHeaderOff + 32, 16);
        writeIntLE(out, arkHeaderOff + 36, 0);

        writeIntLE(out, 0x20, (int) newShOff);
        writeU16LE(out, 0x30, newShNum);
        writeU16LE(out, 0x32, shStrIndex);

        writeAllBytes(outFile, out);

        /*appendLogOnUi("ELF32写入完成");
        appendLogOnUi("section名称：" + ARK_VMP_SECTION_NAME);
        appendLogOnUi("vmp偏移：" + arkOffset);
        appendLogOnUi("vmp大小：" + vmp.length);
        appendLogOnUi("新shstrtab偏移：" + newShStrOffset);
        appendLogOnUi("新SectionHeader偏移：" + newShOff);
        appendLogOnUi("Section数量：" + shNum + " -> " + newShNum);*/
    }
    public static void addZipEntryStream(Context context, ZipOutputStream zos, String name, InputStream in, ZipEntry oldEntry) throws Exception {
        File tempFile = null;

        try {
            ZipEntry newEntry = new ZipEntry(name);

            if (oldEntry != null) {
                newEntry.setTime(oldEntry.getTime());
                newEntry.setComment(oldEntry.getComment());
                newEntry.setExtra(oldEntry.getExtra());
            }

            if (oldEntry != null && shouldStoreEntry(name, oldEntry)) {
                tempFile = File.createTempFile("ark_zip_", ".tmp", context.getCacheDir());

                CRC32 crc32 = new CRC32();
                long size = 0;

                FileOutputStream tempOut = new FileOutputStream(tempFile);
                byte[] buffer = new byte[8192];
                int len;

                while ((len = in.read(buffer)) != -1) {
                    tempOut.write(buffer, 0, len);
                    crc32.update(buffer, 0, len);
                    size += len;
                }

                tempOut.flush();
                tempOut.close();

                newEntry.setMethod(ZipEntry.STORED);
                newEntry.setSize(size);
                newEntry.setCompressedSize(size);
                newEntry.setCrc(crc32.getValue());

                zos.putNextEntry(newEntry);

                FileInputStream tempIn = new FileInputStream(tempFile);
                while ((len = tempIn.read(buffer)) != -1) {
                    zos.write(buffer, 0, len);
                }
                tempIn.close();

                zos.closeEntry();
            } else {
                newEntry.setMethod(ZipEntry.DEFLATED);

                zos.putNextEntry(newEntry);

                byte[] buffer = new byte[8192];
                int len;

                while ((len = in.read(buffer)) != -1) {
                    zos.write(buffer, 0, len);
                }

                zos.closeEntry();
            }
        } finally {
            try {
                in.close();
            } catch (Exception ignored) {
            }

            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }
    public static void addDirectoryZipEntry(ZipOutputStream zos, String name, ZipEntry oldEntry) throws Exception {
        if (!name.endsWith("/")) {
            name = name + "/";
        }

        ZipEntry newEntry = new ZipEntry(name);

        if (oldEntry != null) {
            newEntry.setTime(oldEntry.getTime());
            newEntry.setComment(oldEntry.getComment());
            newEntry.setExtra(oldEntry.getExtra());
        }

        zos.putNextEntry(newEntry);
        zos.closeEntry();
    }
    public static void addLibDirToZipStream(Context context, ZipOutputStream zos, File rootDir, File currentDir) throws Exception {
        File[] files = currentDir.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                addLibDirToZipStream(context, zos, rootDir, file);
                continue;
            }

            String relativePath = rootDir.toURI().relativize(file.toURI()).getPath();
            String zipName = "lib/" + relativePath;

            addZipEntryStream(context, zos, zipName, new FileInputStream(file), null);
        }
    }
    public static ArrayList<String> readApkAbiList(File apkFile) throws Exception {
        ArrayList<String> abiList = new ArrayList<>();

        ZipFile zipFile = new ZipFile(apkFile);

        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();

            if (!name.startsWith("lib/")) {
                continue;
            }

            String[] parts = name.split("/");
            if (parts.length < 3) {
                continue;
            }

            String abi = parts[1];

            if (!abiList.contains(abi)) {
                abiList.add(abi);
            }
        }

        zipFile.close();
        return abiList;
    }
    public static void rewriteApplicationAttributes(Context context, Element application) {
        final String androidNs = "http://schemas.android.com/apk/res/android";

        String stubClassName = getValidStubClassNameFromSettings(context);
        String factoryClassName = stubClassName + "$Factory";

        ArrayList<Attr> oldAttrs = new ArrayList<>();

        NamedNodeMap attrMap = application.getAttributes();
        for (int i = 0; i < attrMap.getLength(); i++) {
            Node node = attrMap.item(i);
            if (node instanceof Attr) {
                Attr attr = (Attr) node;
                String name = attr.getName();

                if ("android:name".equals(name)
                        || "name".equals(name)
                        || "android:extractNativeLibs".equals(name)
                        || "extractNativeLibs".equals(name)
                        || "android:appComponentFactory".equals(name)
                        || "appComponentFactory".equals(name)) {
                    continue;
                }

                oldAttrs.add(attr);
            }
        }

        while (application.getAttributes().getLength() > 0) {
            Node node = application.getAttributes().item(0);
            application.removeAttributeNode((Attr) node);
        }

        boolean hasLabelWritten = false;
        boolean hasIconWritten = false;
        boolean inserted = false;

        for (Attr attr : oldAttrs) {
            String attrName = attr.getName();
            String attrValue = attr.getValue();

            if (attr.getNamespaceURI() != null && attr.getNamespaceURI().length() > 0) {
                application.setAttributeNS(attr.getNamespaceURI(), attrName, attrValue);
            } else {
                application.setAttribute(attrName, attrValue);
            }

            if ("android:label".equals(attrName)) {
                hasLabelWritten = true;
            }

            if ("android:icon".equals(attrName)) {
                hasIconWritten = true;
            }

            if (!inserted && hasLabelWritten && hasIconWritten) {
                application.setAttributeNS(
                        androidNs,
                        "android:name",
                        stubClassName
                );

                application.setAttributeNS(
                        androidNs,
                        "android:appComponentFactory",
                        factoryClassName
                );

                application.setAttributeNS(
                        androidNs,
                        "android:extractNativeLibs",
                        "true"
                );

                inserted = true;
            }
        }

        if (!inserted) {
            application.setAttributeNS(
                    androidNs,
                    "android:name",
                    stubClassName
            );

            application.setAttributeNS(
                    androidNs,
                    "android:appComponentFactory",
                    factoryClassName
            );

            application.setAttributeNS(
                    androidNs,
                    "android:extractNativeLibs",
                    "true"
            );
        }
    }

    public static String getValidStubClassNameFromSettings(Context context) {
        try {
            ArkSettings settings = readArkSettings(context);

            if (settings != null
                    && settings.stubClassName != null
                    && !settings.stubClassName.trim().isEmpty()) {
                return settings.stubClassName.trim();
            }
        } catch (Exception ignored) {
        }

        return DEFAULT_STUB_CLASS_NAME;
    }
    public static class ArkSettings {
        String soName;
        String stubClassName;
        String savePath;
        boolean enableVmpExtract;
        boolean Debug;
        boolean autoSign;

        boolean useCustomJks;
        String jksPath;
        String jksStorePass;
        String jksAlias;
        String jksKeyPass;

        ArkSettings(
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
                String jksKeyPass
        ) {
            this.soName = soName;
            this.stubClassName = stubClassName;
            this.savePath = savePath;
            this.enableVmpExtract = enableVmpExtract;
            this.Debug = Debug;
            this.autoSign = autoSign;
            this.useCustomJks = useCustomJks;
            this.jksPath = jksPath;
            this.jksStorePass = jksStorePass;
            this.jksAlias = jksAlias;
            this.jksKeyPass = jksKeyPass;
        }
    }
    public static ArkSettings readArkSettings(Context context) {
        android.content.SharedPreferences sp = context.getSharedPreferences(SP_SETTINGS, MODE_PRIVATE);

        //String defaultSavePath = getWorkDir().getAbsolutePath();
        String defaultSavePath = "/storage/emulated/0/";//输出APK的默认保存目录

        String soName = sp.getString(KEY_SO_NAME, DEFAULT_SO_NAME);
        String stubClassName = sp.getString(KEY_STUB_CLASS_NAME, DEFAULT_STUB_CLASS_NAME);
        String savePath = sp.getString(KEY_SAVE_PATH, defaultSavePath);
        boolean enableVmpExtract = sp.getBoolean(KEY_ENABLE_VMP_EXTRACT, false);
        boolean Debug = sp.getBoolean(KEY_DEBUG, false);
        boolean autoSign = sp.getBoolean(KEY_AUTO_SIGN, false);

        boolean useCustomJks = sp.getBoolean(KEY_USE_CUSTOM_JKS, false);
        String jksPath = sp.getString(KEY_JKS_PATH, "");
        String jksStorePass = sp.getString(KEY_JKS_STORE_PASS, "");
        String jksAlias = sp.getString(KEY_JKS_ALIAS, "");
        String jksKeyPass = sp.getString(KEY_JKS_KEY_PASS, "");

        if (soName == null || soName.trim().isEmpty()) {
            soName = DEFAULT_SO_NAME;
        }

        if (stubClassName == null || stubClassName.trim().isEmpty()) {
            stubClassName = DEFAULT_STUB_CLASS_NAME;
        }

        if (savePath == null || savePath.trim().isEmpty()) {
            savePath = defaultSavePath;
        }

        return new ArkSettings(
                soName,
                stubClassName,
                savePath,
                enableVmpExtract,
                Debug,
                autoSign,
                useCustomJks,
                jksPath == null ? "" : jksPath,
                jksStorePass == null ? "" : jksStorePass,
                jksAlias == null ? "" : jksAlias,
                jksKeyPass == null ? "" : jksKeyPass
        );
    }
    public static String getFileNameFromUri(Context context, Uri uri) {
        if (uri == null) {
            return null;
        }

        String result = null;

        android.database.Cursor cursor = null;
        try {
            cursor = context.getContentResolver().query(
                    uri,
                    new String[]{android.provider.OpenableColumns.DISPLAY_NAME},
                    null,
                    null,
                    null
            );

            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    result = cursor.getString(index);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        if (result == null || result.trim().isEmpty()) {
            String path = uri.getPath();
            if (path != null) {
                int index = path.lastIndexOf('/');
                if (index >= 0 && index < path.length() - 1) {
                    result = path.substring(index + 1);
                }
            }
        }

        return result;
    }
    public static void copyUriToFile(Context context, Uri uri, File outFile) throws Exception {
        InputStream in = context.getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new RuntimeException("无法打开输入文件");
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
    }
    public static String readApplicationName(Context context, File apkFile) {
        PackageManager pm = context.getPackageManager();

        PackageInfo info = pm.getPackageArchiveInfo(
                apkFile.getAbsolutePath(),
                PackageManager.GET_ACTIVITIES | PackageManager.GET_META_DATA
        );

        if (info == null || info.applicationInfo == null) {
            return "android.app.Application";
        }

        String className = info.applicationInfo.className;
        if (className == null || className.trim().isEmpty()) {
            return "android.app.Application";
        }

        return className;
    }
    public static String readAppComponentFactoryName(Context context, File apkFile) {
        PackageManager pm = context.getPackageManager();

        PackageInfo info = pm.getPackageArchiveInfo(
                apkFile.getAbsolutePath(),
                PackageManager.GET_ACTIVITIES | PackageManager.GET_META_DATA
        );

        if (info == null || info.applicationInfo == null) {
            return null;
        }

        try {
            java.lang.reflect.Field field = ApplicationInfo.class.getField("appComponentFactory");
            Object value = field.get(info.applicationInfo);

            if (value instanceof String) {
                String className = ((String) value).trim();
                if (!className.isEmpty()) {
                    return className;
                }
            }
        } catch (Throwable ignored) {
        }

        return null;
    }




    public static  List<String> readActivityOnCreateMethods(Context context, File apkFile, LogCallback log) {
        List<String> result = new ArrayList<>();

        try {
            PackageManager pm = context.getPackageManager();

            PackageInfo packageInfo;

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageInfo = pm.getPackageArchiveInfo(
                        apkFile.getAbsolutePath(),
                        PackageManager.PackageInfoFlags.of(PackageManager.GET_ACTIVITIES)
                );
            } else {
                packageInfo = pm.getPackageArchiveInfo(
                        apkFile.getAbsolutePath(),
                        PackageManager.GET_ACTIVITIES
                );
            }

            if (packageInfo == null) {
                log(log, "读取 APK 包信息失败");
                return result;
            }

            ApplicationInfo appInfo = packageInfo.applicationInfo;
            if (appInfo != null) {
                appInfo.sourceDir = apkFile.getAbsolutePath();
                appInfo.publicSourceDir = apkFile.getAbsolutePath();
            }

            ActivityInfo[] activities = packageInfo.activities;
            if (activities == null || activities.length == 0) {
                log(log, "目标 APK 中未发现 Activity");
                return result;
            }

            for (ActivityInfo activityInfo : activities) {
                if (activityInfo == null || activityInfo.name == null) {
                    continue;
                }

                String className = activityInfo.name;

                if (className.startsWith(".")) {
                    className = packageInfo.packageName + className;
                }
                // 排除内部类、匿名类，例如：com.demo.Activity$1
                if (className.contains("$")) {
                    //appendLogOnUi("跳过内部类 Activity：" + className);
                    continue;
                }

                result.add(className + ".onCreate");
            }

        } catch (Exception e) {
            log(log, "读取 Activity 失败：" + e.getMessage());
        }

        return result;
    }
    public static File getWorkDir() {
        return new File(Environment.getExternalStorageDirectory(), TEMP_DIR_NAME);
    }
    public static File getFinalOutputDir(Context context, File fallbackDir, LogCallback log) {
        try {
            ArkSettings settings = readArkSettings(context);

            if (settings != null && settings.savePath != null) {
                File saveDir = new File(settings.savePath.trim());

                if (!saveDir.exists()) {
                    saveDir.mkdirs();
                }

                if (saveDir.exists() && saveDir.isDirectory() && saveDir.canWrite()) {
                    return saveDir;
                }
            }
        } catch (Exception e) {
            log(log, "读取输出目录设置失败，使用默认目录：" + e.getMessage());
        }
        return fallbackDir;
    }
    /**
     * 在指定目录生成壳 classes.dex 此版本是attach直接调用
     */
    public static File generateShellDex(Context context, File outputDir, LogCallback log) throws Exception {
        if (outputDir == null) {
            throw new IllegalArgumentException("输出目录为空");
        }

        if (!outputDir.exists() && !outputDir.mkdirs()) {
            throw new RuntimeException("创建输出目录失败：" + outputDir.getAbsolutePath());
        }

        File outputDex = new File(outputDir, "classes.dex");

        String customStubClassName = getValidStubClassNameFromSettings(context);

        String stubClass = "L" + customStubClassName.replace('.', '/') + ";";
        String factoryClass = "L" + customStubClassName.replace('.', '/') + "$Factory;";
        String applicationClass = "Landroid/app/Application;";
        String contextClass = "Landroid/content/Context;";

        DexPool dexPool = new DexPool(Opcodes.getDefault());

        ImmutableMethod clinitMethod = new ImmutableMethod(
                stubClass,
                "<clinit>",
                Collections.<ImmutableMethodParameter>emptyList(),
                "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                Collections.emptySet(),
                null,
                new ImmutableMethodImplementation(
                        2,
                        Arrays.asList(
                                new ImmutableInstruction21c(
                                        Opcode.CONST_STRING,
                                        0,
                                        new ImmutableStringReference("ark")
                                ),
                                new ImmutableInstruction21c(
                                        Opcode.CONST_STRING,
                                        1,
                                        new ImmutableStringReference(customStubClassName)
                                ),
                                new ImmutableInstruction35c(
                                        Opcode.INVOKE_STATIC,
                                        2,
                                        0,
                                        1,
                                        0,
                                        0,
                                        0,
                                        new ImmutableMethodReference(
                                                "Ljava/lang/System;",
                                                "setProperty",
                                                Arrays.asList(
                                                        "Ljava/lang/String;",
                                                        "Ljava/lang/String;"
                                                ),
                                                "Ljava/lang/String;"
                                        )
                                ),
                                new ImmutableInstruction21c(
                                        Opcode.CONST_STRING,
                                        0,
                                        new ImmutableStringReference(getValidSoNameFromSettings(context, log))
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
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        );

        ImmutableMethod initMethod = new ImmutableMethod(
                stubClass,
                "<init>",
                Collections.<ImmutableMethodParameter>emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                Collections.emptySet(),
                null,
                new ImmutableMethodImplementation(
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
                                                applicationClass,
                                                "<init>",
                                                Collections.<String>emptyList(),
                                                "V"
                                        )
                                ),
                                new ImmutableInstruction10x(Opcode.RETURN_VOID)
                        ),
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        );

        ImmutableMethod attachBaseContextMethod = new ImmutableMethod(
                stubClass,
                "attachBaseContext",
                Collections.singletonList(
                        new ImmutableMethodParameter(
                                contextClass,
                                Collections.emptySet(),
                                null
                        )
                ),
                "V",
                AccessFlags.PROTECTED.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        );

        // 【新增】壳 Application 的 native onCreate 方法
        // 作用：让 native 层在 StubApp.onCreate 阶段再启动真实 Application
        // 签名对应：public native void onCreate();
        ImmutableMethod onCreateMethod = new ImmutableMethod(
                stubClass,
                "onCreate",
                Collections.<ImmutableMethodParameter>emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        );

        List<MethodParameter> vmCommonParams = Arrays.asList(
                new ImmutableMethodParameter("I", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Collections.emptySet(), null),
                new ImmutableMethodParameter("[Ljava/lang/Object;", Collections.emptySet(), null)
        );

        int vmNativeFlags = AccessFlags.PUBLIC.getValue()
                | AccessFlags.STATIC.getValue()
                | AccessFlags.NATIVE.getValue();

        List<ImmutableMethod> methods = new ArrayList<>();

        methods.add(clinitMethod);
        methods.add(initMethod);
        methods.add(attachBaseContextMethod);

        // 【新增】添加 native onCreate 到壳类
        methods.add(onCreateMethod);

        methods.add(new ImmutableMethod(
                stubClass,
                "loadDexFromFactory",
                Collections.singletonList(
                        new ImmutableMethodParameter(
                                "Ljava/lang/ClassLoader;",
                                Collections.emptySet(),
                                null
                        )
                ),
                "V",
                AccessFlags.PUBLIC.getValue()
                        | AccessFlags.STATIC.getValue()
                        | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));
        methods.add(new ImmutableMethod(
                stubClass,
                "nativeInstantiateApplication",
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null)
                ),
                "Landroid/app/Application;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                stubClass,
                "nativeInstantiateProvider",
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null)
                ),
                "Landroid/content/ContentProvider;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                stubClass,
                "nativeInstantiateActivity",
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Landroid/content/Intent;", Collections.emptySet(), null)
                ),
                "Landroid/app/Activity;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                stubClass,
                "nativeInstantiateService",
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Landroid/content/Intent;", Collections.emptySet(), null)
                ),
                "Landroid/app/Service;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                stubClass,
                "nativeInstantiateReceiver",
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Landroid/content/Intent;", Collections.emptySet(), null)
                ),
                "Landroid/content/BroadcastReceiver;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.NATIVE.getValue(),
                Collections.emptySet(),
                null,
                null
        ));



        methods.add(new ImmutableMethod(stubClass, "callVoid", vmCommonParams, "V", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callBoolean", vmCommonParams, "Z", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callByte", vmCommonParams, "B", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callShort", vmCommonParams, "S", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callChar", vmCommonParams, "C", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callInt", vmCommonParams, "I", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callLong", vmCommonParams, "J", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callFloat", vmCommonParams, "F", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callDouble", vmCommonParams, "D", vmNativeFlags, null, null, null));
        methods.add(new ImmutableMethod(stubClass, "callObject", vmCommonParams, "Ljava/lang/Object;", vmNativeFlags, null, null, null));

        ImmutableClassDef stubClassDef = new ImmutableClassDef(
                stubClass,
                AccessFlags.PUBLIC.getValue(),
                applicationClass,
                Collections.<String>emptyList(),
                "StubApp.java",
                Collections.emptySet(),
                Collections.emptyList(),
                methods
        );

        dexPool.internClass(stubClassDef);
        dexPool.internClass(shengchengZujianGongchangClass(factoryClass, stubClass));
        dexPool.writeTo(new FileDataStore(outputDex));

        return outputDex;
    }
    private static ImmutableClassDef shengchengZujianGongchangClass(
            String factoryClass,
            String stubClass
    ) {
        String superFactoryClass = "Landroid/app/AppComponentFactory;";

        List<ImmutableMethod> methods = new ArrayList<>();

        methods.add(new ImmutableMethod(
                factoryClass,
                "<init>",
                Collections.<ImmutableMethodParameter>emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                Collections.emptySet(),
                null,
                new ImmutableMethodImplementation(
                        1,
                        Arrays.asList(
                                new ImmutableInstruction35c(
                                        Opcode.INVOKE_DIRECT,
                                        1,
                                        0, 0, 0, 0, 0,
                                        new ImmutableMethodReference(
                                                superFactoryClass,
                                                "<init>",
                                                Collections.<String>emptyList(),
                                                "V"
                                        )
                                ),
                                new ImmutableInstruction10x(Opcode.RETURN_VOID)
                        ),
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        ));

        methods.add(shengchengFactory2CanShuMethod(
                factoryClass,
                stubClass,
                superFactoryClass,
                "instantiateApplication",
                "Landroid/app/Application;"
        ));

        methods.add(shengchengFactory2CanShuMethod(
                factoryClass,
                stubClass,
                superFactoryClass,
                "instantiateProvider",
                "Landroid/content/ContentProvider;"
        ));

        methods.add(shengchengFactory3CanShuMethod(
                factoryClass,
                stubClass,
                superFactoryClass,
                "instantiateActivity",
                "Landroid/app/Activity;"
        ));

        methods.add(shengchengFactory3CanShuMethod(
                factoryClass,
                stubClass,
                superFactoryClass,
                "instantiateService",
                "Landroid/app/Service;"
        ));

        methods.add(shengchengFactory3CanShuMethod(
                factoryClass,
                stubClass,
                superFactoryClass,
                "instantiateReceiver",
                "Landroid/content/BroadcastReceiver;"
        ));

        return new ImmutableClassDef(
                factoryClass,
                AccessFlags.PUBLIC.getValue(),
                superFactoryClass,
                Collections.<String>emptyList(),
                "ShellAppComponentFactory.java",
                Collections.emptySet(),
                Collections.emptyList(),
                methods
        );
    }
    private static ImmutableMethod shengchengFactory2CanShuMethod(
            String factoryClass,
            String stubClass,
            String superFactoryClass,
            String methodName,
            String returnType
    ) {
        String nativeMethodName;

        if ("instantiateApplication".equals(methodName)) {
            nativeMethodName = "nativeInstantiateApplication";
        } else if ("instantiateProvider".equals(methodName)) {
            nativeMethodName = "nativeInstantiateProvider";
        } else {
            throw new IllegalArgumentException("不支持的2参数Factory方法：" + methodName);
        }

        return new ImmutableMethod(
                factoryClass,
                methodName,
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null)
                ),
                returnType,
                AccessFlags.PUBLIC.getValue(),
                Collections.emptySet(),
                null,
                new ImmutableMethodImplementation(
                        4,
                        Arrays.asList(
                                // return StubApp.nativeInstantiateXxx(cl, className)
                                // p0=this=v1, p1=cl=v2, p2=className=v3
                                new ImmutableInstruction35c(
                                        Opcode.INVOKE_STATIC,
                                        2,
                                        2, 3, 0, 0, 0,
                                        new ImmutableMethodReference(
                                                stubClass,
                                                nativeMethodName,
                                                Arrays.asList(
                                                        "Ljava/lang/ClassLoader;",
                                                        "Ljava/lang/String;"
                                                ),
                                                returnType
                                        )
                                ),
                                new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                                new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)
                        ),
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        );
    }
    private static ImmutableMethod shengchengFactory3CanShuMethod(
            String factoryClass,
            String stubClass,
            String superFactoryClass,
            String methodName,
            String returnType
    ) {
        String nativeMethodName;

        if ("instantiateActivity".equals(methodName)) {
            nativeMethodName = "nativeInstantiateActivity";
        } else if ("instantiateService".equals(methodName)) {
            nativeMethodName = "nativeInstantiateService";
        } else if ("instantiateReceiver".equals(methodName)) {
            nativeMethodName = "nativeInstantiateReceiver";
        } else {
            throw new IllegalArgumentException("不支持的3参数Factory方法：" + methodName);
        }

        return new ImmutableMethod(
                factoryClass,
                methodName,
                Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/ClassLoader;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null),
                        new ImmutableMethodParameter("Landroid/content/Intent;", Collections.emptySet(), null)
                ),
                returnType,
                AccessFlags.PUBLIC.getValue(),
                Collections.emptySet(),
                null,
                new ImmutableMethodImplementation(
                        5,
                        Arrays.asList(
                                // return StubApp.nativeInstantiateXxx(cl, className, intent)
                                // p0=this=v1, p1=cl=v2, p2=className=v3, p3=intent=v4
                                new ImmutableInstruction35c(
                                        Opcode.INVOKE_STATIC,
                                        3,
                                        2, 3, 4, 0, 0,
                                        new ImmutableMethodReference(
                                                stubClass,
                                                nativeMethodName,
                                                Arrays.asList(
                                                        "Ljava/lang/ClassLoader;",
                                                        "Ljava/lang/String;",
                                                        "Landroid/content/Intent;"
                                                ),
                                                returnType
                                        )
                                ),
                                new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                                new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)
                        ),
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        );
    }












    public static String getValidSoNameFromSettings(Context context, LogCallback log) {
        try {
            ArkSettings settings = readArkSettings(context);

            if (settings != null && isValidSoName(settings.soName)) {
                return settings.soName.trim();
            }
        } catch (Exception e) {
            log(log, "读取so名称设置失败，使用默认名称：" + e.getMessage());
        }

        return DEFAULT_SO_NAME;
    }
    public static String getValidSoFileNameFromSettings(Context context, LogCallback log) {
        return "lib" + getValidSoNameFromSettings(context, log) + ".so";
    }


}

