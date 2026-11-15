using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

class Shredder
{
    const int MOVEFILE_REPLACE_EXISTING = 0x1;
    const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
    const int SE_PRIVILEGE_ENABLED = 0x2;
    const int TOKEN_QUERY = 0x8;
    const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    const uint FILE_SHARE_ALL = 0x7;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint DELETE_ACCESS = 0x00010000;
    const uint SYNCHRONIZE = 0x00100000;
    const int FileDispositionInformation = 13;
    const int FileDispositionInformationEx = 64;
    const int DISP_DELETE = 0x1;
    const int DISP_POSIX = 0x2;
    const int DISP_IGNORE_RO = 0x10;
    const int PROCESS_DUP_HANDLE = 0x0040;
    const uint DUPLICATE_CLOSE_SOURCE = 0x1;
    const int SystemHandleInformation = 16;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileEx(string existing, string newName, int flags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")]
    static extern int NtSetInformationFile(IntPtr h, out IO_STATUS_BLOCK iosb, IntPtr info, int len, int cls);
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, int acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr tok, bool disall, ref TOKEN_PRIVILEGES newst, uint len, IntPtr prev, IntPtr retlen);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr tgtProc, out IntPtr tgtHandle, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandle(IntPtr hFile, StringBuilder path, uint cch, uint flags);
    [DllImport("kernel32.dll")]
    static extern bool SetConsoleOutputCP(uint cp);
    [DllImport("kernel32.dll")]
    static extern bool SetConsoleCP(uint cp);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint handle, int flags, string key);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint handle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint handle, uint nFiles, string[] files, uint nApps, RM_UNIQUE_PROCESS[] apps, uint nSvc, string[] svcs);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] arr, ref uint reasons);

    static bool deep = false;
    static bool forcePerm = true;
    static bool quiet = false;
    static bool sysMode = false;
    static int passes = 3;
    static int nFiles = 0, nDirs = 0, nFail = 0, nReboot = 0, nKilled = 0, nHandles = 0, nPosix = 0, nPerm = 0;
    static long bytes = 0;
    static List<string> fails = new List<string>();
    static RandomNumberGenerator rng = RandomNumberGenerator.Create();
    static byte[] buf = new byte[1048576];

    static void EnablePrivileges()
    {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out tok)) return;
        try
        {
            string[] privs = new string[] {
                "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege",
                "SeSecurityPrivilege", "SeDebugPrivilege", "SeChangeNotifyPrivilege",
                "SeLoadDriverPrivilege", "SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege",
                "SeIncreaseQuotaPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege"
            };
            foreach (string p in privs)
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, p, out luid)) continue;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privilege.Luid = luid;
                tp.Privilege.Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
        finally { CloseHandle(tok); }
    }

    static bool IsAdmin()
    {
        try
        {
            WindowsPrincipal wp = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return wp.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    static bool IsSystem()
    {
        try { return WindowsIdentity.GetCurrent().User.Value == "S-1-5-18"; }
        catch { return false; }
    }

    static string LongPath(string p)
    {
        try
        {
            if (p.StartsWith("\\\\?\\")) return p;
            string full = Path.GetFullPath(p);
            if (full.StartsWith("\\\\?\\")) return full;
            if (full.StartsWith("\\\\")) return "\\\\?\\UNC\\" + full.Substring(2);
            return "\\\\?\\" + full;
        }
        catch { return p; }
    }

    static bool Exists(string p)
    {
        try { return File.Exists(p) || Directory.Exists(p); } catch { return false; }
    }

    static void RunSysTool(string exe, string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            if (p != null) { p.WaitForExit(60000); }
        }
        catch { }
    }

    static int RunCmd(string exe, string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            if (p == null) return -1;
            p.WaitForExit(120000);
            return p.ExitCode;
        }
        catch { return -1; }
    }

    static void StripAttributes(string path, bool isDir)
    {
        // 强制清除对象的所有属性：只读/隐藏/系统/归档/加密/脱机/临时/重解析点
        try
        {
            FileAttributes a = File.GetAttributes(path);
            if ((a & FileAttributes.Encrypted) != 0 && !isDir)
            {
                try { File.Decrypt(LongPath(path)); } catch { }
            }
        }
        catch { }
        try
        {
            if (isDir) File.SetAttributes(path, FileAttributes.Directory);
            else File.SetAttributes(path, FileAttributes.Normal);
        }
        catch { }
    }

    static void ForceOpenOne(string path)
    {
        EnablePrivileges();
        try
        {
            if (Directory.Exists(path))
            {
                RunSysTool("takeown.exe", "/f \"" + path + "\" /a");
                RunSysTool("icacls.exe", "\"" + path + "\" /reset /c /q");
                RunSysTool("icacls.exe", "\"" + path + "\" /remove:d *S-1-1-0 /c /q");
                RunSysTool("icacls.exe", "\"" + path + "\" /grant *S-1-1-0:(OI)(CI)F /c /q");
            }
            else
            {
                RunSysTool("takeown.exe", "/f \"" + path + "\" /a");
                RunSysTool("icacls.exe", "\"" + path + "\" /reset /c /q");
                RunSysTool("icacls.exe", "\"" + path + "\" /remove:d *S-1-1-0 /c /q");
                RunSysTool("icacls.exe", "\"" + path + "\" /grant *S-1-1-0:F /c /q");
            }
        }
        catch { }
        StripAttributes(path, Directory.Exists(path));
    }

    static void ForceOpenDotNet(string path, bool isDir)
    {
        EnablePrivileges();
        try
        {
            IdentityReference me = WindowsIdentity.GetCurrent().User;
            if (isDir)
            {
                DirectorySecurity ds = Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                try { ds.SetOwner(me); Directory.SetAccessControl(path, ds); } catch { }
                ds = Directory.GetAccessControl(path, AccessControlSections.Access);
                try { ds.SetAccessRuleProtection(true, false); } catch { }
                foreach (FileSystemAccessRule r in ds.GetAccessRules(true, false, typeof(SecurityIdentifier))) { try { ds.RemoveAccessRule(r); } catch { } }
                ds.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(path, ds);
            }
            else
            {
                FileSecurity fs = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
                try { fs.SetOwner(me); File.SetAccessControl(path, fs); } catch { }
                fs = File.GetAccessControl(path, AccessControlSections.Access);
                try { fs.SetAccessRuleProtection(true, false); } catch { }
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, false, typeof(SecurityIdentifier))) { try { fs.RemoveAccessRule(r); } catch { } }
                fs.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(path, fs);
            }
        }
        catch { }
        StripAttributes(path, isDir);
    }

    static void FixPermsRecursive(string dir)
    {
        ForceOpenOne(dir);
        string[] subs = null;
        try { subs = Directory.GetDirectories(dir); } catch { }
        if (subs != null) for (int i = 0; i < subs.Length; i++) FixPermsRecursive(subs[i]);
        string[] fs = null;
        try { fs = Directory.GetFiles(dir); } catch { }
        if (fs != null) for (int i = 0; i < fs.Length; i++) ForceOpenOne(fs[i]);
    }

    static void ForcePermTree(string root)
    {
        EnablePrivileges();
        RunSysTool("takeown.exe", "/f \"" + root + "\" /r /d y");
        RunSysTool("icacls.exe", "\"" + root + "\" /remove:d *S-1-1-0 /t /c /q");
        RunSysTool("icacls.exe", "\"" + root + "\" /remove:d *S-1-5-32-544 /t /c /q");
        RunSysTool("icacls.exe", "\"" + root + "\" /reset /t /c /q");
        RunSysTool("icacls.exe", "\"" + root + "\" /grant *S-1-1-0:F /t /c /q");
        RunSysTool("icacls.exe", "\"" + root + "\" /grant *S-1-5-32-544:F /t /c /q");
        FixPermsRecursive(root);
    }

    // NT 层 POSIX 语义删除：即使文件正被其它进程打开，也能立刻删除
    static bool PosixDelete(string path)
    {
        IntPtr h = CreateFileW(LongPath(path), DELETE_ACCESS | SYNCHRONIZE, FILE_SHARE_ALL,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) return false;
        try
        {
            IntPtr mem = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(mem, DISP_DELETE | DISP_POSIX | DISP_IGNORE_RO);
                IO_STATUS_BLOCK iosb;
                int st = NtSetInformationFile(h, out iosb, mem, 4, FileDispositionInformationEx);
                if (st == 0) { nPosix++; return true; }
            }
            finally { Marshal.FreeHGlobal(mem); }
            IntPtr mem2 = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(mem2, 1);
                IO_STATUS_BLOCK iosb2;
                int st2 = NtSetInformationFile(h, out iosb2, mem2, 1, FileDispositionInformation);
                if (st2 == 0) return true;
            }
            finally { Marshal.FreeHGlobal(mem2); }
            return false;
        }
        finally { CloseHandle(h); }
    }

    // 枚举全系统句柄，找出占用该文件的句柄，直接 DUPLICATE_CLOSE_SOURCE 强关（比杀进程精准，且不伤无辜进程）
    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    static bool CloseFileHandles(string targetPath)
    {
        string target = null;
        try { target = Path.GetFullPath(targetPath).TrimEnd('\\').ToLowerInvariant(); } catch { return false; }
        IntPtr buf = IntPtr.Zero;
        int len = 0x100000;
        int ret = 0;
        for (int attempt = 0; attempt < 6; attempt++)
        {
            buf = Marshal.AllocHGlobal(len);
            int st = NtQuerySystemInformation(SystemHandleInformation, buf, len, out ret);
            if (st == 0) break;
            Marshal.FreeHGlobal(buf);
            buf = IntPtr.Zero;
            len *= 2;
            if (len > 0x8000000) return false;
        }
        if (buf == IntPtr.Zero) return false;
        bool any = false;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int entrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            IntPtr cur = new IntPtr(buf.ToInt64() + 8);
            IntPtr me = GetCurrentProcess();
            int myPid = Process.GetCurrentProcess().Id;
            StringBuilder sb = new StringBuilder(1024);
            for (int i = 0; i < count; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO e = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(cur, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                cur = new IntPtr(cur.ToInt64() + entrySize);
                int pid = e.UniqueProcessId;
                if (pid == 0 || pid == 4 || pid == myPid) continue;
                IntPtr hProc = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
                if (hProc == IntPtr.Zero) continue;
                try
                {
                    IntPtr dup;
                    if (!DuplicateHandle(hProc, new IntPtr(e.HandleValue), me, out dup, 0, false, 0)) continue;
                    try
                    {
                        sb.Length = 0;
                        uint n = GetFinalPathNameByHandle(dup, sb, (uint)sb.Capacity, 0);
                        if (n > 0 && n < sb.Capacity)
                        {
                            string fp = sb.ToString();
                            if (fp.StartsWith("\\\\?\\")) fp = fp.Substring(4);
                            fp = fp.ToLowerInvariant();
                            if (fp == target || fp.StartsWith(target + "\\"))
                            {
                                IntPtr dummy;
                                DuplicateHandle(hProc, new IntPtr(e.HandleValue), IntPtr.Zero, out dummy, 0, false, DUPLICATE_CLOSE_SOURCE);
                                any = true;
                                nHandles++;
                            }
                        }
                    }
                    finally { CloseHandle(dup); }
                }
                finally { CloseHandle(hProc); }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return any;
    }

    static void KillLockers(string path)
    {
        uint handle;
        string key = Guid.NewGuid().ToString();
        if (RmStartSession(out handle, 0, key) != 0) return;
        try
        {
            string[] res = new string[] { path };
            if (RmRegisterResources(handle, 1, res, 0, null, 0, null) != 0) return;
            uint needed = 0, count = 0, reasons = 0;
            RM_PROCESS_INFO[] arr = null;
            int rv = RmGetList(handle, out needed, ref count, arr, ref reasons);
            if (rv == 234 && needed > 0)
            {
                arr = new RM_PROCESS_INFO[needed];
                count = needed;
                rv = RmGetList(handle, out needed, ref count, arr, ref reasons);
            }
            if (rv != 0 || arr == null) return;
            int myPid = Process.GetCurrentProcess().Id;
            for (int i = 0; i < count && i < arr.Length; i++)
            {
                int pid = arr[i].Process.dwProcessId;
                if (pid <= 4 || pid == myPid) continue;
                try
                {
                    Process pr = Process.GetProcessById(pid);
                    string nm = pr.ProcessName.ToLowerInvariant();
                    if (nm == "system" || nm == "csrss" || nm == "wininit" || nm == "smss" || nm == "services" || nm == "lsass" || nm == "winlogon" || nm == "shredder") continue;
                    pr.Kill();
                    pr.WaitForExit(3000);
                    nKilled++;
                    Console.WriteLine();
                    Console.WriteLine("[解占用] 已终止 " + pr.ProcessName + " (PID " + pid + ")");
                }
                catch { }
            }
        }
        finally { RmEndSession(handle); }
    }

    static string TryRename(string path)
    {
        try
        {
            string dir = Path.GetDirectoryName(path);
            if (dir == null) return null;
            string ext = Path.GetExtension(path);
            string np = Path.Combine(dir, Guid.NewGuid().ToString("N") + ext);
            if (MoveFileEx(LongPath(path), LongPath(np), MOVEFILE_REPLACE_EXISTING)) return np;
            return null;
        }
        catch { return null; }
    }

    static void ScheduleReboot(string path)
    {
        bool ok = false;
        try { ok = MoveFileEx(LongPath(path), null, MOVEFILE_DELAY_UNTIL_REBOOT); } catch { }
        nReboot++;
        Console.WriteLine();
        Console.WriteLine("[重启后删] " + path + (ok ? "  (已登记，重启时由内核删除)" : "  (登记失败：请以管理员身份运行后重试)"));
        fails.Add(path + " (pending reboot delete" + (ok ? "" : ", register failed") + ")");
    }

    static bool HardDelete(string p)
    {
        try
        {
            if (!Exists(p)) return true;
            if (Directory.Exists(p))
            {
                try { File.SetAttributes(p, FileAttributes.Directory); } catch { }
                Directory.Delete(p, false);
                return !Directory.Exists(p);
            }
            try { File.SetAttributes(p, FileAttributes.Normal); } catch { }
            File.Delete(p);
            return !File.Exists(p);
        }
        catch { return false; }
    }

    static bool Overwrite(string path)
    {
        FileStream fs = null;
        try
        {
            fs = new FileStream(LongPath(path), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            long len = fs.Length;
            if (deep)
            {
                for (int pass = 0; pass < passes; pass++)
                {
                    fs.Position = 0;
                    long left = len;
                    while (left > 0)
                    {
                        int n = (int)Math.Min((long)buf.Length, left);
                        rng.GetBytes(buf, 0, n);
                        fs.Write(buf, 0, n);
                        left -= n;
                    }
                    fs.Flush(true);
                }
            }
            else
            {
                long chunk = Math.Min(len, (long)buf.Length);
                if (chunk > 0)
                {
                    rng.GetBytes(buf, 0, (int)chunk);
                    fs.Position = 0;
                    fs.Write(buf, 0, (int)chunk);
                }
                if (len > chunk * 2)
                {
                    rng.GetBytes(buf, 0, (int)chunk);
                    fs.Position = len - chunk;
                    fs.Write(buf, 0, (int)chunk);
                }
                fs.Flush();
            }
            fs.SetLength(0);
            return true;
        }
        catch { return false; }
        finally { if (fs != null) { try { fs.Dispose(); } catch { } } }
    }

    static bool IsProtected(string p)
    {
        string s = p.ToLowerInvariant();
        return s.Contains("cuckoo-agent") || s.Contains("shredder.exe") || s.Contains("shredder.cs");
    }

    // 终极删除：逐级升级手段，直到对象消失
    static bool Annihilate(string p, bool isDir)
    {
        if (!Exists(p)) return true;
        StripAttributes(p, isDir);
        if (HardDelete(p)) return true;
        if (forcePerm) { ForceOpenDotNet(p, isDir); if (HardDelete(p)) return true; }
        if (forcePerm) { ForceOpenOne(p); if (HardDelete(p)) return true; }
        CloseFileHandles(p);
        if (HardDelete(p)) return true;
        if (PosixDelete(p)) return true;
        KillLockers(p);
        if (HardDelete(p)) return true;
        if (PosixDelete(p)) return true;
        string r = TryRename(p);
        if (r != null)
        {
            if (HardDelete(r)) return true;
            if (PosixDelete(r)) return true;
            p = r;
        }
        CloseFileHandles(p);
        if (HardDelete(p)) return true;
        if (PosixDelete(p)) return true;
        ScheduleReboot(p);
        return false;
    }

    static void ShredFile(string file)
    {
        if (IsProtected(file)) { Console.WriteLine("[保护] 跳过：" + file); return; }
        long size = 0;
        try { FileInfo fi = new FileInfo(file); size = fi.Length; } catch { }
        StripAttributes(file, false);
        // 第一步：尽力覆写（防恢复）。覆写失败不影响删除
        bool overwritten = Overwrite(file);
        if (!overwritten)
        {
            CloseFileHandles(file);
            overwritten = Overwrite(file);
        }
        if (!overwritten && forcePerm)
        {
            ForceOpenDotNet(file, false);
            nPerm++;
            overwritten = Overwrite(file);
        }
        // 第二步：死磕删除
        if (Annihilate(file, false))
        {
            nFiles++; bytes += size;
            if (!quiet) Console.Write(".");
        }
    }

    static void Collect(string dir, List<string> files, List<string> dirs, List<string> links)
    {
        try
        {
            string[] ds = Directory.GetDirectories(dir);
            for (int i = 0; i < ds.Length; i++)
            {
                try
                {
                    FileAttributes a = File.GetAttributes(ds[i]);
                    if ((a & FileAttributes.ReparsePoint) != 0) { links.Add(ds[i]); continue; }
                }
                catch { }
                Collect(ds[i], files, dirs, links);
            }
            string[] fs = Directory.GetFiles(dir);
            for (int i = 0; i < fs.Length; i++) files.Add(fs[i]);
            dirs.Add(dir);
        }
        catch { }
    }

    static void ShredDir(string dir)
    {
        List<string> files = new List<string>();
        List<string> dirs = new List<string>();
        List<string> links = new List<string>();
        if (forcePerm) ForceOpenOne(dir);
        Collect(dir, files, dirs, links);
        Console.WriteLine();
        Console.WriteLine("[目录] " + dir + "  文件 " + files.Count + " / 子目录 " + dirs.Count + " / 链接 " + links.Count);
        for (int i = 0; i < files.Count; i++) ShredFile(files[i]);
        // 先删重解析点（只删链接本身，不动目标）
        foreach (string l in links)
        {
            if (Directory.Exists(l) || File.Exists(l))
            {
                try { Directory.Delete(l, false); nDirs++; } catch { }
            }
        }
        dirs.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
        foreach (string d in dirs)
        {
            if (!Directory.Exists(d)) { nDirs++; continue; }
            if (Annihilate(d, true)) nDirs++;
            else { nFail++; fails.Add(d); }
        }
    }

    static string logPath = null;
    static string[] rawArgs = null;
    static string DONE_MARK = "__SHREDDER_DONE__";

    static List<string> ParseArgs(string[] args)
    {
        List<string> targets = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string s = a.Trim().Trim('"');
            if (s.Length == 0) continue;
            if (s == "-d" || s == "--deep") { deep = true; continue; }
            if (s == "-q" || s == "--quiet") { quiet = true; continue; }
            if (s == "-k" || s == "--perm") { forcePerm = true; continue; }
            if (s == "-nk" || s == "--noperm") { forcePerm = false; continue; }
            if (s == "-sys" || s == "--system") { sysMode = true; continue; }
            if (s == "-log" || s == "--log")
            {
                if (i + 1 < args.Length) { logPath = args[i + 1].Trim('"'); i++; }
                continue;
            }
            if (s.StartsWith("-p"))
            {
                int v;
                if (int.TryParse(s.Substring(2), out v) && v > 0) passes = v;
                continue;
            }
            if (s.StartsWith("-") && s.Length > 1 && !File.Exists(s) && !Directory.Exists(s)) continue;
            targets.Add(s);
        }
        return targets;
    }

    static string QuoteArgs(string[] args)
    {
        StringBuilder sb = new StringBuilder();
        foreach (string a in args)
        {
            if (sb.Length > 0) sb.Append(' ');
            sb.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
        }
        return sb.ToString();
    }

    static bool Elevate(string[] args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Assembly.GetExecutingAssembly().Location;
            psi.Arguments = QuoteArgs(args);
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }

    // 以 SYSTEM 身份执行：借助计划任务（唯一无需写驱动即可获得 SYSTEM 的可靠途径）
    static void RunAsSystem(string[] args)
    {
        Console.WriteLine("=== 正在以 SYSTEM 身份重新执行 ===");
        string tmpLog = Path.Combine(Path.GetTempPath(), "shredder_sys_" + Guid.NewGuid().ToString("N") + ".log");
        StringBuilder childArgs = new StringBuilder();
        childArgs.Append("-sys -log \"").Append(tmpLog).Append("\"");
        foreach (string a in args)
        {
            string s = a.Trim();
            if (s == "-sys" || s == "--system") continue;
            if (s == "-log" || s == "--log") continue;
            childArgs.Append(' ').Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
        }
        string exe = Assembly.GetExecutingAssembly().Location;
        string tr = "\"" + exe + "\" " + childArgs.ToString();
        string tn = "ShredderSys_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        int rc = RunCmd("schtasks.exe", "/create /tn " + tn + " /tr " + QuoteArgs(new string[] { tr }) + " /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f");
        if (rc != 0)
        {
            rc = RunCmd("schtasks.exe", "/create /tn " + tn + " /tr \"" + tr.Replace("\"", "\\\"") + "\" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f");
        }
        if (rc != 0)
        {
            Console.WriteLine("创建 SYSTEM 计划任务失败（需管理员权限）。将以当前权限继续。");
            return;
        }
        RunCmd("schtasks.exe", "/run /tn " + tn);
        DateTime deadline = DateTime.Now.AddSeconds(900);
        bool finished = false;
        while (DateTime.Now < deadline)
        {
            System.Threading.Thread.Sleep(300);
            try
            {
                if (File.Exists(tmpLog))
                {
                    using (FileStream fs = new FileStream(tmpLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string all = sr.ReadToEnd();
                        if (all.Contains(DONE_MARK)) { finished = true; break; }
                    }
                }
            }
            catch { }
        }
        RunCmd("schtasks.exe", "/delete /tn " + tn + " /f");
        try
        {
            if (File.Exists(tmpLog))
            {
                Console.WriteLine();
                Console.WriteLine("---------- SYSTEM 执行输出 ----------");
                Console.WriteLine(File.ReadAllText(tmpLog, Encoding.UTF8).Replace(DONE_MARK, ""));
                Console.WriteLine("-------------------------------------");
            }
            else Console.WriteLine("未获取到 SYSTEM 执行输出。");
        }
        catch { }
        if (!finished) Console.WriteLine("警告：SYSTEM 任务可能超时未完成。");
    }

    static StreamWriter logWriter = null;

    static void Log(string s)
    {
        Console.WriteLine(s);
        if (logWriter != null) { try { logWriter.WriteLine(s); logWriter.Flush(); } catch { } }
    }

    static void Main(string[] args)
    {
        try { if (Console.IsOutputRedirected) { Console.OutputEncoding = Encoding.UTF8; } } catch { }
        List<string> targets = ParseArgs(args);
        bool interactive = targets.Count == 0;

        if (sysMode && !IsSystem())
        {
            try { SetConsoleOutputCP(65001); } catch { }
            RunAsSystem(args);
            Pause(interactive);
            return;
        }

        if (logPath != null)
        {
            try { logWriter = new StreamWriter(logPath, false, new UTF8Encoding(false)); } catch { }
        }

        try { SetConsoleOutputCP(65001); SetConsoleCP(65001); } catch { }
        Console.Title = "Shredder 2.0";

        if (!IsAdmin())
        {
            Banner();
            Console.WriteLine();
            Console.WriteLine("未获得管理员权限，正在申请提权（会弹出 UAC 确认框）...");
            if (Elevate(args))
            {
                Console.WriteLine("已启动管理员实例，本窗口即将关闭。");
                System.Threading.Thread.Sleep(800);
                return;
            }
            Console.WriteLine("提权失败或已取消。将以当前权限继续（部分顽固目标可能删不掉）。");
        }
        else
        {
            Banner();
        }

        EnablePrivileges();

        if (interactive)
        {
            Console.WriteLine();
            Console.WriteLine("把文件/文件夹拖到本程序图标上即可粉碎，松开即开始。");
            Console.WriteLine("也可以在这里粘贴路径，每行一个，空行结束：");
            string line;
            while ((line = Console.ReadLine()) != null)
            {
                line = line.Trim().Trim('"');
                if (line.Length == 0) break;
                targets.Add(line);
            }
        }

        if (targets.Count == 0) { Log("没有输入路径，退出。"); Finish(); Pause(interactive); return; }

        Log("");
        Log("身份 : " + (IsSystem() ? "SYSTEM (最高权限)" : (IsAdmin() ? "管理员" : "普通用户")));
        Log("模式 : " + (deep ? ("DEEP 深度覆写 x" + passes) : "FAST 极速粉碎") + (forcePerm ? "  +强制夺取权限/属性" : "  (不清权限)"));
        Log("目标 : " + targets.Count + " 项");
        for (int i = 0; i < targets.Count; i++) Log("   [" + (i + 1) + "] " + targets[i]);

        if (interactive)
        {
            Console.Write("输入 YES 回车开始：");
            string ok = Console.ReadLine();
            if (ok == null || ok.Trim().ToUpperInvariant() != "YES") { Log("已取消。"); Finish(); Pause(interactive); return; }
        }

        Log("");
        Stopwatch sw = Stopwatch.StartNew();
        foreach (string t in targets) ProcessTarget(t);
        sw.Stop();
        Log("");
        Report(sw.Elapsed);
        Finish();
        Pause(interactive);
    }

    static void ProcessTarget(string p)
    {
        try
        {
            if (IsProtected(p)) { Log("[保护] 跳过：" + p); return; }
            if (Directory.Exists(p))
            {
                ShredDir(p);
                if (Directory.Exists(p) && forcePerm)
                {
                    Log("");
                    Log("[清权限] 常规删除受阻，整树夺权后重试: " + p);
                    ForcePermTree(p);
                    nPerm++;
                    ShredDir(p);
                }
                return;
            }
            if (File.Exists(p)) { ShredFile(p); return; }
            Log("[跳过] 不存在：" + p);
            nFail++; fails.Add(p + " (not found)");
        }
        catch (Exception ex)
        {
            Log("[错误] " + p + " : " + ex.Message);
            nFail++; fails.Add(p + " : " + ex.Message);
        }
    }

    static void Banner()
    {
        Log("==============================================");
        Log("   Shredder 2.0  -  强力粉碎机 [权限增强版]");
        Log("   拖入即碎 | 夺权 | 强关句柄 | POSIX删除 | 重启后删");
        Log("----------------------------------------------");
        Log("   用法: 拖文件/文件夹到本程序上");
        Log("         Shredder.exe [选项] 路径...");
        Log("   选项: -d 深度覆写   -pN 覆写遍数   -nk 不清权限");
        Log("         -sys 以SYSTEM身份执行(最强,需管理员)");
        Log("   默认: 夺取所有权 -> 清空ACL -> 抹除全部属性");
        Log("         -> 强关占用句柄 -> POSIX立即删除");
        Log("==============================================");
    }

    static void Report(TimeSpan t)
    {
        Log("---------------- 结果 ----------------");
        Log("文件粉碎 : " + nFiles);
        Log("目录删除 : " + nDirs);
        Log("处理数据 : " + Fmt(bytes));
        Log("夺取权限 : " + nPerm);
        Log("强关句柄 : " + nHandles);
        Log("POSIX删除: " + nPosix);
        Log("结束进程 : " + nKilled);
        Log("重启后删 : " + nReboot);
        Log("失败     : " + nFail);
        Log("耗时     : " + t.TotalSeconds.ToString("0.000") + " 秒");
        if (fails.Count > 0)
        {
            Log("---- 未完成清单 ----");
            for (int i = 0; i < fails.Count && i < 50; i++) Log("  ! " + fails[i]);
        }
        Log("--------------------------------------");
    }

    static string Fmt(long b)
    {
        if (b >= 1073741824L) return (b / 1073741824.0).ToString("0.00") + " GB";
        if (b >= 1048576L) return (b / 1048576.0).ToString("0.00") + " MB";
        if (b >= 1024L) return (b / 1024.0).ToString("0.00") + " KB";
        return b + " B";
    }

    static void Finish()
    {
        if (logWriter != null)
        {
            try { logWriter.WriteLine(DONE_MARK); logWriter.Flush(); logWriter.Dispose(); } catch { }
            logWriter = null;
        }
    }

    static void Pause(bool interactive)
    {
        if (!interactive) return;
        try { if (Console.IsInputRedirected || Console.IsOutputRedirected) return; } catch { return; }
        Console.WriteLine();
        Console.Write("按任意键退出...");
        try { Console.ReadKey(true); } catch { }
    }
}
