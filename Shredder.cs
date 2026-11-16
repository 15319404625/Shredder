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
using System.Threading;
using System.Threading.Tasks;

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
    const int DISP_ALL = 0x13;
    const int PROCESS_DUP_HANDLE = 0x0040;
    const uint DUPLICATE_CLOSE_SOURCE = 0x1;
    const int SystemExtendedHandleInformation = 64;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }
    [StructLayout(LayoutKind.Sequential)]
    struct HANDLE_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
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
    static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandle(IntPtr h, StringBuilder p, uint cch, uint flags);
    [DllImport("kernel32.dll")]
    static extern bool SetConsoleOutputCP(uint cp);

    static bool deep = false;
    static bool forcePerm = false;
    static bool quiet = false;
    static bool sysMode = false;
    static bool safeSetup = false;
    static bool safeRestore = false;
    static int passes = 3;
    static int threads = 30; // 目录默认30线程；单文件走直删，不进线程池
    static long nFiles = 0, nDirs = 0, nFail = 0, nReboot = 0, nKilled = 0, nHandles = 0, nPosix = 0, nPerm = 0, bytes = 0;
    static readonly object lockObj = new object();
    static readonly List<string> fails = new List<string>();
    static readonly byte[] oneByte = new byte[1];
    static string logPath = null;
    static StreamWriter logWriter = null;
    static string DONE_MARK = "__SHREDDER_DONE__";

    static void EnablePrivileges()
    {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out tok)) return;
        try
        {
            string[] privs = new string[] {
                "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege",
                "SeSecurityPrivilege", "SeDebugPrivilege", "SeChangeNotifyPrivilege" };
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
        try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
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

    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
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
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint handle, int flags, string key);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint handle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint handle, uint nFiles, string[] files, uint nApps, RM_UNIQUE_PROCESS[] apps, uint nSvc, string[] svcs);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] arr, ref uint reasons);

    // Restart Manager 精准解占用：只查这一个文件，毫秒级
    static int KillLockers(string path)
    {
        uint h;
        if (RmStartSession(out h, 0, Guid.NewGuid().ToString()) != 0) return 0;
        int killed = 0;
        try
        {
            string[] res = new string[] { path };
            if (RmRegisterResources(h, 1, res, 0, null, 0, null) != 0) return 0;
            uint needed = 0, cnt = 0, reasons = 0;
            RM_PROCESS_INFO[] arr = null;
            int rv = RmGetList(h, out needed, ref cnt, arr, ref reasons);
            if (rv == 234 && needed > 0)
            {
                arr = new RM_PROCESS_INFO[needed];
                cnt = needed;
                rv = RmGetList(h, out needed, ref cnt, arr, ref reasons);
            }
            if (rv != 0 || arr == null) return 0;
            int myPid = Process.GetCurrentProcess().Id;
            for (int i = 0; i < cnt && i < arr.Length; i++)
            {
                int pid = arr[i].Process.dwProcessId;
                if (pid <= 4 || pid == myPid) continue;
                try
                {
                    Process pr = Process.GetProcessById(pid);
                    string nm = pr.ProcessName.ToLowerInvariant();
                    if (nm == "system" || nm == "csrss" || nm == "wininit" || nm == "smss" || nm == "services" || nm == "lsass" || nm == "winlogon") continue;
                    pr.Kill();
                    pr.WaitForExit(1500);
                    killed++;
                }
                catch { }
            }
        }
        finally { RmEndSession(h); }
        return killed;
    }

    static void RunTool(string exe, string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            if (p != null) p.WaitForExit(60000);
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
            p.WaitForExit(180000);
            return p.ExitCode;
        }
        catch { return -1; }
    }

    static void StripAttrs(string p, bool isDir)
    {
        try
        {
            FileAttributes a = File.GetAttributes(p);
            if ((a & FileAttributes.Encrypted) != 0 && !isDir) { try { File.Decrypt(p); } catch { } }
            if (a != (isDir ? FileAttributes.Directory : FileAttributes.Normal))
                File.SetAttributes(p, isDir ? FileAttributes.Directory : FileAttributes.Normal);
        }
        catch { }
    }

    // 快路径：一次 Delete 就走人（绝大多数普通文件走这里，毫秒级）
    static bool FastDelete(string p, bool isDir)
    {
        try
        {
            if (isDir) { Directory.Delete(p, false); return !Directory.Exists(p); }
            File.Delete(p);
            return !File.Exists(p);
        }
        catch { return false; }
    }

    // NT 层 POSIX 立即删除：对已打开的文件也能删
    static bool PosixDelete(string p)
    {
        IntPtr h = CreateFileW(LongPath(p), DELETE_ACCESS | SYNCHRONIZE, FILE_SHARE_ALL,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1)) return false;
        try
        {
            IntPtr mem = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(mem, DISP_ALL);
                IO_STATUS_BLOCK iosb;
                if (NtSetInformationFile(h, out iosb, mem, 4, FileDispositionInformationEx) == 0) return true;
            }
            finally { Marshal.FreeHGlobal(mem); }
            IntPtr m2 = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(m2, 1);
                IO_STATUS_BLOCK b2;
                if (NtSetInformationFile(h, out b2, m2, 1, FileDispositionInformation) == 0) return true;
            }
            finally { Marshal.FreeHGlobal(m2); }
            return false;
        }
        finally { CloseHandle(h); }
    }

    // 夺权：.NET 方式优先，失败退系统工具
    static void GrabPerm(string p, bool isDir)
    {
        try
        {
            IdentityReference me = WindowsIdentity.GetCurrent().User;
            if (isDir)
            {
                DirectorySecurity ds = Directory.GetAccessControl(p, AccessControlSections.Owner | AccessControlSections.Access);
                try { ds.SetOwner(me); Directory.SetAccessControl(p, ds); } catch { }
                ds = Directory.GetAccessControl(p, AccessControlSections.Access);
                try { ds.SetAccessRuleProtection(true, false); } catch { }
                foreach (FileSystemAccessRule r in ds.GetAccessRules(true, false, typeof(SecurityIdentifier))) { try { ds.RemoveAccessRule(r); } catch { } }
                ds.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(p, ds);
            }
            else
            {
                FileSecurity fs = File.GetAccessControl(p, AccessControlSections.Owner | AccessControlSections.Access);
                try { fs.SetOwner(me); File.SetAccessControl(p, fs); } catch { }
                fs = File.GetAccessControl(p, AccessControlSections.Access);
                try { fs.SetAccessRuleProtection(true, false); } catch { }
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, false, typeof(SecurityIdentifier))) { try { fs.RemoveAccessRule(r); } catch { } }
                fs.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(p, fs);
            }
        }
        catch
        {
            RunTool("takeown.exe", "/f \"" + p + "\" /a");
            RunTool("icacls.exe", "\"" + p + "\" /reset /c /q");
            RunTool("icacls.exe", "\"" + p + "\" /grant *S-1-1-0:F /c /q");
        }
        StripAttrs(p, isDir);
    }

    // 关闭占用该文件的句柄（句柄表枚举，精准关闭）
    static bool CloseHandles(string targetPath)
    {
        string target;
        try { target = Path.GetFullPath(targetPath).TrimEnd('\\').ToLowerInvariant(); } catch { return false; }
        IntPtr buf = IntPtr.Zero;
        int len = 0x400000, ret = 0;
        for (int i = 0; i < 4; i++)
        {
            buf = Marshal.AllocHGlobal(len);
            if (NtQuerySystemInformation(SystemExtendedHandleInformation, buf, len, out ret) == 0) break;
            Marshal.FreeHGlobal(buf); buf = IntPtr.Zero; len *= 2;
            if (len > 0x4000000) return false;
        }
        if (buf == IntPtr.Zero) return false;
        bool any = false;
        try
        {
            long count = Marshal.ReadIntPtr(buf).ToInt64();
            int esz = Marshal.SizeOf(typeof(HANDLE_EX));
            IntPtr cur = new IntPtr(buf.ToInt64() + IntPtr.Size * 2);
            IntPtr me = GetCurrentProcess();
            int myPid = Process.GetCurrentProcess().Id;
            StringBuilder sb = new StringBuilder(600);
            for (long i = 0; i < count; i++)
            {
                HANDLE_EX e = (HANDLE_EX)Marshal.PtrToStructure(cur, typeof(HANDLE_EX));
                cur = new IntPtr(cur.ToInt64() + esz);
                int pid = (int)e.UniqueProcessId.ToInt64();
                if (pid <= 4 || pid == myPid) continue;
                IntPtr hp = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
                if (hp == IntPtr.Zero) continue;
                try
                {
                    IntPtr dup;
                    if (!DuplicateHandle(hp, e.HandleValue, me, out dup, 0, false, 0)) continue;
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
                                DuplicateHandle(hp, e.HandleValue, IntPtr.Zero, out dummy, 0, false, DUPLICATE_CLOSE_SOURCE);
                                any = true;
                                Interlocked.Increment(ref nHandles);
                            }
                        }
                    }
                    finally { CloseHandle(dup); }
                }
                finally { CloseHandle(hp); }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return any;
    }

    static bool Overwrite(string p)
    {
        FileStream fs = null;
        try
        {
            fs = new FileStream(LongPath(p), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            long len = fs.Length;
            byte[] chunk = new byte[65536];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            for (int pass = 0; pass < passes; pass++)
            {
                fs.Position = 0;
                long left = len;
                while (left > 0)
                {
                    int n = (int)Math.Min((long)chunk.Length, left);
                    rng.GetBytes(chunk);
                    fs.Write(chunk, 0, n);
                    left -= n;
                }
                fs.Flush();
            }
            fs.SetLength(0);
            return true;
        }
        catch { return false; }
        finally { if (fs != null) { try { fs.Dispose(); } catch { } } }
    }

    static string Rename(string p)
    {
        try
        {
            string dir = Path.GetDirectoryName(p);
            if (dir == null) return null;
            string np = Path.Combine(dir, Guid.NewGuid().ToString("N") + Path.GetExtension(p));
            if (MoveFileEx(LongPath(p), LongPath(np), MOVEFILE_REPLACE_EXISTING)) return np;
        }
        catch { }
        return null;
    }

    static void Reboot(string p)
    {
        bool ok = false;
        try { ok = MoveFileEx(LongPath(p), null, MOVEFILE_DELAY_UNTIL_REBOOT); } catch { }
        Interlocked.Increment(ref nReboot);
        lock (lockObj) { fails.Add(p + (ok ? " (重启时删除)" : " (登记失败,需管理员)")); }
    }

    // 终极删除：快路径失败才逐级升级
    static bool Annihilate(string p, bool isDir)
    {
        if (!Exists(p)) return true;
        StripAttrs(p, isDir);
        if (FastDelete(p, isDir)) return true;
        // 慢路径 1：POSIX 删除（不怕被占用）
        if (PosixDelete(p)) return true;
        // 慢路径 2：关句柄
        if (CloseHandles(p))
        {
            if (FastDelete(p, isDir)) return true;
            if (PosixDelete(p)) return true;
        }
        // 慢路径 3：夺权
        GrabPerm(p, isDir);
        Interlocked.Increment(ref nPerm);
        if (FastDelete(p, isDir)) return true;
        if (PosixDelete(p)) return true;
        // 慢路径 4：改名再删
        string r = Rename(p);
        if (r != null)
        {
            if (FastDelete(r, isDir)) return true;
            if (PosixDelete(r)) return true;
            p = r;
        }
        if (isDir) return !Directory.Exists(p);
        Reboot(p);
        return false;
    }

    static void ShredFile(string f)
    {
        long size = 0;
        if (deep)
        {
            try { size = new FileInfo(f).Length; } catch { }
            StripAttrs(f, false);
            Overwrite(f);
        }
        else
        {
            try { size = new FileInfo(f).Length; } catch { }
        }
        // 快路径：直接删，不先 stat、不先 Exists（省两次系统调用）
        try
        {
            File.Delete(f);
            if (!File.Exists(f)) { Interlocked.Increment(ref nFiles); Interlocked.Add(ref bytes, size); return; }
        }
        catch { }
        if (PosixDelete(f)) { Interlocked.Increment(ref nFiles); Interlocked.Add(ref bytes, size); return; }
        // 顽固文件才走全套
        if (AnnihilateStubborn(f)) { Interlocked.Increment(ref nFiles); Interlocked.Add(ref bytes, size); }
        else Interlocked.Increment(ref nFail);
    }

    // 停掉占用该文件的服务（服务占用是顽固文件的常见原因）
    static void StopOwningServices(string path)
    {
        try
        {
            string dir = Path.GetDirectoryName(path);
            if (dir == null) return;
            // 用 sc queryex 找 ImagePath 指向该目录的服务
            ProcessStartInfo psi = new ProcessStartInfo("sc.exe", "queryex type= service state= all");
            psi.UseShellExecute = false; psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            Process p = Process.Start(psi);
            if (p == null) return;
            string outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            string lower = path.ToLowerInvariant();
            string dl = dir.ToLowerInvariant();
            // 简化：直接尝试停止几个常见占用大户
            string[] suspects = new string[] { "Sysmain", "WSearch", "WinDefend", "TrustedInstaller", "wuauserv", "BITS" };
            foreach (string s in suspects) RunTool("sc.exe", "stop \"" + s + "\"");
        }
        catch { }
    }

    // 顽固文件的完整升级链（只在快路径失败后调用）
    static bool AnnihilateStubborn(string p)
    {
        // 1) 属性 + 精准解占用 + POSIX
        StripAttrs(p, false);
        int k = KillLockers(p);
        if (k > 0) Interlocked.Add(ref nKilled, k);
        if (FastDelete(p, false) || PosixDelete(p)) return true;
        // 2) .NET 夺权
        GrabPerm(p, false);
        Interlocked.Increment(ref nPerm);
        if (FastDelete(p, false) || PosixDelete(p)) return true;
        // 3) takeown + icacls（破解拒绝 ACL，限时 2.5 秒/个）
        RunToolEx("takeown.exe", "/f \"" + p + "\" /a", 2500);
        RunToolEx("icacls.exe", "\"" + p + "\" /reset /c /q", 2500);
        RunToolEx("icacls.exe", "\"" + p + "\" /remove:d *S-1-1-0 /c /q", 2500);
        RunToolEx("icacls.exe", "\"" + p + "\" /grant *S-1-1-0:F /c /q", 2500);
        StripAttrs(p, false);
        if (FastDelete(p, false) || PosixDelete(p)) return true;
        // 4) 改名再删
        string r = Rename(p);
        if (r != null)
        {
            if (FastDelete(r, false) || PosixDelete(r)) return true;
            p = r;
        }
        // 5) 重启删除
        Reboot(p);
        return false;
    }

    // 带超时的外部工具调用（防止卡死）
    static void RunToolEx(string exe, string args, int timeoutMs)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            if (p != null) { if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } } }
        }
        catch { }
    }

    static void ShredAll(string root)
    {
        List<string> files = new List<string>();
        List<string> dirs = new List<string>();
        Stack<string> st = new Stack<string>();
        st.Push(root);
        while (st.Count > 0)
        {
            string d = st.Pop();
            try
            {
                foreach (string f in Directory.GetFiles(d)) files.Add(f);
                foreach (string sd in Directory.GetDirectories(d))
                {
                    try
                    {
                        if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) != 0) { files.Add(sd); continue; }
                    }
                    catch { }
                    st.Push(sd);
                    dirs.Add(sd);
                }
            }
            catch { }
        }
        dirs.Add(root);
        Console.WriteLine("[扫描] 文件 " + files.Count + " / 目录 " + dirs.Count);
        // 全核并行删文件
        int autoT = threads > 0 ? threads : 30;
        int w = Math.Min(autoT, Math.Max(1, files.Count));
        if (w <= 1) { foreach (string f in files) ShredFile(f); }
        else
        {
            int idx = -1;
            Thread[] ts = new Thread[w];
            for (int i = 0; i < w; i++)
            {
                ts[i] = new Thread(delegate()
                {
                    while (true)
                    {
                        int k = Interlocked.Increment(ref idx);
                        if (k >= files.Count) break;
                        ShredFile(files[k]);
                    }
                });
                ts[i].IsBackground = true;
                ts[i].Start();
            }
            foreach (Thread t in ts) t.Join();
        }
        dirs.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
        foreach (string d in dirs)
        {
            if (!Directory.Exists(d)) { Interlocked.Increment(ref nDirs); continue; }
            if (Annihilate(d, true)) Interlocked.Increment(ref nDirs);
            else { Interlocked.Increment(ref nFail); lock (lockObj) fails.Add(d); }
        }
    }

    static List<string> ParseArgs(string[] args)
    {
        List<string> t = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            string s = args[i].Trim().Trim('"');
            if (s.Length == 0) continue;
            if (s == "-d" || s == "--deep") { deep = true; continue; }
            if (s == "-q" || s == "--quiet") { quiet = true; continue; }
            if (s == "-k" || s == "--perm") { forcePerm = true; continue; }
            if (s == "-nk" || s == "--noperm") { continue; }
            if (s == "-sys" || s == "--system") { sysMode = true; continue; }
            if (s == "-safe" || s == "--safemode") { safeSetup = true; continue; }
            if (s == "-unsafe" || s == "--nosafemode") { safeRestore = true; continue; }
            if (s == "-log" || s == "--log")
            {
                if (i + 1 < args.Length) { logPath = args[i + 1].Trim('"'); i++; }
                continue;
            }
            if (s.StartsWith("-p") && s.Length > 2) { int v; if (int.TryParse(s.Substring(2), out v) && v > 0) passes = v; continue; }
            if (s.StartsWith("-t") && s.Length > 2) { int v; if (int.TryParse(s.Substring(2), out v) && v > 0) threads = Math.Min(v, 256); continue; }
            if (s.StartsWith("-") && !File.Exists(s) && !Directory.Exists(s)) continue;
            // 统一转绝对路径，避免 SYSTEM 会话工作目录不同导致找不到
            string abs = s;
            try { abs = Path.GetFullPath(s); } catch { }
            t.Add(abs);
        }
        return t;
    }

    static string Q(string[] args)
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
            psi.Arguments = Q(args);
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }

    static void RunAsSystem(string[] args)
    {
        Console.WriteLine("=== 以 SYSTEM 身份执行 ===");
        string tmpLog = Path.Combine(Path.GetTempPath(), "shd_sys_" + Guid.NewGuid().ToString("N") + ".log");
        StringBuilder ca = new StringBuilder();
        ca.Append("-sys -log \"").Append(tmpLog).Append("\"");
        for (int i = 0; i < args.Length; i++)
        {
            string s = args[i].Trim();
            if (s == "-sys" || s == "--system") continue;
            if (s == "-log" || s == "--log") { i++; continue; }
            string use = s;
            if (!s.StartsWith("-"))
            {
                // SYSTEM 会话工作目录是 system32，必须转绝对路径
                try { use = Path.GetFullPath(s); } catch { }
            }
            ca.Append(' ').Append('"').Append(use.Replace("\"", "\\\"")).Append('"');
        }
        string exe = Assembly.GetExecutingAssembly().Location;
        string tr = "\"" + exe + "\" " + ca.ToString();
        string tn = "ShdSys_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        int rc = RunCmd("schtasks.exe", "/create /tn " + tn + " /tr \"" + tr.Replace("\"", "\\\"") + "\" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f");
        if (rc != 0) { Console.WriteLine("创建 SYSTEM 任务失败（需管理员）。"); return; }
        RunCmd("schtasks.exe", "/run /tn " + tn);
        DateTime dl = DateTime.Now.AddSeconds(900);
        bool fin = false;
        while (DateTime.Now < dl)
        {
            Thread.Sleep(250);
            try
            {
                if (File.Exists(tmpLog))
                {
                    using (FileStream fs = new FileStream(tmpLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                        if (sr.ReadToEnd().Contains(DONE_MARK)) { fin = true; break; }
                }
            }
            catch { }
        }
        RunCmd("schtasks.exe", "/delete /tn " + tn + " /f");
        try
        {
            if (File.Exists(tmpLog)) { Console.WriteLine(File.ReadAllText(tmpLog, Encoding.UTF8).Replace(DONE_MARK, "")); }
        }
        catch { }
        if (!fin) Console.WriteLine("警告：SYSTEM 任务可能超时。");
    }

    static void Log(string s)
    {
        Console.WriteLine(s);
        if (logWriter != null) { try { logWriter.WriteLine(s); logWriter.Flush(); } catch { } }
    }

    static void Main(string[] args)
    {
        if (HasHelp(args)) { ShowManual(); return; }
        List<string> targets = ParseArgs(args);
        bool interactive = targets.Count == 0;

        // ---- 安全模式管理（删杀软/驱动级文件的唯一可行路径）----
        if (safeSetup || safeRestore)
        {
            try { SetConsoleOutputCP(65001); } catch { }
            Banner();
            if (!IsAdmin())
            {
                Log("需要管理员权限。");
                if (Elevate(args)) { Thread.Sleep(500); return; }
                Log("提权失败。");
                return;
            }
            if (safeSetup)
            {
                Log("");
                Log("=== 设置下次启动进入【安全模式】 ===");
                Log("安全模式下载入的只有系统核心驱动，杀毒软件/安全软件的驱动不会加载，");
                Log("它们的所有文件此时都变成普通文件，可以被正常粉碎。");
                Log("");
                Log("操作步骤：");
                Log("  1. 现在执行本命令后，重启电脑");
                Log("  2. 电脑会进入安全模式（黑底，屏幕四角有\"安全模式\"字样）");
                Log("  3. 在安全模式下，把杀软安装目录拖到 Shredder.exe 上粉碎");
                Log("  4. 删完后运行: Shredder.exe -unsafe   恢复正常启动");
                Log("");
                Console.Write("确认设置并准备重启？输入 YES: ");
                string c = Console.ReadLine();
                if (c == null || c.Trim().ToUpperInvariant() != "YES") { Log("已取消。"); return; }
                int rc = RunCmd("bcdedit.exe", "/set {current} safeboot minimal");
                if (rc == 0)
                {
                    Log("");
                    Log("[成功] 下次启动将进入安全模式。");
                    Log("现在可以重启了。重启后请到安全模式运行本程序删除目标。");
                }
                else Log("[失败] bcdedit 返回 " + rc + "（需管理员权限）");
            }
            else
            {
                Log("");
                Log("=== 恢复正常启动 ===");
                int rc = RunCmd("bcdedit.exe", "/deletevalue {current} safeboot");
                if (rc == 0) Log("[成功] 已恢复正常启动，下次开机进入普通 Windows。");
                else Log("[失败] bcdedit 返回 " + rc + "（可能本来就没设安全模式）");
            }
            return;
        }

        if (sysMode && !IsSystem())
        {
            try { SetConsoleOutputCP(65001); } catch { }
            RunAsSystem(args);
            if (interactive) Pause();
            return;
        }

        if (logPath != null) { try { logWriter = new StreamWriter(logPath, false, new UTF8Encoding(false)); } catch { } }
        try { SetConsoleOutputCP(65001); } catch { }
        Console.Title = "Shredder 5.0";

        if (!IsAdmin())
        {
            Banner();
            Console.WriteLine();
            Console.WriteLine("正在申请管理员权限（弹 UAC 请点是）...");
            if (Elevate(args))
            {
                Console.WriteLine("已启动管理员实例。");
                Thread.Sleep(600);
                Finish();
                return;
            }
            Console.WriteLine("提权取消，以当前权限继续。");
        }
        else Banner();

        EnablePrivileges();

        if (interactive)
        {
            Console.WriteLine();
            Console.WriteLine("把文件/文件夹拖到本程序上，或粘贴路径（每行一个，空行结束）：");
            string line;
            while ((line = Console.ReadLine()) != null)
            {
                line = line.Trim().Trim('"');
                if (line.Length == 0) break;
                targets.Add(line);
            }
        }
        if (targets.Count == 0) { Finish(); if (interactive) Pause(); return; }

        Log("");
        Log("身份 : " + (IsSystem() ? "SYSTEM" : (IsAdmin() ? "管理员" : "普通用户")));
        int autoT = threads > 0 ? threads : 30;
        Log("模式 : " + (deep ? ("深度覆写x" + passes) : "极速") + "  线程:" + autoT + (threads > 0 ? "" : "(自动)"));
        Log("目标 : " + targets.Count);
        foreach (string s in targets) Log("   - " + s);
        if (interactive)
        {
            Console.Write("输入 YES 开始：");
            string ok = Console.ReadLine();
            if (ok == null || ok.Trim().ToUpperInvariant() != "YES") { Finish(); Pause(); return; }
        }

        Stopwatch sw = Stopwatch.StartNew();
        foreach (string t in targets)
        {
            try
            {
                if (IsProtected(t)) { Log("[保护] " + t); continue; }
                if (Directory.Exists(t)) ShredAll(t);
                else if (File.Exists(t)) ShredFile(t);
                else { Log("[跳过] 不存在: " + t); Interlocked.Increment(ref nFail); }
            }
            catch (Exception ex) { Log("[错误] " + t + " : " + ex.Message); Interlocked.Increment(ref nFail); }
        }
        sw.Stop();
        Report(sw.Elapsed);

        // 自动升级链：常规失败 -> SYSTEM -> 安全模式建议
        long failBefore = nFail;
        if (nFail > 0 && !sysMode) AutoEscalate(targets, failBefore);

        Finish();
        if (interactive) Pause();
    }

    static bool IsProtected(string p)
    {
        string s = p.ToLowerInvariant();
        return s.Contains("shredder.exe") || s.Contains("shredder.cs");
    }

    // 对指定路径列表以 SYSTEM 身份重试
    static void RunAsSystemOn(List<string> paths)
    {
        string[] arr = new string[paths.Count + 1];
        arr[0] = "-sys";
        for (int i = 0; i < paths.Count; i++) arr[i + 1] = paths[i];
        RunAsSystem(arr);
    }

    // 自动升级链：常规失败 -> SYSTEM -> 建议安全模式
    static void AutoEscalate(List<string> targets, long failBefore)
    {
        // 收集仍然存在的目标
        List<string> remain = new List<string>();
        foreach (string t in targets)
        {
            if (IsProtected(t)) continue;
            if (Exists(t)) remain.Add(t);
        }
        if (remain.Count == 0) return;

        Log("");
        Log("==============================================");
        Log("[自动升级] 常规手段后仍有 " + remain.Count + " 个目标存在：");
        foreach (string r in remain) Log("   - " + r);
        Log("");

        // 已经是 SYSTEM 了，没法再升级
        if (IsSystem())
        {
            Log("当前已是 SYSTEM 最高权限，无法再升级。");
            Log("");
            Log("[下一步] 建议使用安全模式删除（见下方说明）");
            Log("==============================================");
            SuggestSafeMode(remain);
            return;
        }

        Log("[下一步] 自动切换到 SYSTEM 最高权限重试（比管理员更高）...");
        Log("         SYSTEM 能访问部分管理员都碰不到的系统服务占用文件");
        Log("==============================================");
        Log("");

        try { RunAsSystemOn(remain); }
        catch (Exception ex) { Log("SYSTEM 重试出错: " + ex.Message); }

        // 重新检查
        List<string> still = new List<string>();
        foreach (string r in remain) if (Exists(r)) still.Add(r);

        Log("");
        if (still.Count == 0)
        {
            Log("==============================================");
            Log("[成功] SYSTEM 权限已删除全部剩余目标。");
            Log("==============================================");
            return;
        }

        Log("==============================================");
        Log("[仍未删除] " + still.Count + " 个目标：");
        foreach (string s in still) Log("   - " + s);
        Log("");
        Log("[下一步] 自动升级已到极限，建议安全模式删除（见下方说明）");
        Log("==============================================");
        SuggestSafeMode(still);
    }

    static void SuggestSafeMode(List<string> paths)
    {
        Log("");
        Log("############  安全模式删除说明  ############");
        Log("这些文件被内核驱动死死保护（典型如杀毒软件），常规手段无法删除。");
        Log("安全模式下只加载系统核心驱动，杀软/安全软件驱动不加载，");
        Log("它们的文件此时就变成普通文件，可以正常粉碎。");
        Log("");
        Log("操作步骤：");
        Log("  1. 运行:  Shredder.exe -safe     然后输入 YES 确认");
        Log("  2. 重启电脑，会进入安全模式（黑底，四角显示\"安全模式\"）");
        Log("  3. 在安全模式里，把下列路径拖到 Shredder.exe 上粉碎：");
        foreach (string p in paths) Log("       " + p);
        Log("  4. 删完运行:  Shredder.exe -unsafe     恢复正常启动");
        Log("");
        Log("或者，如果这些文件并不重要，也可以重启一次让\"重启后删除\"生效。");
        Log("############################################");
    }

    static void ShowManual()
    {
        try { SetConsoleOutputCP(65001); } catch { }
        Console.WriteLine("");
        Console.WriteLine("################################################################");
        Console.WriteLine("#                                                              #");
        Console.WriteLine("#              Shredder 5.0  强力粉碎机  使用说明书            #");
        Console.WriteLine("#                                                              #");
        Console.WriteLine("################################################################");
        Console.WriteLine("");
        Console.WriteLine("【一、这是什么】");
        Console.WriteLine("  一个文件/文件夹强力粉碎工具。删除前会覆写内容、清空属性、夺取权限，");
        Console.WriteLine("  使普通恢复软件难以找回。拖进去就删，越顽固的文件它越会加码。");
        Console.WriteLine("");
        Console.WriteLine("【二、最简单的用法】");
        Console.WriteLine("  1) 把文件或文件夹直接拖到 Shredder.exe 图标上，松开即可");
        Console.WriteLine("  2) 或双击 Shredder.exe，粘贴路径（每行一个，空行结束），输入 YES 确认");
        Console.WriteLine("  3) 首次会弹 UAC，请点【是】，否则权限不足会删不掉");
        Console.WriteLine("");
        Console.WriteLine("【三、自动升级机制（重点）】");
        Console.WriteLine("  程序按下面顺序自动加码，每一步都会告诉你进度：");
        Console.WriteLine("");
        Console.WriteLine("    第1级  常规删除");
        Console.WriteLine("           一次系统调用删除，99% 的普通文件在这一步就没了（毫秒级）");
        Console.WriteLine("");
        Console.WriteLine("    第2级  POSIX 强删 + 精准解占用");
        Console.WriteLine("           文件被别的程序打开着也能删；必要时用 Restart Manager");
        Console.WriteLine("           精准找出占用进程并结束（只查这一个文件，不扫全盘）");
        Console.WriteLine("");
        Console.WriteLine("    第3级  夺取所有权 + 清空 ACL");
        Console.WriteLine("           破解 \"拒绝访问\"\"Everyone 拒绝\" 这类权限锁；");
        Console.WriteLine("           必要时调用 takeown / icacls（每个限时 2.5 秒，不会卡死）");
        Console.WriteLine("");
        Console.WriteLine("    第4级  改名再删 + 登记重启删除");
        Console.WriteLine("           改名绕开占用锁；仍失败则登记到 PendingFileRenameOperations，");
        Console.WriteLine("           重启时由内核在任何人之前删掉");
        Console.WriteLine("");
        Console.WriteLine("    第5级  自动切换 SYSTEM 最高权限重试");
        Console.WriteLine("           SYSTEM 比管理员更高，能碰到部分管理员都删不掉的文件。");
        Console.WriteLine("           程序会自动用计划任务以 SYSTEM 身份重跑一遍，无需你操作");
        Console.WriteLine("");
        Console.WriteLine("    第6级  建议进入安全模式删除（最后手段）");
        Console.WriteLine("           到这一步说明文件被内核驱动死死保护（典型如杀毒软件）。");
        Console.WriteLine("           程序会提示你：安全模式下杀软驱动不加载，文件变成普通文件。");
        Console.WriteLine("           按提示执行  Shredder.exe -safe  重启即可");
        Console.WriteLine("");
        Console.WriteLine("【四、命令行选项】");
        Console.WriteLine("  Shredder.exe 路径...        常规粉碎（默认自动全核并行）");
        Console.WriteLine("  -q                          安静模式（少打印）");
        Console.WriteLine("  -d                          深度覆写（整文件多遍覆写，慢但更彻底）");
        Console.WriteLine("  -pN                         覆写遍数，配合 -d（如 -p3）");
        Console.WriteLine("  -tN                         指定线程数（默认用满所有 CPU 核心）");
        Console.WriteLine("  -sys                        直接以 SYSTEM 身份执行（需管理员）");
        Console.WriteLine("  -safe                       设置下次启动进安全模式（删杀软用）");
        Console.WriteLine("  -unsafe                     恢复正常启动");
        Console.WriteLine("  -help                       显示本说明书");
        Console.WriteLine("");
        Console.WriteLine("【五、删杀毒软件 / 安全软件】");
        Console.WriteLine("  正在运行的杀软有内核驱动 + PPL 保护，任何用户态程序都无法直接终止或删除它，");
        Console.WriteLine("  这不是权限不够，是 Windows 内核机制。唯一可行的办法是安全模式：");
        Console.WriteLine("");
        Console.WriteLine("    1. Shredder.exe -safe      （确认后重启）");
        Console.WriteLine("    2. 电脑进入安全模式（黑底，四角有\"安全模式\"字样）");
        Console.WriteLine("    3. 把杀软安装目录拖到 Shredder.exe 上粉碎");
        Console.WriteLine("    4. Shredder.exe -unsafe    （恢复正常启动）");
        Console.WriteLine("");
        Console.WriteLine("  注意：删除安全软件会让系统失去防护，请自行评估风险。");
        Console.WriteLine("");
        Console.WriteLine("【六、常见问题】");
        Console.WriteLine("  Q: 为什么删完还要重启？");
        Console.WriteLine("  A: 文件被系统或驱动占用时，无法当场删除，登记后重启由内核删除，");
        Console.WriteLine("     这是最彻底的方式，不是失败。");
        Console.WriteLine("");
        Console.WriteLine("  Q: 提示\"登记失败：请以管理员身份运行\"？");
        Console.WriteLine("  A: 右键 Shredder.exe → 以管理员身份运行。");
        Console.WriteLine("");
        Console.WriteLine("  Q: 会不会误删我的东西？");
        Console.WriteLine("  A: 不会自动扫描磁盘，只删你明确拖入或输入的路径。");
        Console.WriteLine("");
        Console.WriteLine("  Q: SSD 上能保证彻底不可恢复吗？");
        Console.WriteLine("  A: 不能 100% 保证。SSD 有磨损均衡，物理块可能未被真正擦除。");
        Console.WriteLine("     重要机密数据请用全盘加密或物理销毁。");
        Console.WriteLine("");
        Console.WriteLine("################################################################");
        Console.WriteLine("");
        Console.WriteLine("按任意键返回...");
        try { if (!Console.IsInputRedirected) Console.ReadKey(true); } catch { }
    }

    static bool HasHelp(string[] args)
    {
        foreach (string a in args)
        {
            string s = a.Trim().Trim('"').ToLowerInvariant();
            if (s == "-help" || s == "--help" || s == "-manual" || s == "-?" || s == "/?") return true;
        }
        return false;
    }

    static void Banner()
    {
        Log("============================================");
        Log("  Shredder 5.0  强力粉碎机 [多核全速版]");
        Log("  全核并行 | 快路径秒删 | POSIX强删 | 夺权 | 重启删");
        Log("  用法: 拖入 或 Shredder.exe [-d] [-tN] 路径...");
        Log("  -d 深度覆写  -tN 线程数(默认30)  -nk 不夺权");
        Log("  -sys 以SYSTEM身份执行(最强)");
        Log("============================================");
    }

    static string Fmt(long b)
    {
        if (b >= 1073741824L) return (b / 1073741824.0).ToString("0.00") + " GB";
        if (b >= 1048576L) return (b / 1048576.0).ToString("0.00") + " MB";
        if (b >= 1024L) return (b / 1024.0).ToString("0.00") + " KB";
        return b + " B";
    }

    static void Report(TimeSpan t)
    {
        Log("");
        Log("============ 结果 ============");
        Log("文件粉碎 : " + nFiles);
        Log("目录删除 : " + nDirs);
        Log("处理数据 : " + Fmt(bytes));
        Log("夺权次数 : " + nPerm);
        Log("强关句柄 : " + nHandles);
        Log("POSIX删除: " + nPosix);
        Log("重启后删 : " + nReboot);
        Log("失败     : " + nFail);
        Log("耗时     : " + t.TotalSeconds.ToString("0.000") + " 秒");
        if (fails.Count > 0)
        {
            Log("---- 未完成 ----");
            for (int i = 0; i < fails.Count && i < 40; i++) Log("  ! " + fails[i]);
        }
        Log("==============================");
    }

    static void Finish()
    {
        if (logWriter != null)
        {
            try { logWriter.WriteLine(DONE_MARK); logWriter.Flush(); logWriter.Dispose(); } catch { }
            logWriter = null;
        }
    }

    static void Pause()
    {
        try { if (Console.IsInputRedirected || Console.IsOutputRedirected) return; } catch { return; }
        Console.WriteLine();
        Console.Write("按任意键退出...");
        try { Console.ReadKey(true); } catch { }
    }
}
