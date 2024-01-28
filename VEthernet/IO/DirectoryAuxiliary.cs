namespace VEthernet.IO
{
    using System;
    using System.IO;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static class DirectoryAuxiliary
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Exists(string dir)
        {
            if (dir == null)
            {
                return false;
            }
            return Directory.Exists(dir);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Create(string dir) => Create(dir, out string r);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Create(string dir, out string r)
        {
            r = null;
            if (string.IsNullOrEmpty(dir))
            {
                return false;
            }
            DirectoryInfo di = new DirectoryInfo(dir);
            if (di.Exists)
            {
                r = di.FullName;
                return true;
            }
            string current_path = string.Empty;
            foreach (string segment in dir.Split('/', '\\'))
            {
                current_path += segment + "/";
                if (Directory.Exists(segment))
                {
                    continue;
                }
                try
                {
                    Directory.CreateDirectory(current_path);
                }
                catch
                {
                    return false;
                }
            }
            r = current_path;
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Copy(string sourceDirName, string destDirName) =>
            CopyDirectory(sourceDirName, destDirName, true);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool CopyDirectory(string sourceDirName, string destDirName, bool doRootDir)
        {
            if (string.IsNullOrEmpty(sourceDirName) || string.IsNullOrEmpty(destDirName))
            {
                return false;
            }
            if (!Directory.Exists(sourceDirName))
            {
                return false;
            }
            if (sourceDirName == destDirName)
            {
                return false;
            }
            if (!Directory.Exists(destDirName))
            {
                try
                {
                    Directory.CreateDirectory(destDirName);
                }
                catch
                {
                    return false;
                }
            }
            string folderName = doRootDir ? string.Empty : sourceDirName.Substring(sourceDirName.LastIndexOf("\\") + 1);
            string destFolderPath = destDirName + (doRootDir ? string.Empty : "\\" + folderName);
            if (destDirName.LastIndexOf("\\") == (destDirName.Length - 1))
            {
                destFolderPath = destDirName + folderName;
            }
            string[] strFileNames = Directory.GetFileSystemEntries(sourceDirName);
            foreach (string strFileName in strFileNames)
            {
                if (Directory.Exists(strFileName))
                {
                    string currentDirectoryPath = destFolderPath + "\\" + strFileName.Substring(strFileName.LastIndexOf("\\") + 1);
                    if (!Directory.Exists(currentDirectoryPath))
                    {
                        try
                        {
                            Directory.CreateDirectory(currentDirectoryPath);
                        }
                        catch
                        {
                            return false;
                        }
                    }
                    DirectoryAuxiliary.CopyDirectory(strFileName, destFolderPath, false);
                }
                else
                {
                    string srcFileName = strFileName.Substring(strFileName.LastIndexOf("\\") + 1);
                    srcFileName = destFolderPath + "\\" + srcFileName;
                    if (!Directory.Exists(destFolderPath))
                    {
                        Directory.CreateDirectory(destFolderPath);
                    }
                    try
                    {
                        File.Copy(strFileName, srcFileName);
                    }
                    catch { }
                }
            }
            return true;
        }
    }
}
