//using CmdLine;
//using CommandLine;
using CommandLine;
using CommandLine.Text;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ForceDelete
{
    class Program
    {
        static void Main(string[] args)
        {
            args = new string[] { "-s", @"dee8e" };
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                bool isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
                if (!isElevated)
                {
                    Console.Error.WriteLine("Error, must run ForceDelete as an administrator.");
                    return;
                }
            }

            AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
            {
                string fileName = new AssemblyName(resolveArgs.Name).Name + ".dll";

                List<string> otherFileNameBases = Kernel32Api.GetFileSiblingHardLinks(Assembly.GetCallingAssembly().Location).ToList();
                foreach (string otherFileNameBase in otherFileNameBases)
                {
                    string otherFileName = Path.Combine(Path.GetDirectoryName(otherFileNameBase), fileName);
                    if (File.Exists(otherFileName))
                    {
                        //Console.WriteLine($"Loading assembly {otherFileName}");
                        return Assembly.Load(File.ReadAllBytes(otherFileName));
                    }
                }

                throw new Exception($"Cannot find assembly {fileName}, searched:\n{string.Join("", otherFileNameBases.Select(x => "\t" + x + "\n"))}");
            };
            Main2(args);
        }
        static void Main2(string[] args)
        {
            var options = CommandLine.Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(Run);
        }



        static string GetPid(string handleOutput)
        {
            string str = handleOutput;
            str = str.Substring(str.IndexOf("pid: ") + "pid: ".Length);
            str = str.Substring(0, str.IndexOf(" "));
            return str;
        }
        static string GetPath(string handleOutput)
        {
            string str = handleOutput;
            str = str.Substring(str.IndexOf("type: File") + "type: File".Length);
            str = str.Substring(str.IndexOf(":") + 2);
            return str;
        }
        static string FormatSize(ulong size)
        {
            if(size >= 1024 * 1024 * 1024)
            {
                return (((double)size) / (1024 * 1024 * 1024)).ToString("0.0GB");
            }
            if (size >= 1024 * 1024)
            {
                return (((double)size) / (1024 * 1024)).ToString("0.0MB");
            }
            if (size >= 1024)
            {
                return (((double)size) / (1024)).ToString("0.0KB");
            }
            return (((double)size) / (1)).ToString("0.0B");
        }

        public class ProcessObj
        {
            public string Name;
            public int ProcessId;
            public string CommandLine;
            public string Handle;
            public uint ThreadCount;
            public ulong WorkingSetSize;

            public string Domain;
            public string User;
            public string[] Paths;

            public Process Process;

            public ProcessObj(ManagementObject retObject, string domain, string user, string[] paths)
            {
                this.Name = (string)retObject.Properties["Name"].Value;
                this.ProcessId = (int)(uint)retObject.Properties["ProcessId"].Value;
                this.CommandLine = (string)retObject.Properties["CommandLine"].Value;
                this.Handle = (string)retObject.Properties["Handle"].Value;
                this.ThreadCount = (uint)retObject.Properties["ThreadCount"].Value;
                this.WorkingSetSize = (ulong)retObject.Properties["WorkingSetSize"].Value;
                this.Domain = domain;
                this.User = user;
                this.Paths = paths;

                try
                {
                    this.Process = Process.GetProcessById(this.ProcessId);
                }
                catch (Exception) { }
            }

            public void WriteToConsole(bool noPaths)
            {
                string mainWindowTitle = "";
                if(this.Process != null && !string.IsNullOrEmpty(this.Process.MainWindowTitle))
                {
                    mainWindowTitle = $" ({this.Process.MainWindowTitle})";
                }
                // {this.Domain}\\{this.User}
                Console.WriteLine($"{this.Name}({this.ProcessId}) ({this.ThreadCount} threads, {FormatSize(this.WorkingSetSize)}), {mainWindowTitle}");
                Console.WriteLine($"\t`{this.CommandLine}`");
                if (!noPaths)
                {
                    foreach (string path in Paths)
                    {
                        Console.WriteLine($"\t{path}");
                    }
                }
            }
        }
        public static IEnumerable<ProcessObj> GetProcesses(int pid, string[] paths)
        {
            string wmiQuery = $"SELECT Name, ProcessID, CommandLine, Handle, ThreadCount, WorkingSetSize FROM Win32_Process WHERE handle={pid}";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiQuery);
            ManagementObjectCollection retObjectCollection = searcher.Get();

            foreach (ManagementObject retObject in retObjectCollection)
            {
                string[] argList = new string[] { "", "" };
                //uint ownerId = (uint)retObject.InvokeMethod("GetOwner", argList);
                yield return new ProcessObj(retObject, argList[0], argList[1], paths);
            }
        }
        public static IEnumerable<ProcessObj> GetExplorerWindows(string searchQuery, string[] paths)
        {
            string wmiQuery = $"SELECT Name, ProcessID, CommandLine, Handle, ThreadCount, WorkingSetSize, Caption, ParentProcessId FROM Win32_Process WHERE Name like \"%explorer%\"";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiQuery);
            ManagementObjectCollection retObjectCollection = searcher.Get();

            foreach (ManagementObject retObject in retObjectCollection)
            {
                string[] argList = new string[] { "", "" };
                //uint ownerId = (uint)retObject.InvokeMethod("GetOwner", argList);
                var obj = new ProcessObj(retObject, argList[0], argList[1], paths);
                // Only for for a substring of the searchQuery... because titles are only so many characters long (around 87 characters),
                //  so long strings can't be matched.
                if(searchQuery.Length > 86)
                {
                    searchQuery = searchQuery.Substring(0, 86);
                }
                if (obj.Process.MainWindowTitle.Contains(searchQuery))
                {
                    foreach(var subProc in GetProcesses(obj.ProcessId, paths))
                    {
                        yield return subProc;
                    }
                }
            }
        }

        public class Options
        {
            [Value(0, MetaName="path", Required=true, HelpText="Deletes the file or folder at this pass, killing and processes with handles to or below this path.")]
            public string Path { get; set; }

            [Option('s', "search", HelpText = "Instead of deleting searches for open handles with the path text, and displays the owners and the full paths.")]
            public bool SearchMode { get; set; }

            [Option('k', "kill", HelpText = "When used with search, automatically kills the found processes.")]
            public bool Kill { get; set; }

            [Option('n', "nokill", HelpText = "When used with search, doesn't kill, or prompt to kill processes.")]
            public bool NoKill { get; set; }

            [Option('r', "recursive", HelpText = "Kill the entire process tree of processes using any handles to the path")]
            public bool Recursive { get; set; }

            [Option('q', "quiet", HelpText = "Doesn't print the paths found.")]
            public bool NoPaths { get; set; }
        }

        static void Kill(ProcessObj procObj, bool recursive, CmdLine.CommandLine cmdLine)
        {
            if(recursive)
            {
                try
                {
                    cmdLine.Run($"taskkill /F /PID {procObj.ProcessId}");
                }
                catch(Exception e)
                {
                    Console.WriteLine($"{procObj.Name}({procObj.ProcessId}) could not be killed, {e.Message}");
                }
            }

            if(procObj.Process == null)
            {
                Console.WriteLine($"{procObj.Name}({procObj.ProcessId}) already killed");
                return;
            }
            
            try
            {
                procObj.Process.Kill();
                Console.WriteLine($"{procObj.Name}({procObj.ProcessId}) killed");
            }
            catch (Exception e)
            {
                Console.WriteLine($"{procObj.Name}({procObj.ProcessId}) could not be killed, {e.Message}");
            }
        }

        static void DeleteEntry(string path)
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
            }
            else
            {
                File.Delete(path);
            }
        }
        static void KillAndDelete(
            List<ProcessObj> procs,
            string searchText,
            bool recursive,
            CmdLine.CommandLine cmdLine
        )
        {
            foreach (var proc in procs)
            {
                try
                {
                    DeleteEntry(searchText);
                    Console.WriteLine($"Deleted \"{searchText}\"");
                    return;
                }
                catch(Exception e) {
                    Console.WriteLine($"Could not delete, {e.ToString()}");
                }
                Kill(proc, recursive, cmdLine);
            }
            DeleteEntry(searchText);
        }

        static void Run(Options options)
        {
            var cmdline = new CmdLine.CommandLine(Print: false);

            string searchText = options.Path;
            if (!options.SearchMode)
            {
                searchText = Path.GetFullPath(searchText).Trim();
                if(searchText.EndsWith("\\"))
                {
                    searchText = searchText.Substring(0, searchText.Length - 1);
                }
            }

            // https://stackoverflow.com/questions/5510343/escape-command-line-arguments-in-c-sharp
            searchText = Regex.Replace(searchText, @"(\\+)$", @"$1$1");

            List<string> handles = cmdline.Run($"handle -nobanner \"{searchText}\"");
            handles = handles.Where(x => x.Trim().Length > 0).ToList();

            var pids = new Dictionary<int, HashSet<string>>();

            foreach(string handle in handles)
            {
                if (handle == "No matching handles found.") continue;
                string pidStr = GetPid(handle);
                string path = GetPath(handle);

                int pid = int.Parse(pidStr);
                if (!pids.ContainsKey(pid))
                {
                    pids.Add(pid, new HashSet<string>());
                    pids[pid].Add(path);
                }
            }

            List<ProcessObj> procs = new List<ProcessObj>();
            foreach (int pid in pids.Keys)
            {
                var paths = pids[pid].ToArray();
                var processes = GetProcesses(pid, paths).ToList();
                foreach(var proc in processes)
                {
                    string name = proc.Name;
                    if (name == "explorer.exe")
                    {
                        // Don't kill the main explorer window, kill the actual windows using the files.
                        var explorerWindows = GetExplorerWindows(searchText, paths).ToList();
                        foreach(var explorerProc in explorerWindows)
                        {
                            explorerProc.WriteToConsole(options.NoPaths);
                            procs.Add(explorerProc);
                        }
                    }
                    else
                    {
                        proc.WriteToConsole(options.NoPaths);
                        procs.Add(proc);
                    }
                    break;
                }
            }

            if (options.NoKill) return;

            if (options.SearchMode)
            {
                if (procs.Count == 0) return;
                if (!options.Kill)
                {
                    Console.WriteLine("\nDo you wish to kill the above processes(y/n)?");
                    char ch = Console.ReadKey().KeyChar;
                    if (ch != 'y')
                    {
                        return;
                    }
                }
                
                foreach (var proc in procs)
                {
                    Kill(proc, options.Recursive, cmdline);
                }
                return;
            }
            else if(!options.SearchMode)
            {
                KillAndDelete(procs, searchText, options.Recursive, cmdline);
            }
        }
    }

    // https://stackoverflow.com/a/11341747/1117119
    public static class Kernel32Api
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern SafeFileHandle CreateFile(
            string lpFileName,
            [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(SafeHandle hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr FindFirstFileNameW(
            string lpFileName,
            uint dwFlags,
            ref uint stringLength,
            StringBuilder fileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool FindNextFileNameW(
            IntPtr hFindStream,
            ref uint stringLength,
            StringBuilder fileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FindClose(IntPtr fFindHandle);

        [DllImport("kernel32.dll")]
        static extern bool GetVolumePathName(string lpszFileName,
            [Out] StringBuilder lpszVolumePathName, uint cchBufferLength);

        [DllImport("shlwapi.dll", CharSet = CharSet.Auto)]
        static extern bool PathAppend([In, Out] StringBuilder pszPath, string pszMore);

        public static int GetFileLinkCount(string filepath)
        {
            int result = 0;
            SafeFileHandle handle = CreateFile(filepath, FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, FileAttributes.Archive, IntPtr.Zero);
            BY_HANDLE_FILE_INFORMATION fileInfo = new BY_HANDLE_FILE_INFORMATION();
            if (GetFileInformationByHandle(handle, out fileInfo))
                result = (int)fileInfo.NumberOfLinks;
            CloseHandle(handle);
            return result;
        }

        public static string[] GetFileSiblingHardLinks(string filepath)
        {
            List<string> result = new List<string>();
            uint stringLength = 256;
            StringBuilder sb = new StringBuilder(256);
            GetVolumePathName(filepath, sb, stringLength);
            string volume = sb.ToString();
            sb.Length = 0; stringLength = 256;
            IntPtr findHandle = FindFirstFileNameW(filepath, 0, ref stringLength, sb);
            if (findHandle.ToInt32() != -1)
            {
                do
                {
                    StringBuilder pathSb = new StringBuilder(volume, 256);
                    PathAppend(pathSb, sb.ToString());
                    result.Add(pathSb.ToString());
                    sb.Length = 0; stringLength = 256;
                } while (FindNextFileNameW(findHandle, ref stringLength, sb));
                FindClose(findHandle);
                return result.ToArray();
            }
            return null;
        }
    }
}
