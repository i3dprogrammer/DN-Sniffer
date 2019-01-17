using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DNSniffer
{
    class DNLoader
    {
        protected int BaseAddress;

        #region KERNEL32 IMPORTS
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead);
        #endregion


        #region ACCESS RIGHTS
        private const uint PAGE_EXECUTE = 16;
        private const uint PAGE_EXECUTE_READ = 32;
        private const uint PAGE_EXECUTE_READWRITE = 64;
        private const uint PAGE_EXECUTE_WRITECOPY = 128;
        private const uint PAGE_GUARD = 256;
        private const uint PAGE_NOACCESS = 1;
        private const uint PAGE_NOCACHE = 512;
        private const uint PAGE_READONLY = 2;
        private const uint PAGE_READWRITE = 4;
        private const uint PAGE_WRITECOPY = 8;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        #endregion

        protected int DNProcessHandle;
        protected string DNProcessPath;
        protected string DNProcessDirectory;
        protected string DNProcessArguments;
        protected Process _Process;
        public DNLoader(string processPath, string processArguments)
        {
            DNProcessPath = processPath;
            DNProcessArguments = processArguments;
            DNProcessDirectory = new FileInfo(processPath).DirectoryName;
        }

        public bool LaunchProcess()
        {
            try
            {
                Console.WriteLine($"Launching {DNProcessPath}");

                //So we can use working directory attribute, because Dragon Nest working dir check.
                ProcessStartInfo pInfo = new ProcessStartInfo();
                pInfo.WorkingDirectory = DNProcessDirectory;
                pInfo.FileName = DNProcessPath;
                pInfo.Arguments = DNProcessArguments;

                _Process = Process.Start(pInfo);

                //Wait for the DNProcess to initialize.
                Thread.Sleep(100);
                BaseAddress = (int)_Process.Modules[0].BaseAddress;

                DNProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _Process.Id);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return false;
            }
        }

        public bool PatchIPCheck()
        { //Only part of a ReadProcessMemory or WriteProcessMemory request was completed 
            try
            {
                if (DNProcessHandle == 0)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    BaseAddress = (int)_Process.MainModule.BaseAddress;
                    DNProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _Process.Id);
                }
                var patchBytes = new byte[] { 0x74, 0x52 };
                Console.WriteLine("Patching IP Check.");
                return WriteProcessMemory(DNProcessHandle, BaseAddress + 0x00861AE6, patchBytes, patchBytes.Length, 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Couldn't get DN handle, restarting process.");
                KillAndRun();
                return false;
            }
        }

        public bool GetXTEAKey()
        {
            try
            {
                if (DNProcessHandle == 0)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    BaseAddress = (int)_Process.MainModule.BaseAddress;
                    DNProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _Process.Id);
                }
                var buf = new byte[0x06];
                ReadProcessMemory(DNProcessHandle, BaseAddress + 0x00863C21, buf, buf.Length, 0);
                var addr = BitConverter.ToInt32(buf, 2);
                Console.WriteLine(addr.ToString("X4"));
                ReadProcessMemory(DNProcessHandle, addr, buf, 4, 0);
                addr = BitConverter.ToInt32(buf, 0);
                var buffer = new byte[0x1005];
                ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                Console.WriteLine(addr);
                var op = ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                File.WriteAllText("TCPKey.txt", "0x" + buffer.Select(x => x.ToString("X2")).Aggregate((x, y) => x + ", 0x" + y));
                //File.WriteAllLines("Key.txt", buffer.Select(x => x.ToString("X2")));
                return op;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return false;
            }
        }

        public bool GetUDPKey()
        {
            try
            {
                if (DNProcessHandle == 0)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    BaseAddress = (int)_Process.MainModule.BaseAddress;
                    DNProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _Process.Id);
                }
                var buf = new byte[0x200];
                ReadProcessMemory(DNProcessHandle, BaseAddress + 0x00863DD1, buf, 6, 0);
                var addr = BitConverter.ToInt32(buf, 2) - 0x94 - 0x8;
                Console.WriteLine(addr.ToString("X4"));
                ReadProcessMemory(DNProcessHandle, addr, buf, buf.Length, 0);
                Console.WriteLine(buf.Select(x => x.ToString("X2")).Aggregate((x, y) => x + " " + y));
                addr = BitConverter.ToInt32(buf, 0);
                Console.WriteLine(addr.ToString("X4"));
                ReadProcessMemory(DNProcessHandle, addr + 0x104, buf, 4, 0);
                addr = BitConverter.ToInt32(buf, 0);
                Console.WriteLine(addr);
                ReadProcessMemory(DNProcessHandle, addr + 0x9C, buf, 4, 0);
                addr = BitConverter.ToInt32(buf, 0);
                Console.WriteLine(addr);
                return false;
                var buffer = new byte[0x1005];
                ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                var op = ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                File.WriteAllText("TCPKey.txt", "0x" + buffer.Select(x => x.ToString("X2")).Aggregate((x, y) => x + ", 0x" + y));
                //File.WriteAllLines("Key.txt", buffer.Select(x => x.ToString("X2")));
                return op;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return false;
            }
        }

        private void KillAndRun()
        {
            //Process.Start($"taskkill.exe /PID /F {_Process.Id}");
            //LaunchProcess();
        }

    }
}
