﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DNSniffer.Client
{
    class DNLoader
    {
        protected int BaseAddress;

        #region KERNEL32 IMPORTS
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead);
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

        protected IntPtr DNProcessHandle;
        protected string DNProcessPath;
        protected string DNProcessDirectory;
        protected string DNProcessArguments;
        protected Process _Process;

        /// <summary>
        /// Initializes a new DNLoader
        /// </summary>
        /// <param name="processPath">The full DragonNest.exe path</param>
        /// <param name="processArguments">The arguments used to run the game leave empty for /ip:127.0.0.1;127.0.0.1 /port:50000;50000 /Lver:2 /use_packing /language:ENG</param>
        public DNLoader(string processPath, string processArguments="")
        {
            if (processArguments == "")
                processArguments = $"/ip:127.0.0.1;127.0.0.1 /port:{50000};{50000} /Lver:2 /use_packing /language:ENG";

            DNProcessPath = processPath;
            DNProcessArguments = processArguments;
            DNProcessDirectory = new FileInfo(processPath).DirectoryName;
        }


        /// <summary>
        /// Launch DragonNest if it wasn't already running.
        /// </summary>
        /// <returns>Returns true if the game launched successfully, false otherwise.</returns>
        public bool LaunchProcess()
        {
            try
            {
                Console.WriteLine($"Launching {DNProcessPath}");

                if(!File.Exists(DNProcessPath))
                {
                    Console.WriteLine($"{DNProcessPath} not found! Aborting.");
                    return false;
                }

                _Process = Process.GetProcesses().ToList().FirstOrDefault(x => x.ProcessName == "DragonNest");

                if(_Process != null)
                {
                    Console.WriteLine("DragonNest already running.");
                    DNProcessHandle = _Process.Handle;
                    return true;
                }

                //So we can use working directory attribute, because Dragon Nest working dir check.
                ProcessStartInfo pInfo = new ProcessStartInfo();
                pInfo.WorkingDirectory = DNProcessDirectory;
                pInfo.FileName = DNProcessPath;
                pInfo.Arguments = DNProcessArguments;

                _Process = Process.Start(pInfo);

                //Wait for the DNProcess to initialize.
                Thread.Sleep(100);

                DNProcessHandle = _Process.Handle;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return false;
            }
        }

        /// <summary>
        /// Patches game IP check to allow for localhost or 127.0.0.1 usage.
        /// </summary>
        /// <returns>Returns a bool specifying if the patch completed succesfully.</returns>
        public bool PatchIPCheck()
        { 
            try
            {
                if (DNProcessHandle == IntPtr.Zero)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    DNProcessHandle = _Process.Handle;
                }
                var patchBytes = new byte[] { 0x74, 0x52 };
                PatternFinder finder = new PatternFinder(_Process, new IntPtr(0xC50000), 0x20000);
                IntPtr virtualAddr = finder.FindPattern(new byte[] { 0x3a, 0xC3, 0x0F, 0x84, 0x9F, 0x00, 0x00, 0x00, 0x38, 0x9D, 0xE0, 0x00, 0x00, 0x00, 0xC6, 0x45, 0x78, 0x01, 0x0F, 0x84, 0xA5, 0x00, 0x00, 0x00, 0x39, 0x9D, 0xF8, 0x00, 0x00, 0x00 }, 0x57);
                finder.ResetRegion();
                Console.WriteLine("Patching IP Check.");
                return WriteProcessMemory(DNProcessHandle, virtualAddr, patchBytes, patchBytes.Length, 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Couldn't get DN handle, restarting process.");
                return false;
            }
        }

        /// <summary>
        /// Writes DragonNest TCP (XTEA) Key to TCPKey.txt
        ///     Use this function only when game is fully loaded. Will write null bytes if not.
        /// </summary>
        /// <returns>Returns a bool specifying whether or not the key retrieval was successful.</returns>
        public byte[] GetXTEAKey()
        {
            try
            {
                if (DNProcessHandle == IntPtr.Zero)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    DNProcessHandle = _Process.Handle;
                }
                PatternFinder finder = new PatternFinder(_Process, new IntPtr(0xC50000), 0x20000);
                IntPtr virtualAddr = finder.FindPattern(new byte[] { 0x33, 0xD2, 0x85, 0xC0, 0x0F, 0x9D, 0xC2, 0x5F, 0x83, 0xEA, 0x01, 0x8B, 0xC2 }, "xxxxxxxxxxxxx", -58);
                finder.ResetRegion();
                if (virtualAddr == IntPtr.Zero)
                    return new byte[0];
                var buf = new byte[0x06];
                ReadProcessMemory(DNProcessHandle,  virtualAddr, buf, buf.Length, 0);
                var addr = new IntPtr(BitConverter.ToInt32(buf, 2));
                ReadProcessMemory(DNProcessHandle, addr, buf, 4, 0);
                addr = new IntPtr(BitConverter.ToInt32(buf, 0));
                var buffer = new byte[0x1005];
                ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                var op = ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                File.WriteAllText("TCPKey.txt", "0x" + buffer.Select(x => x.ToString("X2")).Aggregate((x, y) => x + ", 0x" + y));
                return buffer;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return new byte[0];
            }
        }

        /// <summary>
        /// Writes DragonNest UDP Crpyto Key to UDPKey.txt
        ///     Only call this function when game is fully loaded. Will write null bytes if not.
        /// </summary>
        /// <returns>Returns a bool specifying whether or not the key retrieval was successful.</returns>
        public byte[] GetUDPKey()
        {
            try
            {
                if (DNProcessHandle == IntPtr.Zero)
                {
                    _Process = Process.GetProcesses().First(x => x.ProcessName == "DragonNest");
                    DNProcessHandle = _Process.Handle;
                }
                var buf = new byte[0x200];
                PatternFinder finder = new PatternFinder(_Process, new IntPtr(0xC50000), 0x20000);
                IntPtr virtualAddr = finder.FindPattern(new byte[] { 0x33, 0xD2, 0x85, 0xC0, 0x0F, 0x9D, 0xC2, 0x5F, 0x83, 0xEA, 0x01, 0x8B, 0xC2 }, "xxxxxxxxxxxxx", -58);
                finder.ResetRegion();
                if (virtualAddr == IntPtr.Zero)
                    return new byte[0];
                ReadProcessMemory(DNProcessHandle, virtualAddr, buf, 6, 0);
                var addr = new IntPtr(BitConverter.ToInt32(buf, 2) - 0x94);
                ReadProcessMemory(DNProcessHandle, addr, buf, buf.Length, 0);
                addr = new IntPtr(BitConverter.ToInt32(buf, 0));
                ReadProcessMemory(DNProcessHandle, addr + 0x104, buf, 4, 0);
                addr = new IntPtr(BitConverter.ToInt32(buf, 0));
                ReadProcessMemory(DNProcessHandle, addr + 0x9C, buf, 4, 0);
                addr = new IntPtr(BitConverter.ToInt32(buf, 0));
                var buffer = new byte[30];
                var op = ReadProcessMemory(DNProcessHandle, addr, buffer, buffer.Length, 0);
                File.WriteAllText("UDPKey.txt", "0x" + buffer.Select(x => x.ToString("X2")).Aggregate((x, y) => x + ", 0x" + y));
                return buffer;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + ex.StackTrace);
                return new byte[0];
            }
        }
    }
}
