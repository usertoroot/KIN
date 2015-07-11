using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace KIN
{
    public class KProcess : IDisposable
    {
        private IntPtr m_hProcess = IntPtr.Zero;
        private IntPtr m_baseAddress = IntPtr.Zero;

        public KProcess()
        {

        }

        ~KProcess()
        {
            Dispose();
        }

        public void Dispose()
        {
            Close();
        }

        public unsafe void Open(string process)
        {
            Process[] p = Process.GetProcessesByName(process);
            if (p.Length > 0)
                Open(p[0].Id);
            else
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public void Open(int pid)
        {
            m_hProcess = Kernel32.OpenProcess(Kernel32.ProcessAccessFlags.AllAccess, false, pid);
            if (m_hProcess == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public void Close()
        {
            //if (m_hProcess != IntPtr.Zero)
            //    Kernel32.CloseHandle(m_hProcess);
        }

        public IntPtr VirtualAlloc(int size)
        {
            IntPtr loc = Kernel32.VirtualAllocEx(m_hProcess, IntPtr.Zero, (uint)size, Kernel32.AllocationTypeFlags.Reserve | Kernel32.AllocationTypeFlags.Commit, Kernel32.MemoryProtectionConstants.ExecuteReadWrite);
            if (loc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return loc;
        }

        public void VirtualFree(IntPtr loc)
        {
            if (Kernel32.VirtualFreeEx(m_hProcess, loc, 0, Kernel32.FreeTypeFlags.Release) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public IntPtr CreateThread(IntPtr startAddress)
        {
            uint threadId;
            IntPtr hThread = Kernel32.CreateRemoteThread(m_hProcess, 0, 0, startAddress, IntPtr.Zero, Kernel32.CreationFlags.Immediate, out threadId);

            if (hThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return hThread;
        }

        public int WriteProcessMemory(IntPtr loc, byte[] data)
        {
            uint bytesWritten;
            if (Kernel32.WriteProcessMemory(m_hProcess, loc, data, (uint)data.Length, out bytesWritten) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return (int)bytesWritten;
        }

        public byte[] ReadProcessMemory(IntPtr loc, int size)
        {
            uint bytesRead;
            byte[] ret = new byte[size];
            
            if (Kernel32.ReadProcessMemory(m_hProcess, loc, ret, (uint)size, out bytesRead) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return ret;
        }

        public InjectedLibrary LoadLibrary(string fullDllPath, IntPtr initFunctionOffset)
        {
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getProcAddressLoc = Kernel32.GetProcAddress(module, "GetProcAddress");
            IntPtr loadLibraryLoc = Kernel32.GetProcAddress(module, "LoadLibraryA");
            IntPtr freeLibraryLoc = Kernel32.GetProcAddress(module, "FreeLibrary");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(1000);
            byte[] code = Kernel32.RichAssemble(
                "string dllName " + fullDllPath + "\n" +
                "uint funcOffset " + initFunctionOffset.ToString() + "\n" +
                "uint getProcAddress " + getProcAddressLoc.ToString() + "\n" +
                "uint loadLibrary " + loadLibraryLoc.ToString() + "\n" +
                "uint freeLibrary " + freeLibraryLoc.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH dllName" + "\n" +
                "CALL loadLibrary" + "\n" +
                "MOV EBX, EAX" + "\n" +

                "CMP EAX, 0" + "\n" +
                "JNZ 12" + "\n" +

                "PUSH -1" + "\n" +
                "CALL exitThread" + "\n" +

                "MOV EAX, funcOffset" + "\n" +
                "ADD EAX, EBX" + 
                "CALL EAX" + "\n" +

                "PUSH EBX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);

            if ((int)exitCode == -1)
                throw new Exception("ExitThread failed!");
            else if ((int)exitCode == -2)
                throw new Exception("GetProcAddress failed!");

            VirtualFree(loc);
            return new InjectedLibrary(this, (IntPtr)exitCode);
        }

        public InjectedLibrary LoadLibrary(string fullDllPath, string initFuncName)
        {
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getProcAddressLoc = Kernel32.GetProcAddress(module, "GetProcAddress");
            IntPtr loadLibraryLoc = Kernel32.GetProcAddress(module, "LoadLibraryA");
            IntPtr freeLibraryLoc = Kernel32.GetProcAddress(module, "FreeLibrary");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(1000);
            byte[] code = Kernel32.RichAssemble(
                "string dllName " + fullDllPath + "\n" +
                "string funcName " + initFuncName + "\n" +
                "uint getProcAddress " + getProcAddressLoc.ToString() + "\n" +
                "uint loadLibrary " + loadLibraryLoc.ToString() + "\n" +
                "uint freeLibrary " + freeLibraryLoc.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH dllName" + "\n" +
                "CALL loadLibrary" + "\n" +
                "MOV EBX, EAX" + "\n" +

                "CMP EAX, 0" + "\n" +
                "JNZ 12" + "\n" +

                "PUSH -1" + "\n" +
                "CALL exitThread" + "\n" +

                "PUSH funcName" + "\n" +
                "PUSH EBX" + "\n" +
                "CALL getProcAddress" + "\n" +
                "MOV ECX, EAX" + "\n" +

                "CMP EAX, 0" + "\n" +
                "JNZ 18" + "\n" +

                "PUSH EBX" + "\n" +
                "CALL freeLibrary" + "\n" +

                "PUSH -2" + "\n" +
                "CALL exitThread" + "\n" +

                "CALL ECX" + "\n" +

                "PUSH EBX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);

            if ((int)exitCode == -1)
                throw new Exception("ExitThread failed!");
            else if ((int)exitCode == -2)
                throw new Exception("GetProcAddress failed!");

            VirtualFree(loc);
            return new InjectedLibrary(this, (IntPtr)exitCode);
        }

        public void FreeLibrary(IntPtr hModule)
        {
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr freeLibraryAndExitThread = Kernel32.GetProcAddress(module, "FreeLibraryAndExitThread");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "uint moduleHandle " + module.ToString() + "\n" +
                "uint freeLibraryAndExitThread " + freeLibraryAndExitThread.ToString() + "\n" +

                "PUSH 0" + "\n" + 
                "PUSH moduleHandle" + "\n" +
                "CALL freeLibraryAndExitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);
            VirtualFree(loc);
        }

        public IntPtr GetModuleHandle()
        {
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getModuleHandleA = Kernel32.GetProcAddress(module, "GetModuleHandleA");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "uint getModuleHandleA " + getModuleHandleA.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH 0" + "\n" +
                "CALL getModuleHandleA" + "\n" +

                "PUSH EAX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);

            VirtualFree(loc);
            return (IntPtr)exitCode;
        }

        public IntPtr GetProcAddress(IntPtr module, string name)
        {
            IntPtr kModule = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getProcAddr = Kernel32.GetProcAddress(kModule, "GetProcAddress");
            IntPtr exitThread = Kernel32.GetProcAddress(kModule, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "string moduleName " + name + "\n" +
                "uint getProcAddr " + getProcAddr.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +
                "uint module " + module.ToString() + "\n" +

                "PUSH moduleName" + "\n" +
                "PUSH module" + "\n" +
                "CALL getProcAddr" + "\n" +

                "PUSH EAX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);

            VirtualFree(loc);
            return (IntPtr)exitCode;
        }

        public IntPtr GetModuleHandle(string name)
        {
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getModuleHandleA = Kernel32.GetProcAddress(module, "GetModuleHandleA");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");
            IntPtr codeStart;

            IntPtr loc = VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "string moduleName " + name + "\n" +
                "uint getModuleHandleA " + getModuleHandleA.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH moduleName" + "\n" +
                "CALL getModuleHandleA" + "\n" +

                "PUSH EAX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            WriteProcessMemory(loc, code);
            IntPtr hThread = CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);

            VirtualFree(loc);
            return (IntPtr)exitCode;
        }
    }
}