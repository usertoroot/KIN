using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KIN
{
    public class Helper
    {
        private KProcess m_process;
        private InjectedLibrary m_dll;
        private IntPtr m_replaceImportAddress;

        public Helper(KProcess process, InjectedLibrary dll)
        {
            m_process = process;
            m_dll = dll;

            m_replaceImportAddress = m_process.GetProcAddress(dll.Module, "ReplaceImportAddress");
        }

        public void ReplaceImportAddress(string dllName, string funcName, uint addr)
        {
            IntPtr codeStart;
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");

            IntPtr loc = m_process.VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "string dllName " + dllName + "\n" +
                "string funcName " + funcName + "\n" +
                "uint addr " + addr.ToString() + "\n" +
                "uint replaceIA " + m_replaceImportAddress.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH addr" + "\n" +
                "PUSH funcName" + "\n" +
                "PUSH dllName" + "\n" +
                "CALL replaceIA" + "\n" +

                "PUSH EAX" + "\n" +
                "CALL exitThread", loc, out codeStart
            );

            m_process.WriteProcessMemory(loc, code);
            IntPtr hThread = m_process.CreateThread(codeStart);
            Kernel32.WaitForSingleObject(hThread, Kernel32.Infinite);

            uint exitCode;
            Kernel32.GetExitCodeThread(hThread, out exitCode);
            Kernel32.CloseHandle(hThread);
            m_process.VirtualFree(loc);
        }
    }
}