using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KIN
{
    public class InjectedLibrary
    {
        private IntPtr m_module;
        public IntPtr Module
        {
            get
            {
                return m_module;
            }
        }

        private KProcess m_process;

        public InjectedLibrary(KProcess process, IntPtr module)
        {
            m_process = process;
            m_module = module;
        }

        /// <summary>
        ///     Calls a function in a loaded dll.
        /// </summary>
        /// <param name="function">
        ///     The function name (must be a _declspec(dllexport)!)
        /// </param>
        public void Call(string function)
        {
            IntPtr codeStart;
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getProcAddress = Kernel32.GetProcAddress(module, "GetProcAddress");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");

            IntPtr loc = m_process.VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "string functionName " + function + "\n" + 
                "uint moduleHandle " + m_module.ToString() + "\n" +
                "uint getProcAddress " + getProcAddress.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +

                "PUSH functionName" + "\n" +
                "PUSH moduleHandle" + "\n" +
                "CALL getProcAddress" + "\n" + 
                
                "CMP EAX, 0" + "\n" +
                "JNZ 12" + "\n" +

                "PUSH -1" + "\n" +
                "CALL exitThread" + "\n" +
                
                "CALL EAX" + "\n" +

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

            if (exitCode < 0)
                throw new Exception("Failed to call function.");
        }

        /// <summary>
        ///     Calls a function in a loaded dll. FUNCTION MUST HAVE CALLING CONVENTION stdcall
        /// </summary>
        /// <param name="function">
        ///     The function name (must be a _declspec(dllexport)!)
        /// </param>
        /// <param name="param">
        ///     A parameter to be passed.
        /// </param>
        public void Call(string function, uint param)
        {
            IntPtr codeStart;
            IntPtr module = Kernel32.GetModuleHandleA("kernel32.dll");
            IntPtr getProcAddress = Kernel32.GetProcAddress(module, "GetProcAddress");
            IntPtr exitThread = Kernel32.GetProcAddress(module, "ExitThread");

            IntPtr loc = m_process.VirtualAlloc(200);
            byte[] code = Kernel32.RichAssemble(
                "string functionName " + function + "\n" +
                "uint moduleHandle " + m_module.ToString() + "\n" +
                "uint getProcAddress " + getProcAddress.ToString() + "\n" +
                "uint exitThread " + exitThread.ToString() + "\n" +
                "uint param" + param.ToString() + "\n" + 

                "PUSH functionName" + "\n" +
                "PUSH moduleHandle" + "\n" +
                "CALL getProcAddress" + "\n" +

                "CMP EAX, 0" + "\n" +
                "JNZ 12" + "\n" +

                "PUSH -1" + "\n" +
                "CALL exitThread" + "\n" +

                "PUSH param" + "\n" + 
                "CALL EAX" + "\n" +

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

            if (exitCode < 0)
                throw new Exception("Failed to call function.");
        }
    }
}
