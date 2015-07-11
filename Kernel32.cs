using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using GASS.CUDA;

namespace KIN
{
    [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 48)]
    public struct AsmModel // Model to search for assembler command 
    {
        [FieldOffset(0)]
        public byte Code; // Binary code 

        [FieldOffset(16)]
        public byte Mask; // Mask for binary code (0: bit ignored) 

        [FieldOffset(32)]
        public int Length; // Length of code, bytes (0: empty) 

        [FieldOffset(36)]
        public int JmpSize; // Offset size if relative jump 

        [FieldOffset(40)]
        public int JmpOffset; // Offset relative to IP 

        [FieldOffset(44)]
        public int JmpPos; // Position of jump offset in command 
    };

    [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 884)]
    public struct DisasmModel // Results of disassembling
    {
        [FieldOffset(0)]
        public ulong InstructionPointer; // Instruction pointer

        [FieldOffset(8)]
        public char Dump; // Hexadecimal dump of the command

        [FieldOffset(304)]
        public char Result; // Disassembled command

        [FieldOffset(560)]
        public char Comment; // Brief comment

        [FieldOffset(816)]
        public int CmdType; // One of C_xxx

        [FieldOffset(820)]
        public int MemType; // Type of addressed variable in memory

        [FieldOffset(824)]
        public int PrefixCount; // Number of prefixes

        [FieldOffset(828)]
        public int Indexed; // Address contains register(s)

        [FieldOffset(832)]
        public ulong JmpConst; // Constant jump address

        [FieldOffset(840)]
        public ulong JmpTable; // Possible address of switch table

        [FieldOffset(848)]
        public ulong AddrConstant; // Constant part of address

        [FieldOffset(856)]
        public ulong ImmediateConstant; // Immediate constant

        [FieldOffset(864)]
        public int ZeroConstant; // Whether contains zero constant

        [FieldOffset(868)]
        public int FixupOffset; // Possible offset of 32-bit fixups

        [FieldOffset(872)]
        public int FixupSize; // Possible total size of fixups or 0

        [FieldOffset(876)]
        public int Error; // Error while disassembling command

        [FieldOffset(880)]
        public int Warnings; // Combination of DAW_xxx
    }

    public static class Kernel32
    {
        public const int MaxCmdSize = 16;
        public const uint Infinite = 0xFFFFFFFF;

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x1,
            CreateThread = 0x2,
            VmOperation = 0x8,
            VmRead = 0x10,
            VmWrite = 0x20,
            DuplicateHandle = 0x40,
            CreateProcess = 0x80,
            SetQuota = 0x100,
            SetInformation = 0x200,
            QueryInformation = 0x400,
            QueryLimitedInformation = 0x1000,
            SuspendResume = 0x800,
            Synchronize = 0x100000,
            AllAccess = 0x1F0FFF,
        }

        [Flags]
        public enum AllocationTypeFlags : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Reset = 0x80000,

            LargePages = 0x20000000,
            Physical = 0x400000,
            TopDown = 0x100000
        }

        [Flags]
        public enum FreeTypeFlags : uint
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        public enum MemoryProtectionConstants : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,

            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08
        }

        [Flags]
        public enum MemoryProtectionFlags : uint
        {
            Guard = 0x100,
            NoCache = 0x200,
            WriteCombine = 0x400
        }

        [Flags]
        public enum CreationFlags : uint
        {
            Immediate = 0x0,
            Suspended = 0x4,
            StackSizeParamIsReservation = 0x10000,
        }

        /// <summary>
        ///     Size - Determine command size only
        ///     Data - Determine size and analysis data
        ///     File - Disassembly, no symbols
        ///     Code - Full disassembly
        /// </summary>
        public enum DisassembleType : int
        {
            Size = 0, // Determine command size only
            Data = 1, // Determine size and analysis data
            File = 3, // Disassembly, no symbols
            Code = 4 // Full disassembly
        }

        /// <summary>
        ///     Opens an existing local process object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the process object.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="dwProcessId">The identifier of the local process to be opened.</param>
        /// <returns>
        ///     If the function succeeds, the return value is an open handle to the specified process.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        /// <summary>
        ///     Closes an open object handle.
        /// </summary>
        /// <param name="hObject">A valid handle to an open object.</param>
        /// <returns>
        ///     If the function succeeds, the return value is nonzero.
        ///     If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);

        /// <summary>
        ///     Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
        /// </summary>
        /// <param name="hProcess">A handle to the process memory to be modified.</param>
        /// <param name="lpBaseAddress">A pointer to the base address in the specified process to which data is written.</param>
        /// <param name="lpBuffer">A pointer to the buffer that contains data to be written in the address space of the specified process.</param>
        /// <param name="nSize">The number of bytes to be written to the specified process.</param>
        /// <param name="lpNumberOfBytesWritten">A pointer to a variable that receives the number of bytes transferred into the specified process.</param>
        /// <returns>
        ///     If the function succeeds, the return value is nonzero.
        ///     If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        /// <summary>
        ///     Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
        /// </summary>
        /// <param name="hProcess">A handle to the process with memory that is being read.</param>
        /// <param name="lpBaseAddress">A pointer to the base address in the specified process from which to read.</param>
        /// <param name="lpBuffer">A pointer to a buffer that receives the contents from the address space of the specified process.</param>
        /// <param name="nSize">The number of bytes to be read from the specified process.</param>
        /// <param name="lpNumberOfBytesRead">A pointer to a variable that receives the number of bytes transferred into the specified buffer.</param>
        /// <returns>
        ///     If the function succeeds, the return value is nonzero.
        ///     If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

        /// <summary>
        ///     Reserves or commits a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero, unless MEM_RESET is used.
        /// </summary>
        /// <param name="hProcess">The handle to a process. The function allocates memory within the virtual address space of this process.</param>
        /// <param name="lpAddress">The pointer that specifies a desired starting address for the region of pages that you want to allocate.</param>
        /// <param name="dwSize">The size of the region of memory to allocate, in bytes.</param>
        /// <param name="flAllocationType">The type of memory allocation. This parameter must contain one of the following values.</param>
        /// <param name="flProtect">The memory protection for the region of pages to be allocated.</param>
        /// <returns>
        ///     If the function succeeds, the return value is the base address of the allocated region of pages.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationTypeFlags flAllocationType, MemoryProtectionConstants flProtect);

        /// <summary>
        ///     Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
        /// </summary>
        /// <param name="hProcess">A handle to a process. The function frees memory within the virtual address space of the process.</param>
        /// <param name="lpAddress">A pointer to the starting address of the region of memory to be freed.</param>
        /// <param name="dwSize">The size of the region of memory to free, in bytes.</param>
        /// <param name="dwFreeType">The type of free operation. This parameter can be one of the following values.</param>
        /// <returns>
        ///     If the function succeeds, the return value is a nonzero value.
        ///     If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern int VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, FreeTypeFlags dwFreeType);

        /// <summary>
        ///     Creates a thread that runs in the virtual address space of another process.
        /// </summary>
        /// <param name="hProcess">A handle to the process in which the thread is to be created.</param>
        /// <param name="lpThreadAttributes">A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited.</param>
        /// <param name="dwStackSize">The initial size of the stack, in bytes. The system rounds this value to the nearest page. If this parameter is 0 (zero), the new thread uses the default size for the executable.</param>
        /// <param name="lpStartAddress">A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process.</param>
        /// <param name="lpParameter">A pointer to a variable to be passed to the thread function.</param>
        /// <param name="dwCreationFlags">The flags that control the creation of the thread.</param>
        /// <param name="lpThreadId">A pointer to a variable that receives the thread identifier.</param>
        /// <returns>
        ///     If the function succeeds, the return value is a handle to the new thread.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, CreationFlags dwCreationFlags, out uint lpThreadId);

        /// <summary>
        ///     Retrieves a module handle for the specified module. The module must have been loaded by the calling process.
        /// </summary>
        /// <param name="lpModuleName">The name of the loaded module (either a .dll or .exe file). If the file name extension is omitted, the default library extension .dll is appended.</param>
        /// <returns>
        ///     If the function succeeds, the return value is a handle to the specified module.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandleA([MarshalAs(UnmanagedType.LPStr)]string lpModuleName);

        /// <summary>
        ///     Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
        /// </summary>
        /// <param name="hModule">A handle to the DLL module that contains the function or variable.</param>
        /// <param name="lpProcName">The function or variable name, or the function's ordinal value.</param>
        /// <returns>
        ///     If the function succeeds, the return value is the address of the exported function or variable.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)]string lpProcName);

        /// <summary>
        ///     Loads the specified module into the address space of the calling process.
        /// </summary>
        /// <param name="lpProcName">The name of the module.</param>
        /// <returns>
        ///     If the function succeeds, the return value is a handle to the module.
        ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpProcName);

        /// <summary>
        ///     Waits until the specified object is in the signaled state or the time-out interval elapses.
        /// </summary>
        /// <param name="hHandle">A handle to the object.</param>
        /// <param name="dwMilliseconds">The time-out interval, in milliseconds.</param>
        /// <returns>
        ///     If the function succeeds, the return value indicates the event that caused the function to return.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        /// <summary>
        ///     Retrieves the termination status of the specified thread.
        /// </summary>
        /// <param name="hThread">A handle to the thread.</param>
        /// <param name="lpExitCode">A pointer to a variable to receive the thread termination status.</param>
        /// <returns>
        ///     If the function succeeds, the return value is nonzero.
        ///     If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </returns>
        [DllImport("kernel32.dll")]
        public static extern int GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("KEncode.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int Assemble([MarshalAs(UnmanagedType.LPStr)]string cmd, uint ip, ref AsmModel model, int attempt, int constsize, char[] errtext);

        [DllImport("KEncode.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong Disassemble(byte[] src, uint srcsize, uint srcip, ref DisasmModel disasm, DisassembleType type);

        public static unsafe byte[] Assemble(string cmd)
        {
            AsmModel model = new AsmModel();
            char[] error = new char[1024];

            int ret = Kernel32.Assemble(cmd, 0, ref model, 0, 0, error);
            if (ret <= 0)
                throw new Exception(new string(error));

            byte[] buff = new byte[ret];
            fixed (byte* a = buff)
            {
                byte* b = &model.Code;
                for (int x = 0; x < ret; x++)
                    a[x] = b[x];
            }

            return buff;
        }

        public static unsafe int Assemble(string cmd, byte* buffer, int length, uint ip = 0)
        {
            AsmModel model = new AsmModel();
            char[] error = new char[1024];
            int ret = Kernel32.Assemble(cmd, ip, ref model, 0, 0, error);
            if (ret <= 0)
                throw new Exception(new string(error));

            if (ret > length)
                throw new Exception("Buffer too small!");

            byte* b = &model.Code;
            for (int x = 0; x < ret; x++)
                buffer[x] = b[x];
            return ret;
        }

        public static unsafe byte[] Assemble(string[] cmds)
        {
            int length = cmds.Length * Kernel32.MaxCmdSize;
            uint size = 0;
            byte[] buffer = new byte[length];
            byte* bufferCopy;
            int ret;

            fixed (byte* bufferPtr = buffer)
            {
                bufferCopy = bufferPtr;
                foreach (string line in cmds)
                {
                    ret = Assemble(line, bufferCopy, length);
                    bufferCopy += ret;
                    length -= ret;
                    size += (uint)ret;
                }

                byte[] buff = new byte[size];
                fixed (byte* a = buff)
                {
                    for (int x = 0; x < size; x++)
                        a[x] = bufferPtr[x];
                }

                return buff;
            }
        }

        public static unsafe byte[] RichAssemble(string code, IntPtr loc, out IntPtr codeStart)
        {
            string[] lines = code.Split('\n');
            int dataSize = 0;
            int ret;
            string[] tokens = new string[3];
            string type;
            string[] subTokens;
            int index;
            int index2;

            Dictionary<string, KeyValuePair<string, object>> variables = new Dictionary<string, KeyValuePair<string, object>>();

            foreach (string line in lines)
            {
                if (line.StartsWith("string") || line.StartsWith("int") || line.StartsWith("uint"))
                {
                    index = line.IndexOf(' ');
                    tokens[0] = line.Substring(0, index++);

                    index2 = line.IndexOf(' ', index);
                    tokens[1] = line.Substring(index, (index2++) - index);
                    tokens[2] = line.Substring(index2, line.Length - index2);
                    type = tokens[0];

                    switch (type)
                    {
                        case "string":
                            variables.Add(tokens[1], new KeyValuePair<string, object>(tokens[0], tokens[2]));
                            dataSize += tokens[2].Length + 1;
                            break;
                        case "rint":
                        case "int":
                            variables.Add(tokens[1], new KeyValuePair<string, object>(tokens[0], Convert.ToInt32(tokens[2])));
                            dataSize += 4;
                            break;
                        case "ruint":
                        case "uint":
                            variables.Add(tokens[1], new KeyValuePair<string, object>(tokens[0], Convert.ToUInt32(tokens[2])));
                            dataSize += 4;
                            break;
                    }

                    continue;
                }
            }

            int offset = 0;
            int length = lines.Length * Kernel32.MaxCmdSize;
            byte[] buffer = new byte[(int)length + dataSize];
            Dictionary<string, uint> variableLocations = new Dictionary<string, uint>(variables.Count);
            foreach (var pair in variables)
            {
                switch (pair.Value.Key)
                {
                    case "string":
                        variableLocations.Add(pair.Key, (uint)loc + (uint)offset);
                        Array.Copy(Encoding.ASCII.GetBytes((string)pair.Value.Value), 0, buffer, offset, ((string)pair.Value.Value).Length);
                        offset += ((string)pair.Value.Value).Length;
                        buffer[offset++] = (byte)'\0';
                        break;
                    case "uint":
                        variableLocations.Add(pair.Key, (uint)pair.Value.Value);
                        break;
                    case "int":
                        variableLocations.Add(pair.Key, (uint)(int)pair.Value.Value);
                        break;
                    case "rint":
                        variableLocations.Add(pair.Key, (uint)loc + (uint)offset);
                        Array.Copy(BitConverter.GetBytes((int)pair.Value.Value), 0, buffer, offset, 4);
                        offset += 4;
                        break;
                    case "ruint":
                        variableLocations.Add(pair.Key, (uint)loc + (uint)offset);
                        Array.Copy(BitConverter.GetBytes((uint)pair.Value.Value), 0, buffer, offset, 4);
                        offset += 4;
                        break;
                }
            }

            codeStart = loc + offset;
            string c;
            fixed (byte* bufferPtr = buffer)
            {
                foreach (string line in lines)
                {
                    if (line == "" || line.Contains("string") || line.Contains("uint") || line.Contains("int") || line.StartsWith(" "))
                        continue;

                    c = line;
                    foreach (var pair in variableLocations)
                        c = c.Replace(pair.Key, Convert.ToString(pair.Value, 16));

                    if (c.StartsWith("J"))
                    {
                        subTokens = c.Split(' ');
                        if (subTokens.Length > 1)
                            c = subTokens[0] + " " + Convert.ToString((uint)loc + (uint)offset + Convert.ToInt32(subTokens[1]), 16);
                    }

                    ret = Assemble(c, bufferPtr + offset, length, (uint)loc + (uint)offset);
                    length -= ret;
                    offset += ret;
                }
            }

            return buffer;
        }

        public static unsafe int Disassemble(byte[] data, uint ip, DisassembleType type, out string result, int offset = 0)
        {
            uint size = (uint)(data.Length - offset);
            if (size > MaxCmdSize)
                size = MaxCmdSize;

            DisasmModel model = new DisasmModel();
            Disassemble(data, size, ip, ref model, type);

            result = new string(&model.Dump);
            if (model.Error > 0)
            {
                result = new string(&model.Comment);
                return -1;
            }
            else
            {
                result = new string(&model.Result);
                return 0;
            }
        }
    }
}
