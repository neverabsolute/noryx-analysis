using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Noryx.Agent;

internal static class ProcessMemoryIntegrityCollector
{
	private struct MEMORY_BASIC_INFORMATION
	{
		public nint BaseAddress;

		public nint AllocationBase;

		public uint AllocationProtect;

		public ushort PartitionId;

		public nuint RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;
	}

	private struct SYSTEM_INFO
	{
		public ushort wProcessorArchitecture;

		public ushort wReserved;

		public uint dwPageSize;

		public nint lpMinimumApplicationAddress;

		public nint lpMaximumApplicationAddress;

		public nuint dwActiveProcessorMask;

		public uint dwNumberOfProcessors;

		public uint dwProcessorType;

		public uint dwAllocationGranularity;

		public ushort wProcessorLevel;

		public ushort wProcessorRevision;
	}

	private sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeProcessHandle()
			: base(ownsHandle: true)
		{
		}

		protected override bool ReleaseHandle()
		{
			return CloseHandle(handle);
		}
	}

	private const uint PROCESS_QUERY_INFORMATION = 1024u;

	private const uint PROCESS_VM_READ = 16u;

	private const uint MEM_COMMIT = 4096u;

	private const uint MEM_PRIVATE = 131072u;

	private const uint PAGE_EXECUTE = 16u;

	private const uint PAGE_EXECUTE_READ = 32u;

	private const uint PAGE_EXECUTE_READWRITE = 64u;

	private const uint PAGE_EXECUTE_WRITECOPY = 128u;

	private const uint PAGE_GUARD = 256u;

	private static readonly string[] TargetProcesses = new string[5] { "rust", "rustclient", "steam", "steamwebhelper", "explorer" };

	public static List<ProcessMemoryIntegrityRecord> Collect()
	{
		List<ProcessMemoryIntegrityRecord> list = new List<ProcessMemoryIntegrityRecord>();
		GetNativeSystemInfo(out var lpSystemInfo);
		nuint lpMinimumApplicationAddress = (nuint)lpSystemInfo.lpMinimumApplicationAddress;
		nuint lpMaximumApplicationAddress = (nuint)lpSystemInfo.lpMaximumApplicationAddress;
		Process[] processes = Process.GetProcesses();
		foreach (Process process in processes)
		{
			try
			{
				if (!TargetProcesses.Contains<string>(process.ProcessName, StringComparer.OrdinalIgnoreCase))
				{
					continue;
				}
				using SafeProcessHandle safeProcessHandle = OpenProcess(1040u, bInheritHandle: false, process.Id);
				if (safeProcessHandle.IsInvalid)
				{
					continue;
				}
				string text = "";
				try
				{
					text = process.MainModule?.FileName ?? "";
				}
				catch
				{
				}
				bool processSigned = false;
				string processSigner = "";
				if (!string.IsNullOrWhiteSpace(text) && File.Exists(text))
				{
					(processSigned, processSigner) = AuthenticodeVerifier.Verify(text);
				}
				nuint num = lpMinimumApplicationAddress;
				int num2 = 0;
				while (num < lpMaximumApplicationAddress && num2 < 200000 && list.Count < 1000)
				{
					num2++;
					if (VirtualQueryEx(safeProcessHandle, (nint)num, out var lpBuffer, (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
					{
						nuint baseAddress = (nuint)lpBuffer.BaseAddress;
						nuint regionSize = lpBuffer.RegionSize;
						if (regionSize != 0)
						{
							bool num3 = lpBuffer.State == 4096;
							bool flag = lpBuffer.Type == 131072;
							bool flag2 = IsExecutableProtection(lpBuffer.Protect);
							bool flag3 = (lpBuffer.Protect & 0x100) != 0;
							if (num3 && flag && flag2 && !flag3 && regionSize >= 4096 && (ulong)regionSize <= 536870912uL)
							{
								bool flag4 = HasMzHeader(safeProcessHandle, lpBuffer.BaseAddress);
								list.Add(new ProcessMemoryIntegrityRecord
								{
									ProcessId = process.Id,
									ProcessName = process.ProcessName,
									ProcessPath = text,
									ProcessSigned = processSigned,
									ProcessSigner = processSigner,
									BaseAddress = "0x" + ((UIntPtr)baseAddress).ToString("X"),
									RegionSize = regionSize,
									Protection = lpBuffer.Protect,
									MemoryType = "MEM_PRIVATE",
									Executable = true,
									MzHeader = flag4,
									PotentialManualMap = flag4
								});
							}
							nuint num4 = baseAddress + regionSize;
							if (num4 > num)
							{
								num = num4;
								continue;
							}
							break;
						}
						break;
					}
					break;
				}
			}
			catch
			{
			}
			finally
			{
				process.Dispose();
			}
		}
		return (from x in list
			group x by $"{x.ProcessId}|{x.BaseAddress}|{x.RegionSize}" into x
			select x.First()).Take(1000).ToList();
	}

	private static bool HasMzHeader(SafeProcessHandle process, nint address)
	{
		try
		{
			byte[] array = new byte[2];
			if (!ReadProcessMemory(process, address, array, array.Length, out var lpNumberOfBytesRead))
			{
				return false;
			}
			return lpNumberOfBytesRead >= 2 && array[0] == 77 && array[1] == 90;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsExecutableProtection(uint protection)
	{
		uint num = protection & 0xFF;
		if (num != 16 && num != 32 && num != 64)
		{
			return num == 128;
		}
		return true;
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern SafeProcessHandle OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern nuint VirtualQueryEx(SafeProcessHandle hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool ReadProcessMemory(SafeProcessHandle hProcess, nint lpBaseAddress, [Out] byte[] lpBuffer, int nSize, out nuint lpNumberOfBytesRead);

	[DllImport("kernel32.dll")]
	private static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool CloseHandle(nint hObject);
}
