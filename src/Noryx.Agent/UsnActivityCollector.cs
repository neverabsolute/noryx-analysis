using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Noryx.Agent;

internal static class UsnActivityCollector
{
	private struct USN_JOURNAL_DATA_V0
	{
		public ulong UsnJournalID;

		public long FirstUsn;

		public long NextUsn;

		public long LowestValidUsn;

		public long MaxUsn;

		public ulong MaximumSize;

		public ulong AllocationDelta;
	}

	private struct READ_USN_JOURNAL_DATA_V0
	{
		public long StartUsn;

		public uint ReasonMask;

		public uint ReturnOnlyOnClose;

		public ulong Timeout;

		public ulong BytesToWaitFor;

		public ulong UsnJournalID;
	}

	private struct BY_HANDLE_FILE_INFORMATION
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

	private const uint GENERIC_READ = 2147483648u;

	private const uint FILE_READ_ATTRIBUTES = 128u;

	private const uint FILE_SHARE_READ = 1u;

	private const uint FILE_SHARE_WRITE = 2u;

	private const uint FILE_SHARE_DELETE = 4u;

	private const uint OPEN_EXISTING = 3u;

	private const uint FILE_FLAG_BACKUP_SEMANTICS = 33554432u;

	private const uint FSCTL_READ_USN_JOURNAL = 590011u;

	private const uint FSCTL_QUERY_USN_JOURNAL = 590068u;

	private const uint USN_REASON_DATA_OVERWRITE = 1u;

	private const uint USN_REASON_DATA_EXTEND = 2u;

	private const uint USN_REASON_DATA_TRUNCATION = 4u;

	private const uint USN_REASON_FILE_CREATE = 256u;

	private const uint USN_REASON_FILE_DELETE = 512u;

	private const uint USN_REASON_RENAME_OLD_NAME = 4096u;

	private const uint USN_REASON_RENAME_NEW_NAME = 8192u;

	private const uint USN_REASON_CLOSE = 2147483648u;

	private const ulong MftIndexMask = 281474976710655uL;

	private static readonly HashSet<string> InterestingExtensions = new HashSet<string>(new string[17]
	{
		".exe", ".com", ".scr", ".dll", ".sys", ".msi", ".bat", ".cmd", ".zip", ".rar",
		".7z", ".pf", ".evtx", ".db", ".dat", ".hve", ".lnk"
	}, StringComparer.OrdinalIgnoreCase);

	public static List<UsnActivityRecord> Collect()
	{
		List<UsnActivityRecord> list = new List<UsnActivityRecord>();
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			try
			{
				if (!driveInfo.IsReady || (driveInfo.DriveType != DriveType.Fixed && driveInfo.DriveType != DriveType.Removable) || !driveInfo.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				string text = driveInfo.Name.TrimEnd('\\');
				ulong? prefetchIndex = null;
				string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
				if (!string.IsNullOrWhiteSpace(folderPath) && folderPath.StartsWith(text, StringComparison.OrdinalIgnoreCase))
				{
					prefetchIndex = GetFileIndex(Path.Combine(folderPath, "Prefetch"));
				}
				list.AddRange(CollectVolume(text, driveInfo.DriveType.ToString(), prefetchIndex, 12000));
				goto IL_00bf;
			}
			catch
			{
				goto IL_00bf;
			}
			IL_00bf:
			if (list.Count >= 18000)
			{
				break;
			}
		}
		return (from x in list.OrderByDescending((UsnActivityRecord x) => x.TimestampUtc).GroupBy<UsnActivityRecord, string>((UsnActivityRecord x) => $"{x.Volume}|{x.FileName}|{x.TimestampUtc:O}|{x.ReasonMask}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(18000).ToList();
	}

	private static List<UsnActivityRecord> CollectVolume(string volume, string driveType, ulong? prefetchIndex, int maxRecords)
	{
		List<UsnActivityRecord> list = new List<UsnActivityRecord>();
		using SafeFileHandle safeFileHandle = CreateFile("\\\\.\\" + volume, 2147483648u, 7u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
		if (safeFileHandle.IsInvalid)
		{
			return list;
		}
		if (!DeviceIoControlQuery(safeFileHandle, 590068u, IntPtr.Zero, 0, out var lpOutBuffer, Marshal.SizeOf<USN_JOURNAL_DATA_V0>(), out var _, IntPtr.Zero))
		{
			return list;
		}
		long num = 536870912L;
		long startUsn = Math.Max(lpOutBuffer.FirstUsn, lpOutBuffer.NextUsn - num);
		uint reasonMask = 2147496711u;
		READ_USN_JOURNAL_DATA_V0 lpInBuffer = new READ_USN_JOURNAL_DATA_V0
		{
			StartUsn = startUsn,
			ReasonMask = reasonMask,
			ReturnOnlyOnClose = 0u,
			Timeout = 0uL,
			BytesToWaitFor = 0uL,
			UsnJournalID = lpOutBuffer.UsnJournalID
		};
		byte[] array = new byte[1048576];
		DateTime cutoff = DateTime.UtcNow.AddDays(-45.0);
		for (int i = 0; i < 800; i++)
		{
			if (list.Count >= maxRecords)
			{
				break;
			}
			if (!DeviceIoControlRead(safeFileHandle, 590011u, ref lpInBuffer, Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>(), array, array.Length, out var lpBytesReturned2, IntPtr.Zero))
			{
				break;
			}
			if (lpBytesReturned2 <= 8)
			{
				break;
			}
			long num2 = BitConverter.ToInt64(array, 0);
			uint num3;
			for (int j = 8; j + 8 <= lpBytesReturned2; j += checked((int)num3))
			{
				if (list.Count >= maxRecords)
				{
					break;
				}
				num3 = BitConverter.ToUInt32(array, j);
				if (num3 < 60 || j + num3 > lpBytesReturned2)
				{
					break;
				}
				if (BitConverter.ToUInt16(array, j + 4) == 2)
				{
					ParseV2(array, j, num3, volume, driveType, prefetchIndex, cutoff, list);
				}
			}
			if (num2 <= lpInBuffer.StartUsn || num2 >= lpOutBuffer.NextUsn)
			{
				break;
			}
			lpInBuffer.StartUsn = num2;
		}
		return list;
	}

	private static void ParseV2(byte[] buffer, int offset, uint recordLength, string volume, string driveType, ulong? prefetchIndex, DateTime cutoff, List<UsnActivityRecord> target)
	{
		try
		{
			ulong fileReferenceNumber = BitConverter.ToUInt64(buffer, offset + 8);
			ulong num = BitConverter.ToUInt64(buffer, offset + 16);
			long usn = BitConverter.ToInt64(buffer, offset + 24);
			long fileTime = BitConverter.ToInt64(buffer, offset + 32);
			uint num2 = BitConverter.ToUInt32(buffer, offset + 40);
			ushort num3 = BitConverter.ToUInt16(buffer, offset + 56);
			ushort num4 = BitConverter.ToUInt16(buffer, offset + 58);
			if (num3 == 0 || num4 + num3 > recordLength)
			{
				return;
			}
			string text = Encoding.Unicode.GetString(buffer, offset + num4, num3);
			if (string.IsNullOrWhiteSpace(text))
			{
				return;
			}
			DateTime dateTime;
			try
			{
				dateTime = DateTime.FromFileTimeUtc(fileTime);
			}
			catch
			{
				return;
			}
			if (!(dateTime < cutoff) && !(dateTime > DateTime.UtcNow.AddDays(2.0)))
			{
				string text2 = Path.GetExtension(text).ToLowerInvariant();
				bool flag = InterestingExtensions.Contains(text2);
				bool flag2 = text.Equals("History", StringComparison.OrdinalIgnoreCase) || text.Equals("places.sqlite", StringComparison.OrdinalIgnoreCase) || text.Equals("Cookies", StringComparison.OrdinalIgnoreCase);
				bool flag3;
				switch (text2)
				{
				case ".pf":
				case ".evtx":
				case ".hve":
					flag3 = true;
					break;
				default:
					flag3 = false;
					break;
				}
				bool flag4 = flag3 || text.Equals("SRUDB.dat", StringComparison.OrdinalIgnoreCase) || text.Contains("ActivitiesCache", StringComparison.OrdinalIgnoreCase);
				if (flag || flag2 || flag4)
				{
					ulong num5 = num & 0xFFFFFFFFFFFFL;
					bool underPrefetchDirectory = prefetchIndex.HasValue && num5 == prefetchIndex.Value;
					target.Add(new UsnActivityRecord
					{
						Volume = volume,
						DriveType = driveType,
						FileName = text,
						Extension = text2,
						TimestampUtc = dateTime,
						Usn = usn,
						FileReferenceNumber = fileReferenceNumber,
						ParentFileReferenceNumber = num,
						ReasonMask = num2,
						Reasons = DescribeReasons(num2),
						Deleted = ((num2 & 0x200) != 0),
						Created = ((num2 & 0x100) != 0),
						Renamed = ((num2 & 0x3000) != 0),
						Modified = ((num2 & 7) != 0),
						UnderPrefetchDirectory = underPrefetchDirectory,
						BrowserDatabase = flag2,
						WindowsForensicArtifact = flag4
					});
				}
			}
		}
		catch
		{
		}
	}

	private static List<string> DescribeReasons(uint reason)
	{
		List<string> result = new List<string>();
		Add(1u, "DATA_OVERWRITE");
		Add(2u, "DATA_EXTEND");
		Add(4u, "DATA_TRUNCATION");
		Add(256u, "FILE_CREATE");
		Add(512u, "FILE_DELETE");
		Add(4096u, "RENAME_OLD_NAME");
		Add(8192u, "RENAME_NEW_NAME");
		Add(2147483648u, "CLOSE");
		return result;
		void Add(uint mask, string label)
		{
			if ((reason & mask) != 0)
			{
				result.Add(label);
			}
		}
	}

	private static ulong? GetFileIndex(string path)
	{
		if (!Directory.Exists(path))
		{
			return null;
		}
		using SafeFileHandle safeFileHandle = CreateFile(path, 128u, 7u, IntPtr.Zero, 3u, 33554432u, IntPtr.Zero);
		if (safeFileHandle.IsInvalid)
		{
			return null;
		}
		if (!GetFileInformationByHandle(safeFileHandle, out var lpFileInformation))
		{
			return null;
		}
		return (((ulong)lpFileInformation.FileIndexHigh << 32) | lpFileInformation.FileIndexLow) & 0xFFFFFFFFFFFFL;
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, nint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, nint hTemplateFile);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

	[DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeviceIoControlQuery(SafeFileHandle hDevice, uint dwIoControlCode, nint lpInBuffer, int nInBufferSize, out USN_JOURNAL_DATA_V0 lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, nint lpOverlapped);

	[DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeviceIoControlRead(SafeFileHandle hDevice, uint dwIoControlCode, ref READ_USN_JOURNAL_DATA_V0 lpInBuffer, int nInBufferSize, [Out] byte[] lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, nint lpOverlapped);
}
