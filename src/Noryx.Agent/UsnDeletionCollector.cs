using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Noryx.Agent;

internal static class UsnDeletionCollector
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

	private const uint GENERIC_READ = 2147483648u;

	private const uint FILE_SHARE_READ = 1u;

	private const uint FILE_SHARE_WRITE = 2u;

	private const uint FILE_SHARE_DELETE = 4u;

	private const uint OPEN_EXISTING = 3u;

	private const uint FSCTL_READ_USN_JOURNAL = 590011u;

	private const uint FSCTL_QUERY_USN_JOURNAL = 590068u;

	private const uint USN_REASON_FILE_DELETE = 512u;

	private const uint USN_REASON_RENAME_OLD_NAME = 4096u;

	public static List<DeletedUsnRecord> Collect()
	{
		List<DeletedUsnRecord> list = new List<DeletedUsnRecord>();
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			try
			{
				if (!driveInfo.IsReady || (driveInfo.DriveType != DriveType.Fixed && driveInfo.DriveType != DriveType.Removable) || !driveInfo.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				list.AddRange(CollectVolume(driveInfo.Name.TrimEnd('\\'), driveInfo.DriveType.ToString(), 6000));
				goto IL_007a;
			}
			catch
			{
				goto IL_007a;
			}
			IL_007a:
			if (list.Count >= 10000)
			{
				break;
			}
		}
		return (from x in list.OrderByDescending((DeletedUsnRecord x) => x.TimestampUtc).GroupBy<DeletedUsnRecord, string>((DeletedUsnRecord x) => $"{x.Volume}|{x.FileName}|{x.TimestampUtc:O}|{x.Reason}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(10000).ToList();
	}

	private static List<DeletedUsnRecord> CollectVolume(string volume, string driveType, int maxRecords)
	{
		List<DeletedUsnRecord> list = new List<DeletedUsnRecord>();
		using SafeFileHandle safeFileHandle = CreateFile("\\\\.\\" + volume, 2147483648u, 7u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
		if (safeFileHandle.IsInvalid)
		{
			return list;
		}
		if (!DeviceIoControlQuery(safeFileHandle, 590068u, IntPtr.Zero, 0, out var lpOutBuffer, Marshal.SizeOf<USN_JOURNAL_DATA_V0>(), out var _, IntPtr.Zero))
		{
			return list;
		}
		long num = 402653184L;
		long startUsn = Math.Max(lpOutBuffer.FirstUsn, lpOutBuffer.NextUsn - num);
		READ_USN_JOURNAL_DATA_V0 lpInBuffer = new READ_USN_JOURNAL_DATA_V0
		{
			StartUsn = startUsn,
			ReasonMask = 4608u,
			ReturnOnlyOnClose = 0u,
			Timeout = 0uL,
			BytesToWaitFor = 0uL,
			UsnJournalID = lpOutBuffer.UsnJournalID
		};
		byte[] array = new byte[1048576];
		DateTime cutoff = DateTime.UtcNow.AddDays(-120.0);
		for (int i = 0; i < 512; i++)
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
					ParseV2(array, j, num3, volume, driveType, cutoff, list);
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

	private static void ParseV2(byte[] buffer, int offset, uint recordLength, string volume, string driveType, DateTime cutoff, List<DeletedUsnRecord> target)
	{
		try
		{
			ulong fileReferenceNumber = BitConverter.ToUInt64(buffer, offset + 8);
			ulong parentFileReferenceNumber = BitConverter.ToUInt64(buffer, offset + 16);
			long usn = BitConverter.ToInt64(buffer, offset + 24);
			long fileTime = BitConverter.ToInt64(buffer, offset + 32);
			uint num = BitConverter.ToUInt32(buffer, offset + 40);
			ushort num2 = BitConverter.ToUInt16(buffer, offset + 56);
			ushort num3 = BitConverter.ToUInt16(buffer, offset + 58);
			bool flag = (num & 0x200) != 0;
			bool flag2 = (num & 0x1000) != 0;
			if ((!flag && !flag2) || num2 == 0 || num3 + num2 > recordLength)
			{
				return;
			}
			string text = Encoding.Unicode.GetString(buffer, offset + num3, num2);
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
			if (dateTime < cutoff || dateTime > DateTime.UtcNow.AddDays(2.0))
			{
				return;
			}
			string text2 = Path.GetExtension(text).ToLowerInvariant();
			if (text2 != null)
			{
				int length = text2.Length;
				if (length != 3)
				{
					if (length == 4)
					{
						switch (text2[2])
						{
						case 'x':
							break;
						case 'o':
							goto IL_018b;
						case 'c':
							goto IL_01a1;
						case 'l':
							goto IL_01b7;
						case 'y':
							goto IL_01c7;
						case 's':
							goto IL_01d7;
						case 'a':
							goto IL_01e7;
						case 'm':
							goto IL_0205;
						case 'i':
							goto IL_0215;
						default:
							goto IL_0238;
						}
						if (text2 == ".exe")
						{
							goto IL_0233;
						}
					}
				}
				else if (text2 == ".7z")
				{
					goto IL_0233;
				}
			}
			goto IL_0238;
			IL_01d7:
			if (text2 == ".msi")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_0233:
			bool flag3 = true;
			goto IL_023b;
			IL_0238:
			flag3 = false;
			goto IL_023b;
			IL_01c7:
			if (text2 == ".sys")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_01e7:
			if (text2 == ".bat" || text2 == ".rar")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_023b:
			if (flag3)
			{
				target.Add(new DeletedUsnRecord
				{
					Volume = volume,
					DriveType = driveType,
					FileName = text,
					Extension = text2,
					TimestampUtc = dateTime,
					Reason = (flag ? "FILE_DELETE" : "RENAME_OLD_NAME"),
					Usn = usn,
					FileReferenceNumber = fileReferenceNumber,
					ParentFileReferenceNumber = parentFileReferenceNumber,
					RandomLikeName = LooksRandomExecutableName(text),
					DeceptiveDoubleExtension = IsDoubleExtension(text)
				});
			}
			return;
			IL_01a1:
			if (text2 == ".scr")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_0215:
			if (text2 == ".zip")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_01b7:
			if (text2 == ".dll")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_018b:
			if (text2 == ".com")
			{
				goto IL_0233;
			}
			goto IL_0238;
			IL_0205:
			if (text2 == ".cmd")
			{
				goto IL_0233;
			}
			goto IL_0238;
		}
		catch
		{
		}
	}

	private static bool IsDoubleExtension(string value)
	{
		return Regex.IsMatch(Path.GetFileName(value), "\\.(zip|rar|7z|pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx|ppt|pptx)\\.exe$", RegexOptions.IgnoreCase);
	}

	private static bool LooksRandomExecutableName(string value)
	{
		if (!Path.GetExtension(value).Equals(".exe", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}
		string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(value);
		if (IsGenericInstallerStem(fileNameWithoutExtension) || HasReadableExecutableToken(fileNameWithoutExtension))
		{
			return false;
		}
		fileNameWithoutExtension = Regex.Replace(fileNameWithoutExtension, "\\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$", "", RegexOptions.IgnoreCase);
		if (fileNameWithoutExtension.Length < 4 || fileNameWithoutExtension.Length > 28 || !fileNameWithoutExtension.All(char.IsLetterOrDigit))
		{
			return false;
		}
		int num = fileNameWithoutExtension.Count(char.IsLetter);
		int num2 = fileNameWithoutExtension.Count(char.IsDigit);
		int num3 = fileNameWithoutExtension.Count((char ch) => "aeiouAEIOU".Contains(ch));
		int num4 = fileNameWithoutExtension.ToUpperInvariant().Distinct().Count();
		bool flag = fileNameWithoutExtension.All((char ch) => char.IsDigit(ch) || char.IsUpper(ch));
		double num5 = ((num > 0) ? ((double)num3 / (double)num) : 0.0);
		if (fileNameWithoutExtension.Length <= 5)
		{
			if (flag && num4 >= Math.Max(4, fileNameWithoutExtension.Length - 1) && (num2 >= 1 || num3 == 0))
			{
				return num5 <= 0.25;
			}
			return false;
		}
		if (flag && num4 >= Math.Min(6, fileNameWithoutExtension.Length - 1) && ((num2 >= 1) ? (num5 <= 0.35) : (num5 <= 0.12)))
		{
			return true;
		}
		if (fileNameWithoutExtension.Length >= 8 && fileNameWithoutExtension.Length <= 18 && num2 == 0 && num == fileNameWithoutExtension.Length && num4 >= 7 && num5 <= 0.22)
		{
			return true;
		}
		int num6 = 0;
		for (int num7 = 1; num7 < fileNameWithoutExtension.Length; num7++)
		{
			bool num8 = char.IsDigit(fileNameWithoutExtension[num7 - 1]);
			bool flag2 = char.IsDigit(fileNameWithoutExtension[num7]);
			if (num8 != flag2)
			{
				num6++;
			}
		}
		if (Regex.IsMatch(fileNameWithoutExtension, "^[A-Za-z]+[0-9]{1,4}$") && num >= 5 && num5 >= 0.16)
		{
			return false;
		}
		if (fileNameWithoutExtension.Length >= 10 && num >= 6 && num2 >= 2 && num4 >= 8)
		{
			if (num6 < 3)
			{
				return num5 <= 0.12;
			}
			return true;
		}
		return false;
	}

	private static bool IsGenericInstallerStem(string value)
	{
		switch ((value ?? "").Trim().ToLowerInvariant())
		{
		case "installer":
		case "uninstall":
		case "updater":
		case "install":
		case "setup32":
		case "setup64":
		case "setup":
		case "update":
		case "uninstaller":
		case "bootstrapper":
		case "launcherinstaller":
			return true;
		default:
			return false;
		}
	}

	private static bool HasReadableExecutableToken(string value)
	{
		string stem = (value ?? "").ToLowerInvariant().Replace("_", "").Replace("-", "")
			.Replace(".", "");
		return new string[33]
		{
			"installer", "install", "setup", "updater", "update", "uninstall", "bootstrapper", "launcher", "browser", "microsoft",
			"windows", "store", "opera", "avast", "crystal", "disk", "info", "control", "driver", "client",
			"helper", "service", "runtime", "manager", "discord", "chrome", "edge", "steam", "spotify", "firefox",
			"nvidia", "amd", "intel"
		}.Any((string token) => token.Length >= 4 && stem.Contains(token, StringComparison.OrdinalIgnoreCase));
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, nint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, nint hTemplateFile);

	[DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeviceIoControlQuery(SafeFileHandle hDevice, uint dwIoControlCode, nint lpInBuffer, int nInBufferSize, out USN_JOURNAL_DATA_V0 lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, nint lpOverlapped);

	[DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeviceIoControlRead(SafeFileHandle hDevice, uint dwIoControlCode, ref READ_USN_JOURNAL_DATA_V0 lpInBuffer, int nInBufferSize, [Out] byte[] lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, nint lpOverlapped);
}
