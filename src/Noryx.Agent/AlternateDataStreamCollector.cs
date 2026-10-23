using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Noryx.Agent;

internal static class AlternateDataStreamCollector
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WIN32_FIND_STREAM_DATA
	{
		public long StreamSize;

		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
		public string cStreamName;
	}

	private sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private SafeFindHandle()
			: base(ownsHandle: true)
		{
		}

		protected override bool ReleaseHandle()
		{
			return FindClose(handle);
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool FindClose(nint hFindFile);
	}

	private const int FindStreamInfoStandard = 0;

	public static List<AlternateDataStreamRecord> Collect(List<FileRecord> files)
	{
		List<AlternateDataStreamRecord> list = new List<AlternateDataStreamRecord>();
		foreach (FileRecord file in files)
		{
			if (list.Count >= 2500)
			{
				break;
			}
			if (!string.IsNullOrWhiteSpace(file.Path) && File.Exists(file.Path))
			{
				try
				{
					CollectFile(file.Path, list);
				}
				catch
				{
				}
			}
		}
		return (from x in list.GroupBy<AlternateDataStreamRecord, string>((AlternateDataStreamRecord x) => x.Path + "|" + x.StreamName, StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(2500).ToList();
	}

	private static void CollectFile(string path, List<AlternateDataStreamRecord> result)
	{
		WIN32_FIND_STREAM_DATA lpFindStreamData;
		using SafeFindHandle safeFindHandle = FindFirstStreamW(path, 0, out lpFindStreamData, 0);
		if (safeFindHandle.IsInvalid)
		{
			return;
		}
		do
		{
			string text = lpFindStreamData.cStreamName ?? "";
			if (!IsDefaultStream(text) && !IsZoneIdentifier(text))
			{
				string text2 = text.Trim(':').Replace(":$DATA", "", StringComparison.OrdinalIgnoreCase);
				bool flag = Regex.IsMatch(text2, "\\.(exe|dll|sys|com|scr|bat|cmd|ps1|msi)$", RegexOptions.IgnoreCase) || Regex.IsMatch(text, "\\.(exe|dll|sys|com|scr|bat|cmd|ps1|msi):\\$DATA$", RegexOptions.IgnoreCase);
				bool suspicious = flag || text2.Contains("loader", StringComparison.OrdinalIgnoreCase) || text2.Contains("inject", StringComparison.OrdinalIgnoreCase) || text2.Contains("cheat", StringComparison.OrdinalIgnoreCase) || text2.Contains("script", StringComparison.OrdinalIgnoreCase);
				result.Add(new AlternateDataStreamRecord
				{
					Path = path,
					StreamName = text,
					StreamSize = lpFindStreamData.StreamSize,
					ExecutableLike = flag,
					Suspicious = suspicious
				});
			}
		}
		while (FindNextStreamW(safeFindHandle, out lpFindStreamData));
	}

	private static bool IsDefaultStream(string value)
	{
		return value.Equals("::$DATA", StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsZoneIdentifier(string value)
	{
		return value.Contains("Zone.Identifier", StringComparison.OrdinalIgnoreCase);
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern SafeFindHandle FindFirstStreamW(string lpFileName, int infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool FindNextStreamW(SafeFindHandle hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);
}
