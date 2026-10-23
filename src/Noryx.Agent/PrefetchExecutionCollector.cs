using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Prefetch;
using Prefetch.Other;

namespace Noryx.Agent;

internal static class PrefetchExecutionCollector
{
	public static List<PrefetchExecutionRecord> Collect()
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
		List<PrefetchExecutionRecord> list = new List<PrefetchExecutionRecord>();
		if (!Directory.Exists(path))
		{
			return list;
		}
		Dictionary<string, DosDeviceRecord> deviceMap = GetDosDeviceMap();
		string text = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
		string value = QueryDevice(text);
		string value2 = QueryVolumeGuid(text);
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		if (!string.IsNullOrWhiteSpace(value))
		{
			hashSet.Add(NormalizeDevice(value));
		}
		if (!string.IsNullOrWhiteSpace(value2))
		{
			hashSet.Add(NormalizeDevice(value2));
		}
		foreach (string item in (from x in Directory.EnumerateFiles(path, "*.pf", SearchOption.TopDirectoryOnly)
			orderby SafeLastWriteUtc(x) descending
			select x).Take(1500))
		{
			try
			{
				using FileStream stream = new FileStream(item, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
				IPrefetch prefetch = PrefetchFile.Open(stream, item);
				string executableName = prefetch.Header.ExecutableFilename ?? "";
				string nativeExecutablePath = prefetch.Filenames.Where((string x) => !string.IsNullOrWhiteSpace(x)).FirstOrDefault((string x) => x.EndsWith("\\" + executableName, StringComparison.OrdinalIgnoreCase) || x.Equals(executableName, StringComparison.OrdinalIgnoreCase));
				string text2 = ResolveNativePath(nativeExecutablePath, deviceMap);
				bool? executablePresent = null;
				if (!string.IsNullOrWhiteSpace(text2))
				{
					try
					{
						executablePresent = File.Exists(text2);
					}
					catch
					{
						executablePresent = null;
					}
				}
				DateTime? lastRunUtc = ((IEnumerable<DateTimeOffset>)prefetch.LastRunTimes.OrderByDescending((DateTimeOffset x) => x.UtcDateTime)).Select((Func<DateTimeOffset, DateTime?>)((DateTimeOffset x) => x.UtcDateTime)).FirstOrDefault();
				List<PrefetchVolumeRecord> list2 = prefetch.VolumeInformation.Select(delegate(VolumeInfo v)
				{
					string text3 = v.DeviceName ?? "";
					string text4 = v.SerialNumber ?? "";
					string key = NormalizeDevice(text3);
					deviceMap.TryGetValue(key, out DosDeviceRecord value3);
					if (value3 == null && !string.IsNullOrWhiteSpace(text4))
					{
						deviceMap.TryGetValue("SERIAL:" + NormalizeSerial(text4), out value3);
					}
					return new PrefetchVolumeRecord
					{
						DeviceName = text3,
						SerialNumber = text4,
						CreationTimeUtc = v.CreationTime.UtcDateTime,
						CurrentDriveLetter = value3?.DriveLetter,
						CurrentDriveType = value3?.DriveType,
						CurrentlyMounted = (value3 != null)
					};
				}).ToList();
				PrefetchVolumeRecord prefetchVolumeRecord = null;
				if (!string.IsNullOrWhiteSpace(nativeExecutablePath))
				{
					prefetchVolumeRecord = list2.OrderByDescending((PrefetchVolumeRecord v) => v.DeviceName.Length).FirstOrDefault((PrefetchVolumeRecord v) => nativeExecutablePath.StartsWith(v.DeviceName, StringComparison.OrdinalIgnoreCase));
				}
				bool volumeNotMounted = prefetchVolumeRecord != null && !prefetchVolumeRecord.CurrentlyMounted;
				bool flag = prefetchVolumeRecord != null && prefetchVolumeRecord.CurrentDriveType?.Equals(DriveType.Removable.ToString(), StringComparison.OrdinalIgnoreCase) == true;
				bool num = LooksLikeWindowsSystemPath(nativeExecutablePath, text2);
				bool nonSystemVolume = prefetchVolumeRecord != null && (string.IsNullOrWhiteSpace(prefetchVolumeRecord.CurrentDriveLetter) ? (!hashSet.Contains(NormalizeDevice(prefetchVolumeRecord.DeviceName))) : (!prefetchVolumeRecord.CurrentDriveLetter.Equals(text.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)));
				bool likelyDetachedOrRemovable = !num && flag;
				list.Add(new PrefetchExecutionRecord
				{
					ExecutableName = executableName,
					PrefetchFile = Path.GetFileName(item),
					PrefetchHash = (prefetch.Header.Hash ?? ""),
					Version = prefetch.Header.Version.ToString(),
					RunCount = prefetch.RunCount,
					LastRunTimesUtc = (from x in prefetch.LastRunTimes.OrderByDescending((DateTimeOffset x) => x.UtcDateTime).Take(8)
						select x.UtcDateTime).ToList(),
					LastRunUtc = lastRunUtc,
					NativeExecutablePath = nativeExecutablePath,
					ResolvedExecutablePath = text2,
					ExecutablePresent = executablePresent,
					VolumeNotMounted = volumeNotMounted,
					CurrentRemovable = flag,
					NonSystemVolume = nonSystemVolume,
					LikelyDetachedOrRemovable = likelyDetachedOrRemovable,
					Volumes = list2
				});
			}
			catch
			{
			}
		}
		return list.OrderByDescending((PrefetchExecutionRecord x) => x.LastRunUtc ?? DateTime.MinValue).Take(1200).ToList();
	}

	private static Dictionary<string, DosDeviceRecord> GetDosDeviceMap()
	{
		Dictionary<string, DosDeviceRecord> dictionary = new Dictionary<string, DosDeviceRecord>(StringComparer.OrdinalIgnoreCase);
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			string driveLetter = driveInfo.Name.TrimEnd('\\');
			string text = QueryDevice(driveLetter);
			if (!string.IsNullOrWhiteSpace(text))
			{
				DosDeviceRecord dosDeviceRecord = new DosDeviceRecord
				{
					DriveLetter = driveLetter,
					DevicePath = text,
					VolumeGuidPath = (QueryVolumeGuid(driveLetter) ?? ""),
					VolumeSerialNumber = (QueryVolumeSerial(driveLetter) ?? ""),
					DriveType = driveInfo.DriveType.ToString()
				};
				dictionary[NormalizeDevice(text)] = dosDeviceRecord;
				if (!string.IsNullOrWhiteSpace(dosDeviceRecord.VolumeGuidPath))
				{
					dictionary[NormalizeDevice(dosDeviceRecord.VolumeGuidPath)] = dosDeviceRecord;
				}
				if (!string.IsNullOrWhiteSpace(dosDeviceRecord.VolumeSerialNumber))
				{
					dictionary["SERIAL:" + NormalizeSerial(dosDeviceRecord.VolumeSerialNumber)] = dosDeviceRecord;
				}
			}
		}
		return dictionary;
	}

	private static string? ResolveNativePath(string? nativePath, Dictionary<string, DosDeviceRecord> deviceMap)
	{
		if (string.IsNullOrWhiteSpace(nativePath))
		{
			return null;
		}
		string text = NormalizeDevice(nativePath);
		foreach (KeyValuePair<string, DosDeviceRecord> item in deviceMap.OrderByDescending<KeyValuePair<string, DosDeviceRecord>, int>((KeyValuePair<string, DosDeviceRecord> x) => x.Key.Length))
		{
			if (text.StartsWith(item.Key, StringComparison.OrdinalIgnoreCase))
			{
				string text2 = text;
				int length = item.Key.Length;
				string text3 = text2.Substring(length, text2.Length - length).TrimStart('\\');
				return item.Value.DriveLetter + "\\" + text3;
			}
		}
		return null;
	}

	private static string? QueryDevice(string driveLetter)
	{
		try
		{
			StringBuilder stringBuilder = new StringBuilder(1024);
			return (QueryDosDevice(driveLetter.TrimEnd('\\'), stringBuilder, stringBuilder.Capacity) == 0) ? null : stringBuilder.ToString();
		}
		catch
		{
			return null;
		}
	}

	private static string? QueryVolumeGuid(string driveLetter)
	{
		try
		{
			string lpszVolumeMountPoint = driveLetter.TrimEnd('\\') + "\\";
			StringBuilder stringBuilder = new StringBuilder(1024);
			return GetVolumeNameForVolumeMountPoint(lpszVolumeMountPoint, stringBuilder, stringBuilder.Capacity) ? stringBuilder.ToString() : null;
		}
		catch
		{
			return null;
		}
	}

	private static string? QueryVolumeSerial(string driveLetter)
	{
		try
		{
			string lpRootPathName = driveLetter.TrimEnd('\\') + "\\";
			StringBuilder stringBuilder = new StringBuilder(261);
			StringBuilder stringBuilder2 = new StringBuilder(261);
			if (!GetVolumeInformation(lpRootPathName, stringBuilder, stringBuilder.Capacity, out var lpVolumeSerialNumber, out var _, out var _, stringBuilder2, stringBuilder2.Capacity))
			{
				return null;
			}
			return lpVolumeSerialNumber.ToString("X8");
		}
		catch
		{
			return null;
		}
	}

	private static string NormalizeSerial(string? value)
	{
		return new string((value ?? "").Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
	}

	private static bool LooksLikeWindowsSystemPath(string? nativePath, string? resolvedPath)
	{
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		if (!string.IsNullOrWhiteSpace(resolvedPath) && !string.IsNullOrWhiteSpace(folderPath))
		{
			try
			{
				string fullPath = Path.GetFullPath(resolvedPath);
				string value = Path.GetFullPath(folderPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
				if (fullPath.StartsWith(value, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			catch
			{
			}
		}
		string text = NormalizeDevice(nativePath);
		if (!text.Contains("\\WINDOWS\\", StringComparison.OrdinalIgnoreCase))
		{
			return text.EndsWith("\\WINDOWS", StringComparison.OrdinalIgnoreCase);
		}
		return true;
	}

	private static string NormalizeDevice(string? value)
	{
		string text = (value ?? "").Trim().TrimEnd('\\').ToUpperInvariant();
		if (text.StartsWith("\\\\?\\VOLUME{", StringComparison.OrdinalIgnoreCase))
		{
			string text2 = text;
			text = "\\" + text2.Substring(4, text2.Length - 4);
		}
		return text;
	}

	private static DateTime SafeLastWriteUtc(string path)
	{
		try
		{
			return File.GetLastWriteTimeUtc(path);
		}
		catch
		{
			return DateTime.MinValue;
		}
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetVolumeNameForVolumeMountPoint(string lpszVolumeMountPoint, StringBuilder lpszVolumeName, int cchBufferLength);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetVolumeInformation(string lpRootPathName, StringBuilder lpVolumeNameBuffer, int nVolumeNameSize, out uint lpVolumeSerialNumber, out uint lpMaximumComponentLength, out uint lpFileSystemFlags, StringBuilder lpFileSystemNameBuffer, int nFileSystemNameSize);
}
