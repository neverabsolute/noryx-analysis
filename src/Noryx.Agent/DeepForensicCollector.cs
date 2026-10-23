using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class DeepForensicCollector
{
	public static List<ProcessCreationRecord> CollectProcessCreationEvents()
	{
		List<ProcessCreationRecord> list = new List<ProcessCreationRecord>();
		foreach (string item in QueryEvents("Security", "*[System[(EventID=4688)]]", 700, 15000))
		{
			try
			{
				XDocument doc = XDocument.Parse(item);
				XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
				DateTime timeCreatedUtc = EventTime(doc, ns);
				Dictionary<string, string> data = EventData(doc, ns);
				string data2 = GetData(data, "NewProcessName");
				string data3 = GetData(data, "ParentProcessName");
				if (!string.IsNullOrWhiteSpace(data2))
				{
					list.Add(new ProcessCreationRecord
					{
						TimeCreatedUtc = timeCreatedUtc,
						ProcessPath = data2,
						ProcessName = Path.GetFileName(data2),
						ParentProcessPath = data3,
						ParentProcessName = Path.GetFileName(data3),
						ProcessPresent = SafeFileExists(data2),
						DriveType = GetDriveType(data2)
					});
				}
			}
			catch
			{
			}
		}
		return list.OrderByDescending((ProcessCreationRecord x) => x.TimeCreatedUtc).Take(700).ToList();
	}

	public static List<ProcessTerminationRecord> CollectProcessTerminationEvents()
	{
		List<ProcessTerminationRecord> list = new List<ProcessTerminationRecord>();
		foreach (string item in QueryEvents("Security", "*[System[(EventID=4689)]]", 700, 15000))
		{
			try
			{
				XDocument doc = XDocument.Parse(item);
				XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
				DateTime timeCreatedUtc = EventTime(doc, ns);
				Dictionary<string, string> data = EventData(doc, ns);
				string text = FirstNonEmpty(GetData(data, "ProcessName"), GetData(data, "Process Name"));
				string processId = FirstNonEmpty(GetData(data, "ProcessId"), GetData(data, "Process ID"));
				string exitStatus = FirstNonEmpty(GetData(data, "Status"), GetData(data, "ExitStatus"), GetData(data, "Exit Status"));
				if (!string.IsNullOrWhiteSpace(text))
				{
					list.Add(new ProcessTerminationRecord
					{
						TimeCreatedUtc = timeCreatedUtc,
						ProcessPath = text,
						ProcessName = Path.GetFileName(text),
						ProcessId = processId,
						ExitStatus = exitStatus
					});
				}
			}
			catch
			{
			}
		}
		return list.OrderByDescending((ProcessTerminationRecord x) => x.TimeCreatedUtc).Take(700).ToList();
	}

	public static List<DefenderDetectionRecord> CollectDefenderDetections()
	{
		List<DefenderDetectionRecord> list = new List<DefenderDetectionRecord>();
		foreach (string item in QueryEvents("Microsoft-Windows-Windows Defender/Operational", "*[System[(EventID=1116 or EventID=1117)]]", 250, 12000))
		{
			try
			{
				XDocument xDocument = XDocument.Parse(item);
				XNamespace xNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
				int result;
				int eventId = (int.TryParse((xDocument.Root?.Element(xNamespace + "System"))?.Element(xNamespace + "EventID")?.Value, out result) ? result : 0);
				Dictionary<string, string> dictionary = EventData(xDocument, xNamespace);
				string text = FirstNonEmpty(GetData(dictionary, "Threat Name"), GetData(dictionary, "ThreatName"), GetData(dictionary, "Name"));
				string text2 = FirstNonEmpty(GetData(dictionary, "Path"), GetData(dictionary, "Process Name"), GetData(dictionary, "ProcessName"));
				string action = FirstNonEmpty(GetData(dictionary, "Action Name"), GetData(dictionary, "ActionName"), GetData(dictionary, "Action"));
				string detectionOrigin = FirstNonEmpty(GetData(dictionary, "Detection Origin"), GetData(dictionary, "DetectionOrigin"));
				if (string.IsNullOrWhiteSpace(text) && string.IsNullOrWhiteSpace(text2))
				{
					string text3 = string.Join(" | ", from x in dictionary
						where IsUsefulDefenderField(x.Key)
						select x.Key + "=" + x.Value);
					if (!string.IsNullOrWhiteSpace(text3))
					{
						list.Add(new DefenderDetectionRecord
						{
							EventId = eventId,
							TimeCreatedUtc = EventTime(xDocument, xNamespace),
							ThreatName = text3,
							Path = "",
							Action = action,
							DetectionOrigin = detectionOrigin
						});
					}
				}
				else
				{
					list.Add(new DefenderDetectionRecord
					{
						EventId = eventId,
						TimeCreatedUtc = EventTime(xDocument, xNamespace),
						ThreatName = text,
						Path = text2,
						Action = action,
						DetectionOrigin = detectionOrigin
					});
				}
			}
			catch
			{
			}
		}
		return list.OrderByDescending((DefenderDetectionRecord x) => x.TimeCreatedUtc).Take(250).ToList();
	}

	public static List<RecentShortcutRecord> CollectRecentShortcuts()
	{
		List<RecentShortcutRecord> list = new List<RecentShortcutRecord>();
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
		if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
		{
			return list;
		}
		object obj = null;
		try
		{
			Type typeFromProgID = Type.GetTypeFromProgID("WScript.Shell");
			if (typeFromProgID == null)
			{
				return list;
			}
			obj = Activator.CreateInstance(typeFromProgID);
			if (obj == null)
			{
				return list;
			}
			foreach (string item in Directory.EnumerateFiles(folderPath, "*.lnk", SearchOption.TopDirectoryOnly).OrderByDescending(SafeLastWriteUtc).Take(600))
			{
				try
				{
					object obj2 = typeFromProgID.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, obj, new object[1] { item });
					if (obj2 != null)
					{
						string text = Convert.ToString(obj2.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, obj2, null)) ?? "";
						string workingDirectory = Convert.ToString(obj2.GetType().InvokeMember("WorkingDirectory", BindingFlags.GetProperty, null, obj2, null)) ?? "";
						list.Add(new RecentShortcutRecord
						{
							ShortcutName = Path.GetFileName(item),
							ShortcutLastWriteUtc = SafeLastWriteUtc(item),
							TargetPath = text,
							WorkingDirectory = workingDirectory,
							TargetExists = SafeFileExists(text)
						});
					}
				}
				catch
				{
				}
			}
		}
		catch
		{
		}
		finally
		{
			if (obj != null && MarshalIsComObject(obj))
			{
				try
				{
					Marshal.FinalReleaseComObject(obj);
				}
				catch
				{
				}
			}
		}
		return list;
	}

	public static List<ExtensionMismatchRecord> CollectModifiedExtensions()
	{
		string[] source = new string[4]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
			Path.GetTempPath(),
			Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
		};
		List<ExtensionMismatchRecord> list = new List<ExtensionMismatchRecord>();
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		foreach (string item in source.Where(Directory.Exists))
		{
			foreach (string item2 in EnumerateFilesLimited(item, 2, 2500))
			{
				if (list.Count >= 300)
				{
					return list;
				}
				if (!hashSet.Add(item2) || !IsDeceptiveDocumentExtension(Path.GetExtension(item2)))
				{
					continue;
				}
				try
				{
					FileInfo fileInfo = new FileInfo(item2);
					if (!fileInfo.Exists || fileInfo.Length < 64 || fileInfo.Length > 524288000)
					{
						continue;
					}
					using FileStream fileStream = new FileStream(item2, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
					byte[] array = new byte[2];
					if (fileStream.Read(array) == 2 && array[0] == 77 && array[1] == 90)
					{
						list.Add(new ExtensionMismatchRecord
						{
							Name = fileInfo.Name,
							Path = fileInfo.FullName,
							Extension = fileInfo.Extension,
							Size = fileInfo.Length,
							LastWriteUtc = fileInfo.LastWriteTimeUtc,
							Reason = "Arquivo possui cabeçalho PE/MZ mas extensão não executável."
						});
					}
				}
				catch
				{
				}
			}
		}
		return list;
	}

	public static List<DefenderExclusionRecord> CollectDefenderExclusions()
	{
		List<DefenderExclusionRecord> list = new List<DefenderExclusionRecord>();
		string[] array = new string[3] { "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes", "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions" };
		foreach (string text in array)
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(text);
				if (registryKey == null)
				{
					continue;
				}
				string[] valueNames = registryKey.GetValueNames();
				foreach (string value in valueNames)
				{
					if (!string.IsNullOrWhiteSpace(value))
					{
						list.Add(new DefenderExclusionRecord
						{
							Category = text.Split('\\').Last(),
							Value = value
						});
					}
				}
			}
			catch
			{
			}
		}
		return list.Take(300).ToList();
	}

	public static List<BootIntegrityRecord> CollectBootIntegrityFlags()
	{
		List<BootIntegrityRecord> list = new List<BootIntegrityRecord>();
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "bcdedit.exe",
				Arguments = "/enum {current}",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return list;
			}
			string text = process.StandardOutput.ReadToEnd();
			process.StandardError.ReadToEnd();
			if (!process.WaitForExit(8000))
			{
				try
				{
					process.Kill(entireProcessTree: true);
				}
				catch
				{
				}
				return list;
			}
			string[] array = text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
			for (int i = 0; i < array.Length; i++)
			{
				string text2 = array[i].Trim();
				string text3 = text2.ToLowerInvariant();
				if (text3.Contains("testsigning") || text3.Contains("nointegritychecks") || Regex.IsMatch(text3, "^debug\\s+"))
				{
					string[] array2 = Regex.Split(text2, "\\s{2,}");
					list.Add(new BootIntegrityRecord
					{
						Setting = (array2.FirstOrDefault() ?? text2),
						Value = ((array2.Length > 1) ? array2[^1] : ""),
						Raw = text2
					});
				}
			}
		}
		catch
		{
		}
		return list;
	}

	public static ActivityHistoryState CollectActivityHistoryState()
	{
		ActivityHistoryState activityHistoryState = new ActivityHistoryState();
		try
		{
			using RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
			activityHistoryState.EnableActivityFeed = ReadDword(key, "EnableActivityFeed");
			activityHistoryState.PublishUserActivities = ReadDword(key, "PublishUserActivities");
			activityHistoryState.UploadUserActivities = ReadDword(key, "UploadUserActivities");
		}
		catch
		{
		}
		return activityHistoryState;
	}

	public static List<SystemTimeChangeRecord> CollectSystemTimeChanges()
	{
		List<SystemTimeChangeRecord> list = new List<SystemTimeChangeRecord>();
		foreach (string item in QueryEvents("Security", "*[System[(EventID=4616)]]", 50, 10000))
		{
			try
			{
				XDocument doc = XDocument.Parse(item);
				XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
				Dictionary<string, string> data = EventData(doc, ns);
				list.Add(new SystemTimeChangeRecord
				{
					TimeCreatedUtc = EventTime(doc, ns),
					PreviousTime = GetData(data, "PreviousTime"),
					NewTime = GetData(data, "NewTime"),
					ProcessName = GetData(data, "ProcessName")
				});
			}
			catch
			{
			}
		}
		return list.OrderByDescending((SystemTimeChangeRecord x) => x.TimeCreatedUtc).ToList();
	}

	public static List<VirtualDiskRecord> CollectVirtualDiskIndicators()
	{
		List<VirtualDiskRecord> list = new List<VirtualDiskRecord>();
		try
		{
			using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Model,Caption,DeviceID,InterfaceType,PNPDeviceID FROM Win32_DiskDrive");
			foreach (ManagementObject item in managementObjectSearcher.Get())
			{
				string text = Convert.ToString(item["Model"]) ?? "";
				string text2 = Convert.ToString(item["Caption"]) ?? "";
				string text3 = Convert.ToString(item["PNPDeviceID"]) ?? "";
				string text4 = Convert.ToString(item["InterfaceType"]) ?? "";
				string text5 = string.Join(" ", text, text2, text3, text4).ToLowerInvariant();
				if (text5.Contains("virtual") || text5.Contains("vhd") || text5.Contains("imdisk") || text5.Contains("osfmount") || text5.Contains("arsenal image mounter"))
				{
					list.Add(new VirtualDiskRecord
					{
						Model = text,
						Caption = text2,
						DeviceId = (Convert.ToString(item["DeviceID"]) ?? ""),
						InterfaceType = text4,
						PnpDeviceId = text3
					});
				}
			}
		}
		catch
		{
		}
		return list;
	}

	public static List<RustModuleRecord> CollectRustModules()
	{
		List<RustModuleRecord> list = new List<RustModuleRecord>();
		Process[] array = (from p in Process.GetProcesses()
			where p.ProcessName.Equals("RustClient", StringComparison.OrdinalIgnoreCase) || p.ProcessName.Equals("Rust", StringComparison.OrdinalIgnoreCase)
			select p).ToArray();
		foreach (Process process in array)
		{
			try
			{
				string text = null;
				try
				{
					text = process.MainModule?.FileName;
				}
				catch
				{
				}
				string text2 = ((!string.IsNullOrWhiteSpace(text)) ? (Path.GetDirectoryName(text) ?? "") : "");
				foreach (ProcessModule module in process.Modules)
				{
					try
					{
						string text3 = module.FileName ?? "";
						if (!string.IsNullOrWhiteSpace(text3))
						{
							(bool Signed, string Subject) tuple = TrySigner(text3);
							bool item = tuple.Signed;
							string item2 = tuple.Subject;
							string companyName = "";
							try
							{
								companyName = FileVersionInfo.GetVersionInfo(text3).CompanyName ?? "";
							}
							catch
							{
							}
							list.Add(new RustModuleRecord
							{
								ProcessId = process.Id,
								ProcessName = process.ProcessName,
								ModuleName = (module.ModuleName ?? Path.GetFileName(text3)),
								Path = text3,
								Signed = item,
								SignerSubject = item2,
								CompanyName = companyName,
								UnderGameDirectory = (!string.IsNullOrWhiteSpace(text2) && IsPathUnder(text3, text2)),
								UnderWindows = IsPathUnder(text3, Environment.GetFolderPath(Environment.SpecialFolder.Windows)),
								UnderProgramFiles = (IsPathUnder(text3, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)) || IsPathUnder(text3, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86))),
								UnderUserProfile = IsPathUnder(text3, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
								UnderTemp = IsPathUnder(text3, Path.GetTempPath())
							});
						}
					}
					catch
					{
					}
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
		return (from x in list.GroupBy<RustModuleRecord, string>((RustModuleRecord x) => $"{x.ProcessId}|{x.Path}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(1200).ToList();
	}

	public static List<UsnJournalStateRecord> CollectUsnJournalState()
	{
		List<UsnJournalStateRecord> list = new List<UsnJournalStateRecord>();
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			try
			{
				if (!driveInfo.IsReady || driveInfo.DriveType != DriveType.Fixed || !driveInfo.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				string text = driveInfo.Name.TrimEnd('\\');
				using Process process = Process.Start(new ProcessStartInfo
				{
					FileName = "fsutil.exe",
					Arguments = "usn queryjournal " + text,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					UseShellExecute = false,
					CreateNoWindow = true
				});
				if (process == null)
				{
					continue;
				}
				string text2 = process.StandardOutput.ReadToEnd();
				string text3 = process.StandardError.ReadToEnd();
				if (!process.WaitForExit(8000))
				{
					try
					{
						process.Kill(entireProcessTree: true);
					}
					catch
					{
					}
				}
				else
				{
					list.Add(new UsnJournalStateRecord
					{
						Volume = text,
						Active = (process.ExitCode == 0),
						Detail = ((process.ExitCode == 0) ? FirstLines(text2, 12) : FirstLines(text3, 8))
					});
				}
			}
			catch
			{
			}
		}
		return list;
	}

	private static List<string> QueryEvents(string logName, string query, int count, int timeoutMs)
	{
		List<string> list = new List<string>();
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "wevtutil.exe",
				Arguments = $"qe \"{logName}\" /q:\"{query}\" /f:xml /rd:true /c:{count}",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return list;
			}
			string text = process.StandardOutput.ReadToEnd();
			process.StandardError.ReadToEnd();
			if (!process.WaitForExit(timeoutMs))
			{
				try
				{
					process.Kill(entireProcessTree: true);
				}
				catch
				{
				}
				return list;
			}
			if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(text))
			{
				return list;
			}
			foreach (Match item in Regex.Matches(text, "<Event\\b.*?</Event>", RegexOptions.IgnoreCase | RegexOptions.Singleline))
			{
				list.Add(item.Value);
			}
		}
		catch
		{
		}
		return list;
	}

	private static Dictionary<string, string> EventData(XDocument doc, XNamespace ns)
	{
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		foreach (XElement item in doc.Descendants(ns + "Data"))
		{
			string text = item.Attribute("Name")?.Value ?? "";
			if (!string.IsNullOrWhiteSpace(text))
			{
				dictionary[text] = (item.Value ?? "").Trim();
			}
		}
		return dictionary;
	}

	private static DateTime EventTime(XDocument doc, XNamespace ns)
	{
		if (!DateTimeOffset.TryParse(doc.Root?.Element(ns + "System")?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value, out var result))
		{
			return DateTime.UtcNow;
		}
		return result.UtcDateTime;
	}

	private static string GetData(Dictionary<string, string> data, string name)
	{
		if (!data.TryGetValue(name, out string value))
		{
			return "";
		}
		return value;
	}

	private static bool IsUsefulDefenderField(string name)
	{
		string text = name.ToLowerInvariant();
		if (!text.Contains("threat") && !text.Contains("path") && !text.Contains("action"))
		{
			return text.Contains("detection");
		}
		return true;
	}

	private static int? ReadDword(RegistryKey? key, string name)
	{
		object obj = key?.GetValue(name);
		if (obj is int)
		{
			return (int)obj;
		}
		return null;
	}

	private static bool IsDeceptiveDocumentExtension(string ext)
	{
		return new string[37]
		{
			".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg", ".jpg", ".jpeg", ".png",
			".gif", ".bmp", ".webp", ".ico", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
			".pptx", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp3", ".wav", ".ogg", ".mp4",
			".avi", ".mkv", ".mov", ".html", ".htm", ".css", ".md"
		}.Contains<string>(ext, StringComparer.OrdinalIgnoreCase);
	}

	private static IEnumerable<string> EnumerateFilesLimited(string root, int maxDepth, int maxFiles)
	{
		Queue<(string Path, int Depth)> queue = new Queue<(string, int)>();
		queue.Enqueue((root, 0));
		int yielded = 0;
		while (queue.Count > 0 && yielded < maxFiles)
		{
			var (current, depth) = queue.Dequeue();
			IEnumerable<string> enumerable;
			try
			{
				enumerable = Directory.EnumerateFiles(current);
			}
			catch
			{
				continue;
			}
			foreach (string item in enumerable)
			{
				yield return item;
				yielded++;
				if (yielded >= maxFiles)
				{
					yield break;
				}
			}
			if (depth >= maxDepth)
			{
				continue;
			}
			IEnumerable<string> source;
			try
			{
				source = Directory.EnumerateDirectories(current);
			}
			catch
			{
				continue;
			}
			foreach (string item2 in source.Take(180))
			{
				queue.Enqueue((item2, depth + 1));
			}
		}
	}

	private static bool SafeFileExists(string path)
	{
		try
		{
			return !string.IsNullOrWhiteSpace(path) && File.Exists(path);
		}
		catch
		{
			return false;
		}
	}

	private static string GetDriveType(string path)
	{
		try
		{
			if (string.IsNullOrWhiteSpace(path))
			{
				return "";
			}
			if (path.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase))
			{
				return "Network";
			}
			string pathRoot = Path.GetPathRoot(path);
			if (string.IsNullOrWhiteSpace(pathRoot))
			{
				return "";
			}
			return new DriveInfo(pathRoot).DriveType.ToString();
		}
		catch
		{
			return "";
		}
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

	private static (bool Signed, string Subject) TrySigner(string path)
	{
		return AuthenticodeVerifier.Verify(path);
	}

	private static bool IsPathUnder(string path, string root)
	{
		if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root))
		{
			return false;
		}
		try
		{
			string text = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
			string value = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
			return text.StartsWith(value, StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}

	private static bool MarshalIsComObject(object value)
	{
		try
		{
			return Marshal.IsComObject(value);
		}
		catch
		{
			return false;
		}
	}

	private static string FirstNonEmpty(params string[] values)
	{
		return values.FirstOrDefault((string x) => !string.IsNullOrWhiteSpace(x)) ?? "";
	}

	private static string FirstLines(string text, int count)
	{
		return string.Join("\n", (text ?? "").Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Take(count));
	}
}
