using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class AdvancedCollectors
{
	public static List<BamRecord> CollectBam()
	{
		List<BamRecord> list = new List<BamRecord>();
		using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");
		if (registryKey == null)
		{
			using (RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings"))
			{
				return (registryKey2 == null) ? list : ReadBamRoot(registryKey2);
			}
		}
		return ReadBamRoot(registryKey);
	}

	private static List<BamRecord> ReadBamRoot(RegistryKey root)
	{
		List<BamRecord> list = new List<BamRecord>();
		string[] subKeyNames = root.GetSubKeyNames();
		foreach (string text in subKeyNames)
		{
			using RegistryKey registryKey = root.OpenSubKey(text);
			if (registryKey == null)
			{
				continue;
			}
			string[] valueNames = registryKey.GetValueNames();
			foreach (string text2 in valueNames)
			{
				if (string.IsNullOrWhiteSpace(text2) || text2.StartsWith("Version", StringComparison.OrdinalIgnoreCase) || text2.StartsWith("SequenceNumber", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				object? value = registryKey.GetValue(text2);
				DateTime? lastExecutionUtc = null;
				if (value is byte[] array && array.Length >= 8)
				{
					try
					{
						long num = BitConverter.ToInt64(array, 0);
						if (num > 0)
						{
							lastExecutionUtc = DateTime.FromFileTimeUtc(num);
						}
					}
					catch
					{
					}
				}
				list.Add(new BamRecord
				{
					Sid = text,
					Path = text2,
					LastExecutionUtc = lastExecutionUtc,
					FileExists = SafeFileExists(text2)
				});
			}
		}
		return list.OrderByDescending((BamRecord x) => x.LastExecutionUtc ?? DateTime.MinValue).Take(5000).ToList();
	}

	public static List<UserAssistRecord> CollectUserAssist()
	{
		List<UserAssistRecord> list = new List<UserAssistRecord>();
		using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
		if (registryKey == null)
		{
			return list;
		}
		string[] subKeyNames = registryKey.GetSubKeyNames();
		foreach (string text in subKeyNames)
		{
			using RegistryKey registryKey2 = registryKey.OpenSubKey(text + "\\Count");
			if (registryKey2 == null)
			{
				continue;
			}
			string[] valueNames = registryKey2.GetValueNames();
			foreach (string text2 in valueNames)
			{
				string decodedName = Rot13(text2);
				object? value = registryKey2.GetValue(text2);
				DateTime? lastExecutionUtc = null;
				int? runCount = null;
				int dataLength = 0;
				if (value is byte[] array)
				{
					dataLength = array.Length;
					if (array.Length >= 8)
					{
						try
						{
							int num = BitConverter.ToInt32(array, 4);
							if (num >= 0)
							{
								runCount = num;
							}
						}
						catch
						{
						}
					}
					if (array.Length >= 68)
					{
						try
						{
							long num2 = BitConverter.ToInt64(array, 60);
							if (num2 > 0)
							{
								DateTime dateTime = DateTime.FromFileTimeUtc(num2);
								if (dateTime.Year >= 2000 && dateTime <= DateTime.UtcNow.AddDays(2.0))
								{
									lastExecutionUtc = dateTime;
								}
							}
						}
						catch
						{
						}
					}
				}
				list.Add(new UserAssistRecord
				{
					Guid = text,
					EncodedName = text2,
					DecodedName = decodedName,
					DataLength = dataLength,
					RunCount = runCount,
					LastExecutionUtc = lastExecutionUtc
				});
			}
		}
		return list.Take(5000).ToList();
	}

	public static List<MuiCacheRecord> CollectMuiCache()
	{
		List<MuiCacheRecord> list = new List<MuiCacheRecord>();
		string[] array = new string[2] { "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache" };
		foreach (string text in array)
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(text);
			if (registryKey == null)
			{
				continue;
			}
			string[] valueNames = registryKey.GetValueNames();
			foreach (string text2 in valueNames)
			{
				if (!string.IsNullOrWhiteSpace(text2))
				{
					list.Add(new MuiCacheRecord
					{
						RegistryPath = text,
						Path = text2,
						DisplayName = (Convert.ToString(registryKey.GetValue(text2)) ?? ""),
						FileExists = SafeFileExists(text2)
					});
				}
			}
		}
		return (from x in list.GroupBy<MuiCacheRecord, string>((MuiCacheRecord x) => x.RegistryPath + "|" + x.Path, StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(5000).ToList();
	}

	public static List<PcaRecord> CollectPcaStore()
	{
		List<PcaRecord> list = new List<PcaRecord>();
		string[] array = new string[2] { "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted" };
		foreach (string text in array)
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(text);
			if (registryKey == null)
			{
				continue;
			}
			string[] valueNames = registryKey.GetValueNames();
			foreach (string text2 in valueNames)
			{
				if (!string.IsNullOrWhiteSpace(text2))
				{
					list.Add(new PcaRecord
					{
						Source = (text.EndsWith("Store", StringComparison.OrdinalIgnoreCase) ? "PCA Store" : "PCA Persisted"),
						Path = text2,
						FileExists = SafeFileExists(text2)
					});
				}
			}
		}
		return (from x in list.GroupBy<PcaRecord, string>((PcaRecord x) => x.Source + "|" + x.Path, StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(5000).ToList();
	}

	public static List<SetupApiUsbRecord> CollectSetupApiUsb()
	{
		List<SetupApiUsbRecord> list = new List<SetupApiUsbRecord>();
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", "setupapi.dev.log");
		if (!File.Exists(path))
		{
			return list;
		}
		int num = 0;
		string section = "";
		DateTime? sectionTimeUtc = null;
		foreach (string item in File.ReadLines(path))
		{
			num++;
			string text = item.Trim();
			if (text.StartsWith(">>> [", StringComparison.Ordinal))
			{
				section = ((text.Length > 300) ? text.Substring(0, 300) : text);
				sectionTimeUtc = null;
				continue;
			}
			if (text.Contains("Section start", StringComparison.OrdinalIgnoreCase))
			{
				string text2 = text;
				int num2 = text.IndexOf("Section start", StringComparison.OrdinalIgnoreCase) + "Section start".Length;
				if (DateTime.TryParse(text2.Substring(num2, text2.Length - num2).Trim(), out var result))
				{
					sectionTimeUtc = result.ToUniversalTime();
				}
			}
			if (text.Contains("USBSTOR\\", StringComparison.OrdinalIgnoreCase) || text.Contains("USB\\VID_", StringComparison.OrdinalIgnoreCase) || (text.Contains("VID_", StringComparison.OrdinalIgnoreCase) && text.Contains("PID_", StringComparison.OrdinalIgnoreCase)))
			{
				list.Add(new SetupApiUsbRecord
				{
					LineNumber = num,
					Section = section,
					SectionTimeUtc = sectionTimeUtc,
					Evidence = ((text.Length > 600) ? text.Substring(0, 600) : text)
				});
				if (list.Count >= 1200)
				{
					break;
				}
			}
		}
		return list;
	}

	public static List<PowerShellRuleHit> CollectPowerShellRuleHits(List<DetectionRule> rules)
	{
		var list = (from x in rules
			where string.Equals(x.Type, "powershell_contains", StringComparison.OrdinalIgnoreCase)
			select new
			{
				Id = x.Id,
				Name = x.Name,
				Pattern = (x.Pattern ?? "").Trim()
			} into x
			where x.Pattern.Length >= 3
			select x).ToList();
		if (list.Count == 0)
		{
			return new List<PowerShellRuleHit>();
		}
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		string folderPath2 = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
		hashSet.Add(Path.Combine(folderPath, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"));
		hashSet.Add(Path.Combine(folderPath2, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt"));
		List<PowerShellRuleHit> list2 = new List<PowerShellRuleHit>();
		foreach (string item in hashSet)
		{
			if (!File.Exists(item))
			{
				continue;
			}
			int num = 0;
			foreach (string item2 in File.ReadLines(item))
			{
				num++;
				string text = item2.Trim();
				if (text.Length == 0)
				{
					continue;
				}
				foreach (var item3 in list)
				{
					if (text.Contains(item3.Pattern, StringComparison.OrdinalIgnoreCase))
					{
						list2.Add(new PowerShellRuleHit
						{
							RuleId = item3.Id,
							RuleName = item3.Name,
							Pattern = item3.Pattern,
							SourceFile = Path.GetFileName(item),
							LineNumber = num,
							MatchedLine = ((text.Length > 500) ? text.Substring(0, 500) : text)
						});
						if (list2.Count >= 500)
						{
							return list2;
						}
					}
				}
			}
		}
		return list2;
	}

	public static SystemArtifactRecord CollectSystemArtifactState()
	{
		SystemArtifactRecord systemArtifactRecord = new SystemArtifactRecord
		{
			PrefetchDirectoryExists = Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch")),
			AmcacheExists = File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve")),
			SetupApiLogExists = File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", "setupapi.dev.log"))
		};
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters");
			systemArtifactRecord.EnablePrefetcher = ((registryKey?.GetValue("EnablePrefetcher") is int value) ? new int?(value) : ((int?)null));
		}
		catch
		{
		}
		try
		{
			using RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\bam");
			systemArtifactRecord.BamStart = ((registryKey2?.GetValue("Start") is int value2) ? new int?(value2) : ((int?)null));
		}
		catch
		{
		}
		return systemArtifactRecord;
	}

	public static List<PrefetchIntegrityRecord> CollectPrefetchIntegrity()
	{
		List<PrefetchIntegrityRecord> list = new List<PrefetchIntegrityRecord>();
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
		if (!Directory.Exists(path))
		{
			return list;
		}
		Dictionary<string, List<string>> dictionary = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
		foreach (string item in Directory.EnumerateFiles(path, "*.pf", SearchOption.TopDirectoryOnly).Take(5000))
		{
			try
			{
				FileInfo fileInfo = new FileInfo(item);
				string text = TrySha256(item);
				if (!string.IsNullOrWhiteSpace(text))
				{
					if (!dictionary.TryGetValue(text, out var value))
					{
						value = (dictionary[text] = new List<string>());
					}
					value.Add(fileInfo.Name);
				}
				if (fileInfo.IsReadOnly)
				{
					list.Add(new PrefetchIntegrityRecord
					{
						Kind = "read_only",
						Name = fileInfo.Name,
						Detail = "Prefetch marcado como somente leitura.",
						Sha256 = text,
						LastWriteUtc = fileInfo.LastWriteTimeUtc
					});
				}
			}
			catch
			{
			}
		}
		foreach (KeyValuePair<string, List<string>> item2 in dictionary.Where((KeyValuePair<string, List<string>> x) => x.Value.Count > 1))
		{
			list.Add(new PrefetchIntegrityRecord
			{
				Kind = "duplicate_hash",
				Name = string.Join(", ", item2.Value.Take(12)),
				Detail = "Múltiplos arquivos Prefetch possuem o mesmo SHA-256.",
				Sha256 = item2.Key
			});
		}
		return list.Take(500).ToList();
	}

	public static List<VolumeRecord> CollectVolumesWithoutDriveLetter()
	{
		List<VolumeRecord> list = new List<VolumeRecord>();
		using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT DeviceID,DriveLetter,Label,FileSystem,Capacity,BootVolume,SystemVolume FROM Win32_Volume");
		foreach (ManagementObject item in managementObjectSearcher.Get())
		{
			if (string.IsNullOrWhiteSpace(Convert.ToString(item["DriveLetter"]) ?? ""))
			{
				bool flag = Convert.ToBoolean(item["BootVolume"] ?? ((object)false));
				bool flag2 = Convert.ToBoolean(item["SystemVolume"] ?? ((object)false));
				list.Add(new VolumeRecord
				{
					DeviceId = (Convert.ToString(item["DeviceID"]) ?? ""),
					Label = (Convert.ToString(item["Label"]) ?? ""),
					FileSystem = (Convert.ToString(item["FileSystem"]) ?? ""),
					Capacity = ((item["Capacity"] == null) ? ((ulong?)null) : new ulong?(Convert.ToUInt64(item["Capacity"]))),
					BootVolume = flag,
					SystemVolume = flag2,
					ExpectedSystemVolume = (flag || flag2)
				});
			}
		}
		return list.Take(100).ToList();
	}

	public static List<EventLogSignalRecord> CollectRecentLogClearSignals(List<string>? errors = null)
	{
		List<EventLogSignalRecord> result = new List<EventLogSignalRecord>();
		ReadWevtutil("System", "*[System[(EventID=104) and TimeCreated[timediff(@SystemTime) <= 1296000000]]]", "System log clear (Event ID 104)", result, errors);
		ReadWevtutil("Security", "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 1296000000]]]", "Security audit log clear (Event ID 1102)", result, errors);
		return result;
	}

	private static void ReadWevtutil(string channel, string query, string signal, List<EventLogSignalRecord> result, List<string>? errors)
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "wevtutil.exe",
				Arguments = $"qe {channel} /q:\"{query}\" /f:xml /rd:true /c:30",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				throw new IOException("Não foi possível iniciar a consulta de logs.");
			}
			Task<string> task = process.StandardOutput.ReadToEndAsync();
			Task<string> task2 = process.StandardError.ReadToEndAsync();
			if (!process.WaitForExit(10000))
			{
				try
				{
					process.Kill(entireProcessTree: true);
				}
				catch
				{
				}
				throw new IOException("Consulta de log não concluiu no prazo.");
			}
			string result2 = task.GetAwaiter().GetResult();
			task2.GetAwaiter().GetResult();
			if (process.ExitCode != 0)
			{
				throw new IOException("Não foi possível consultar o canal (permissão ou disponibilidade).");
			}
			if (!string.IsNullOrWhiteSpace(result2))
			{
				result.AddRange(LogClearEventParser.Parse(result2, channel));
			}
		}
		catch (Exception ex)
		{
			if (errors != null)
			{
				lock (errors)
				{
					errors.Add("Sinais de limpeza de logs / " + channel + ": " + ex.Message);
					return;
				}
			}
		}
	}

	private static string? TrySha256(string path)
	{
		try
		{
			using FileStream source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
			return Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
		}
		catch
		{
			return null;
		}
	}

	private static bool SafeFileExists(string value)
	{
		try
		{
			string text = Environment.ExpandEnvironmentVariables(value.Trim('"'));
			if (text.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
			{
				string text2 = ResolveNativePath(text);
				return !string.IsNullOrWhiteSpace(text2) && File.Exists(text2);
			}
			return File.Exists(text);
		}
		catch
		{
			return false;
		}
	}

	private static string? ResolveNativePath(string nativePath)
	{
		DriveInfo[] drives = DriveInfo.GetDrives();
		for (int i = 0; i < drives.Length; i++)
		{
			string text = drives[i].Name.TrimEnd('\\');
			string text2 = QueryDevice(text);
			if (!string.IsNullOrWhiteSpace(text2) && nativePath.StartsWith(text2, StringComparison.OrdinalIgnoreCase))
			{
				int length = text2.Length;
				string text3 = nativePath.Substring(length, nativePath.Length - length).TrimStart('\\');
				return text + "\\" + text3;
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

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

	private static string Rot13(string value)
	{
		char[] array = value.ToCharArray();
		for (int i = 0; i < array.Length; i++)
		{
			char c = array[i];
			if (c >= 'a' && c <= 'z')
			{
				array[i] = (char)(97 + (c - 97 + 13) % 26);
			}
			else if (c >= 'A' && c <= 'Z')
			{
				array[i] = (char)(65 + (c - 65 + 13) % 26);
			}
		}
		return new string(array);
	}
}
