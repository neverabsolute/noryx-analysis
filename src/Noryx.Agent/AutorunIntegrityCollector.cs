using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class AutorunIntegrityCollector
{
	public static List<AutorunIntegrityRecord> Collect()
	{
		List<AutorunIntegrityRecord> list = new List<AutorunIntegrityRecord>();
		CollectRunKey(Registry.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run", list);
		CollectRunKey(Registry.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce", list);
		CollectRunKey(Registry.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run", list);
		CollectRunKey(Registry.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce", list);
		CollectStartupFolder(list);
		CollectScheduledTasks(list);
		return (from x in list.GroupBy<AutorunIntegrityRecord, string>((AutorunIntegrityRecord x) => $"{x.Source}|{x.Name}|{x.Command}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(2500).ToList();
	}

	private static void CollectRunKey(RegistryKey hive, string subKey, string source, List<AutorunIntegrityRecord> result)
	{
		try
		{
			using RegistryKey registryKey = hive.OpenSubKey(subKey);
			if (registryKey != null)
			{
				string[] valueNames = registryKey.GetValueNames();
				foreach (string name in valueNames)
				{
					string command = Convert.ToString(registryKey.GetValue(name)) ?? "";
					AddRecord(result, source, name, command, enabled: true);
				}
			}
		}
		catch
		{
		}
	}

	private static void CollectStartupFolder(List<AutorunIntegrityRecord> result)
	{
		foreach (string item in new string[2]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.Startup),
			Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
		}.Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			if (!Directory.Exists(item))
			{
				continue;
			}
			IEnumerable<string> source;
			try
			{
				source = Directory.EnumerateFiles(item);
			}
			catch
			{
				continue;
			}
			foreach (string item2 in source.Take(600))
			{
				AddRecord(result, "Startup Folder", Path.GetFileName(item2), item2, enabled: true);
			}
		}
	}

	private static void CollectScheduledTasks(List<AutorunIntegrityRecord> result)
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "schtasks.exe",
				Arguments = "/query /fo CSV /v /nh",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return;
			}
			string text = process.StandardOutput.ReadToEnd();
			process.StandardError.ReadToEnd();
			if (!process.WaitForExit(20000))
			{
				try
				{
					process.Kill(entireProcessTree: true);
					return;
				}
				catch
				{
					return;
				}
			}
			if (process.ExitCode != 0)
			{
				return;
			}
			foreach (string item in text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Take(2500))
			{
				List<string> list = ParseCsv(item);
				if (list.Count >= 9)
				{
					string name = list.ElementAtOrDefault(1) ?? "";
					string text2 = list.ElementAtOrDefault(3) ?? "";
					string runAs = list.ElementAtOrDefault(7) ?? "";
					string text3 = list.FirstOrDefault((string x) => x.Contains(".exe", StringComparison.OrdinalIgnoreCase) || x.Contains(".bat", StringComparison.OrdinalIgnoreCase) || x.Contains(".cmd", StringComparison.OrdinalIgnoreCase) || x.Contains(".ps1", StringComparison.OrdinalIgnoreCase)) ?? "";
					if (!string.IsNullOrWhiteSpace(text3))
					{
						AddRecord(result, "Scheduled Task", name, text3, !text2.Equals("Disabled", StringComparison.OrdinalIgnoreCase), runAs);
					}
				}
			}
		}
		catch
		{
		}
	}

	private static void AddRecord(List<AutorunIntegrityRecord> result, string source, string name, string command, bool enabled, string runAs = "")
	{
		string text = ExtractExecutablePath(command);
		bool flag = !string.IsNullOrWhiteSpace(text) && File.Exists(text);
		bool signed = false;
		string signerSubject = "";
		if (flag)
		{
			(signed, signerSubject) = AuthenticodeVerifier.Verify(text);
		}
		bool flag2 = IsUserWritablePath(text);
		bool suspicious = enabled && flag2;
		result.Add(new AutorunIntegrityRecord
		{
			Source = source,
			Name = name,
			Command = command,
			ExecutablePath = text,
			FileExists = flag,
			Signed = signed,
			SignerSubject = signerSubject,
			UserWritablePath = flag2,
			Enabled = enabled,
			RunAs = runAs,
			Suspicious = suspicious
		});
	}

	private static string ExtractExecutablePath(string command)
	{
		if (string.IsNullOrWhiteSpace(command))
		{
			return "";
		}
		string text = Environment.ExpandEnvironmentVariables(command.Trim());
		if (text.StartsWith('"'))
		{
			int num = text.IndexOf('"', 1);
			if (num > 1)
			{
				return text.Substring(1, num - 1);
			}
		}
		Match match = Regex.Match(text, "^[^\\r\\n]*?\\.(exe|com|bat|cmd|ps1|scr)", RegexOptions.IgnoreCase);
		if (!match.Success)
		{
			return "";
		}
		return match.Value.Trim().Trim('"');
	}

	private static bool IsUserWritablePath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return false;
		}
		string text = path.Replace('/', '\\').ToLowerInvariant();
		string value = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).Replace('/', '\\').ToLowerInvariant();
		string value2 = Path.GetTempPath().Replace('/', '\\').ToLowerInvariant();
		if (string.IsNullOrWhiteSpace(value) || !text.StartsWith(value))
		{
			if (!string.IsNullOrWhiteSpace(value2))
			{
				return text.StartsWith(value2);
			}
			return false;
		}
		return true;
	}

	private static List<string> ParseCsv(string line)
	{
		List<string> list = new List<string>();
		foreach (Match item2 in Regex.Matches(line, "(?:^|,)(?:\"((?:\"\"|[^\"])*)\"|([^,]*))"))
		{
			string item = (item2.Groups[1].Success ? item2.Groups[1].Value.Replace("\"\"", "\"") : item2.Groups[2].Value);
			list.Add(item);
		}
		return list;
	}
}
