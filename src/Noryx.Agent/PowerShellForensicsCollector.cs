using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Noryx.Agent;

internal static class PowerShellForensicsCollector
{
	private static readonly string[] SuspiciousTokens = new string[38]
	{
		"wevtutil", "clear-eventlog", "fsutil usn deletejournal", "prefetch", "amcache", "psreadline", "sru\\", "invoke-expression", "iex ", "downloadstring",
		"downloadfile", "invoke-webrequest", "iwr ", "start-bitstransfer", "frombase64string", "-encodedcommand", "reflection.assembly", "assembly]::load", "virtualalloc", "writeprocessmemory",
		"createremotethread", "add-mppreference", "set-mppreference", "exclusionpath", "exclusionprocess", "set-executionpolicy bypass", "windowstyle hidden", "hidden -command", "certutil -decode", "bitsadmin",
		"mshta ", "rundll32 ", "regsvr32 ", "curl ", "wget ", "discord.gg/", "cdn.discordapp.com/", "t.me/"
	};

	public static List<PowerShellArtifactRecord> Collect()
	{
		List<PowerShellArtifactRecord> list = new List<PowerShellArtifactRecord>();
		CollectPsReadLine(list);
		CollectEventLog(list);
		return (from x in list.GroupBy<PowerShellArtifactRecord, string>((PowerShellArtifactRecord x) => $"{x.Source}|{x.TimestampUtc:O}|{x.Command}", StringComparer.OrdinalIgnoreCase)
			select x.First() into x
			orderby x.TimestampUtc ?? DateTime.MinValue descending
			select x).Take(1800).ToList();
	}

	private static void CollectPsReadLine(List<PowerShellArtifactRecord> result)
	{
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		foreach (string item in new string[2]
		{
			Path.Combine(folderPath, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
			Path.Combine(folderPath, "Microsoft", "Windows", "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt")
		}.Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			if (!File.Exists(item))
			{
				continue;
			}
			try
			{
				foreach (string item2 in File.ReadAllLines(item).TakeLast(5000))
				{
					AddIfInteresting(result, "PSReadLine", item, item2, null, null);
				}
			}
			catch
			{
			}
		}
	}

	private static void CollectEventLog(List<PowerShellArtifactRecord> result)
	{
		string[] array = new string[2] { "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell" };
		foreach (string text in array)
		{
			foreach (string item in QueryEvents(text, "*[System[(EventID=4104 or EventID=4103 or EventID=400 or EventID=600)]]", 900))
			{
				try
				{
					XDocument xDocument = XDocument.Parse(item);
					XNamespace xNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
					int result2;
					int value = (int.TryParse(xDocument.Root?.Element(xNamespace + "System")?.Element(xNamespace + "EventID")?.Value, out result2) ? result2 : 0);
					DateTime? timestamp = TryEventTime(xDocument, xNamespace);
					var source = (from x in xDocument.Descendants(xNamespace + "Data")
						select new
						{
							Name = (x.Attribute("Name")?.Value ?? ""),
							Value = (x.Value ?? "")
						}).ToList();
					string text2 = (from x in source
						where x.Name.Equals("ScriptBlockText", StringComparison.OrdinalIgnoreCase) || x.Name.Equals("Payload", StringComparison.OrdinalIgnoreCase) || x.Name.Equals("HostApplication", StringComparison.OrdinalIgnoreCase)
						select x.Value).FirstOrDefault((string x) => !string.IsNullOrWhiteSpace(x)) ?? "";
					if (string.IsNullOrWhiteSpace(text2))
					{
						text2 = string.Join(" ", from x in source
							select x.Value into x
							where !string.IsNullOrWhiteSpace(x)
							select x);
					}
					AddIfInteresting(result, text, text, text2, timestamp, value);
				}
				catch
				{
				}
			}
		}
	}

	private static void AddIfInteresting(List<PowerShellArtifactRecord> result, string source, string sourcePath, string command, DateTime? timestamp, int? eventId)
	{
		string normalized = command.Replace("\r", " ").Replace("\n", " ").Trim();
		if (normalized.Length != 0)
		{
			List<string> list = SuspiciousTokens.Where((string token) => normalized.Contains(token, StringComparison.OrdinalIgnoreCase)).Distinct<string>(StringComparer.OrdinalIgnoreCase).ToList();
			bool flag = Regex.IsMatch(normalized, "[A-Za-z0-9+/]{180,}={0,2}", RegexOptions.CultureInvariant);
			if (list.Count != 0 || flag)
			{
				string command2 = ((normalized.Length > 4000) ? normalized.Substring(0, 4000) : normalized);
				result.Add(new PowerShellArtifactRecord
				{
					Source = source,
					SourcePath = sourcePath,
					EventId = eventId,
					TimestampUtc = timestamp,
					Command = command2,
					MatchedIndicators = list,
					LongEncodedPayload = flag
				});
			}
		}
	}

	private static IEnumerable<string> QueryEvents(string logName, string query, int count)
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
			if (!process.WaitForExit(15000))
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

	private static DateTime? TryEventTime(XDocument doc, XNamespace ns)
	{
		try
		{
			DateTimeOffset result;
			return DateTimeOffset.TryParse(doc.Root?.Element(ns + "System")?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value, out result) ? new DateTime?(result.UtcDateTime) : ((DateTime?)null);
		}
		catch
		{
			return null;
		}
	}
}
