using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class SystemIntegrityExpansionCollector
{
	private static readonly string[] ImportantServices = new string[7] { "EventLog", "DPS", "PcaSvc", "DiagTrack", "SysMain", "WSearch", "WinDefend" };

	public static List<SystemIntegrityExpansionRecord> Collect()
	{
		List<SystemIntegrityExpansionRecord> list = new List<SystemIntegrityExpansionRecord>();
		CollectSecureBoot(list);
		CollectBcd(list);
		CollectServiceState(list);
		CollectServiceEvents(list);
		CollectSrumState(list);
		CollectPrefetchState(list);
		return (from x in list.GroupBy<SystemIntegrityExpansionRecord, string>((SystemIntegrityExpansionRecord x) => $"{x.Kind}|{x.Name}|{x.TimestampUtc:O}|{x.Detail}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(1200).ToList();
	}

	private static void CollectSecureBoot(List<SystemIntegrityExpansionRecord> result)
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
			int? num = ((registryKey?.GetValue("UEFISecureBootEnabled") is int value) ? new int?(value) : ((int?)null));
			result.Add(new SystemIntegrityExpansionRecord
			{
				Kind = "secure_boot",
				Name = "UEFI Secure Boot",
				SeverityHint = ((num == 0) ? "medium" : "info"),
				Detail = ((!num.HasValue) ? "Estado não disponível." : ((num == 1) ? "Ativado" : "Desativado"))
			});
		}
		catch
		{
		}
	}

	private static void CollectBcd(List<SystemIntegrityExpansionRecord> result)
	{
		string text = Run("bcdedit.exe", "/enum {current}", 10000);
		if (!string.IsNullOrWhiteSpace(text))
		{
			string[] array = text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
			for (int i = 0; i < array.Length; i++)
			{
				string text2 = array[i].Trim();
				string text3 = text2.ToLowerInvariant();
				string severityHint = "info";
				bool flag = false;
				if (text3.Contains("testsigning") && !text3.EndsWith(" no"))
				{
					severityHint = "high";
					flag = true;
				}
				if (text3.Contains("nointegritychecks") && !text3.EndsWith(" no"))
				{
					severityHint = "high";
					flag = true;
				}
				if (Regex.IsMatch(text3, "^debug\\s+(yes|on|true)"))
				{
					severityHint = "high";
					flag = true;
				}
				if (text3.Contains("hypervisorlaunchtype") || text3.Contains("bootmenupolicy") || text3.Contains("nx ") || text3.StartsWith("nx "))
				{
					flag = true;
				}
				if (flag)
				{
					result.Add(new SystemIntegrityExpansionRecord
					{
						Kind = "bcd",
						Name = "BCD Current",
						SeverityHint = severityHint,
						Detail = text2
					});
				}
			}
		}
		string text4 = Run("bcdedit.exe", "/enum firmware", 12000);
		if (!string.IsNullOrWhiteSpace(text4))
		{
			string detail = ((text4.Length > 24000) ? text4.Substring(0, 24000) : text4);
			result.Add(new SystemIntegrityExpansionRecord
			{
				Kind = "efi_entries",
				Name = "Entradas EFI / firmware",
				SeverityHint = "info",
				Detail = detail
			});
		}
	}

	private static void CollectServiceState(List<SystemIntegrityExpansionRecord> result)
	{
		string[] importantServices = ImportantServices;
		foreach (string text in importantServices)
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\" + text);
				int? num = ((registryKey?.GetValue("Start") is int value) ? new int?(value) : ((int?)null));
				string text2 = Convert.ToString(registryKey?.GetValue("ImagePath")) ?? "";
				bool flag = num == 4;
				if (flag)
				{
					bool flag2;
					switch (text)
					{
					case "EventLog":
					case "DPS":
					case "PcaSvc":
						flag2 = true;
						break;
					default:
						flag2 = false;
						break;
					}
					flag = flag2;
				}
				string severityHint = (flag ? "high" : "info");
				result.Add(new SystemIntegrityExpansionRecord
				{
					Kind = "service_state",
					Name = text,
					SeverityHint = severityHint,
					Detail = "Start=" + (num?.ToString() ?? "?") + " | ImagePath=" + text2
				});
			}
			catch
			{
			}
		}
	}

	private static void CollectServiceEvents(List<SystemIntegrityExpansionRecord> result)
	{
		string query = "*[System[(EventID=7036 or EventID=7040) and TimeCreated[timediff(@SystemTime) <= 172800000]]]";
		foreach (string item in QueryEvents("System", query, 250))
		{
			try
			{
				XDocument xDocument = XDocument.Parse(item);
				XNamespace xNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
				if ((xDocument.Root?.Element(xNamespace + "System")?.Element(xNamespace + "Provider")?.Attribute("Name")?.Value ?? "").Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
				{
					int result2;
					int num = (int.TryParse(xDocument.Root?.Element(xNamespace + "System")?.Element(xNamespace + "EventID")?.Value, out result2) ? result2 : 0);
					DateTime? timestampUtc = TryEventTime(xDocument, xNamespace);
					string message = string.Join(" | ", from x in xDocument.Descendants(xNamespace + "Data")
						select x.Value into x
						where !string.IsNullOrWhiteSpace(x)
						select x);
					if (ImportantServices.Any((string name) => message.Contains(name, StringComparison.OrdinalIgnoreCase)))
					{
						result.Add(new SystemIntegrityExpansionRecord
						{
							Kind = ((num == 7040) ? "service_start_type_change" : "service_state_change"),
							Name = "Service Control Manager",
							SeverityHint = ((num == 7040) ? "medium" : "info"),
							TimestampUtc = timestampUtc,
							Detail = ((message.Length > 2500) ? message.Substring(0, 2500) : message)
						});
					}
				}
			}
			catch
			{
			}
		}
	}

	private static void CollectSrumState(List<SystemIntegrityExpansionRecord> result)
	{
		string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "sru", "SRUDB.dat");
		try
		{
			bool flag = File.Exists(text);
			result.Add(new SystemIntegrityExpansionRecord
			{
				Kind = "srum_state",
				Name = "SRUDB.dat",
				SeverityHint = (flag ? "info" : "medium"),
				TimestampUtc = (flag ? new DateTime?(File.GetLastWriteTimeUtc(text)) : ((DateTime?)null)),
				Detail = (flag ? text : "Banco SRUM não localizado.")
			});
		}
		catch
		{
		}
	}

	private static void CollectPrefetchState(List<SystemIntegrityExpansionRecord> result)
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
		try
		{
			int num = (Directory.Exists(path) ? Directory.EnumerateFiles(path, "*.pf", SearchOption.TopDirectoryOnly).Take(5000).Count() : 0);
			result.Add(new SystemIntegrityExpansionRecord
			{
				Kind = "prefetch_state",
				Name = "Windows Prefetch",
				SeverityHint = ((num == 0) ? "medium" : "info"),
				Detail = (Directory.Exists(path) ? $"Arquivos PF atuais: {num}" : "Diretório Prefetch não localizado.")
			});
		}
		catch
		{
		}
	}

	private static IEnumerable<string> QueryEvents(string log, string query, int count)
	{
		string text = Run("wevtutil.exe", $"qe \"{log}\" /q:\"{query}\" /f:xml /rd:true /c:{count}", 16000);
		if (string.IsNullOrWhiteSpace(text))
		{
			yield break;
		}
		foreach (Match item in Regex.Matches(text, "<Event\\b.*?</Event>", RegexOptions.IgnoreCase | RegexOptions.Singleline))
		{
			yield return item.Value;
		}
	}

	private static DateTime? TryEventTime(XDocument doc, XNamespace ns)
	{
		if (!DateTimeOffset.TryParse(doc.Root?.Element(ns + "System")?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value, out var result))
		{
			return null;
		}
		return result.UtcDateTime;
	}

	private static string Run(string fileName, string arguments, int timeoutMs)
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = fileName,
				Arguments = arguments,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return "";
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
				return "";
			}
			return (process.ExitCode == 0) ? text : "";
		}
		catch
		{
			return "";
		}
	}
}
