using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Noryx.Agent;

internal static class UsbEventCollector
{
	public static List<UsbDeviceEventRecord> Collect()
	{
		List<UsbDeviceEventRecord> list = new List<UsbDeviceEventRecord>();
		QueryLog("Microsoft-Windows-DriverFrameworks-UserMode/Operational", "*[System[(EventID=2003 or EventID=2100 or EventID=2102)]]", 2200, list);
		QueryLog("Microsoft-Windows-Partition/Diagnostic", "*[System[(EventID=1006)]]", 3000, list);
		QueryLog("Microsoft-Windows-Kernel-PnP/Configuration", "*[System[(EventID=400 or EventID=410 or EventID=430)]]", 3000, list);
		return (from x in list
			orderby x.TimeCreatedUtc descending
			group x by $"{x.Provider}|{x.EventId}|{x.TimeCreatedUtc:O}|{x.DeviceId}|{x.Evidence}" into x
			select x.First()).Take(5000).ToList();
	}

	public static void EnrichUsbHistory(List<UsbHistoryRecord> history, List<UsbDeviceEventRecord> events)
	{
		foreach (UsbHistoryRecord item in history)
		{
			HashSet<string> tokens = BuildMatchTokens(item);
			List<UsbDeviceEventRecord> source = (from x in events.Where(delegate(UsbDeviceEventRecord e)
				{
					string haystack = e.DeviceId + " " + e.Evidence;
					return tokens.Any((string token) => token.Length >= 4 && ContainsIdentity(haystack, token));
				})
				orderby x.TimeCreatedUtc descending
				select x).ToList();
			UsbDeviceEventRecord usbDeviceEventRecord = source.FirstOrDefault((UsbDeviceEventRecord x) => x.EventType == "connect");
			UsbDeviceEventRecord usbDeviceEventRecord2 = source.FirstOrDefault((UsbDeviceEventRecord x) => x.EventType == "disconnect");
			item.LastConnectedUtc = usbDeviceEventRecord?.TimeCreatedUtc;
			item.LastDisconnectedUtc = usbDeviceEventRecord2?.TimeCreatedUtc;
			UsbDeviceEventRecord usbDeviceEventRecord3 = source.FirstOrDefault();
			item.TimelineSource = ((usbDeviceEventRecord3 == null) ? "" : $"{usbDeviceEventRecord3.Provider} Event {usbDeviceEventRecord3.EventId}");
		}
	}

	private static HashSet<string> BuildMatchTokens(UsbHistoryRecord item)
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		string obj = item.InstanceId ?? "";
		string text = obj.Trim();
		if (text.Length >= 6)
		{
			hashSet.Add(text);
		}
		string text2 = Regex.Replace(obj, "&\\d+$", "", RegexOptions.IgnoreCase).Trim();
		if (text2.Length >= 6)
		{
			hashSet.Add(text2);
		}
		return hashSet;
	}

	private static bool ContainsIdentity(string text, string identity)
	{
		int num = 0;
		while (num <= text.Length - identity.Length)
		{
			int num2 = text.IndexOf(identity, num, StringComparison.OrdinalIgnoreCase);
			if (num2 < 0)
			{
				return false;
			}
			int num3 = num2 + identity.Length;
			if ((num2 == 0 || !char.IsLetterOrDigit(text[num2 - 1])) && (num3 == text.Length || !char.IsLetterOrDigit(text[num3])))
			{
				return true;
			}
			num = num2 + 1;
		}
		return false;
	}

	private static void QueryLog(string logName, string query, int maxEvents, List<UsbDeviceEventRecord> target)
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = "wevtutil.exe",
				Arguments = $"qe \"{logName}\" /q:\"{query}\" /f:xml /rd:true /c:{maxEvents}",
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
			if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(text))
			{
				return;
			}
			foreach (Match item in Regex.Matches(text, "<Event\\b.*?</Event>", RegexOptions.IgnoreCase | RegexOptions.Singleline))
			{
				TryParseEvent(item.Value, logName, target);
			}
		}
		catch
		{
		}
	}

	private static void TryParseEvent(string xml, string fallbackProvider, List<UsbDeviceEventRecord> target)
	{
		try
		{
			XDocument xDocument = XDocument.Parse(xml);
			XNamespace xNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
			XElement xElement = xDocument.Root?.Element(xNamespace + "System");
			if (xElement == null)
			{
				return;
			}
			int result;
			int num = (int.TryParse(xElement.Element(xNamespace + "EventID")?.Value, out result) ? result : 0);
			string text = xElement.Element(xNamespace + "Provider")?.Attribute("Name")?.Value ?? fallbackProvider;
			DateTime timeCreatedUtc = DateTime.UtcNow;
			if (DateTimeOffset.TryParse(xElement.Element(xNamespace + "TimeCreated")?.Attribute("SystemTime")?.Value, out var result2))
			{
				timeCreatedUtc = result2.UtcDateTime;
			}
			var list = (from x in xDocument.Descendants(xNamespace + "Data")
				select new
				{
					Name = (x.Attribute("Name")?.Value ?? ""),
					Value = (x.Value ?? "").Trim()
				} into x
				where !string.IsNullOrWhiteSpace(x.Value)
				select x).ToList();
			if (list.Count == 0)
			{
				list = (from x in xDocument.Descendants()
					where !x.HasElements && !string.IsNullOrWhiteSpace(x.Value)
					select new
					{
						Name = x.Name.LocalName,
						Value = x.Value.Trim()
					}).Take(80).ToList();
			}
			string text2 = string.Join(" | ", list.Select(x => (!string.IsNullOrWhiteSpace(x.Name)) ? (x.Name + "=" + x.Value) : x.Value));
			string text3 = FindDeviceIdentifier(list.Select(x => x.Value));
			if (string.IsNullOrWhiteSpace(text3) && num == 1006)
			{
				string text4 = list.FirstOrDefault(x => x.Name.Equals("ParentId", StringComparison.OrdinalIgnoreCase))?.Value;
				string text5 = list.FirstOrDefault(x => x.Name.Equals("SerialNumber", StringComparison.OrdinalIgnoreCase))?.Value;
				text3 = ((!string.IsNullOrWhiteSpace(text4)) ? text4 : text5);
			}
			string text6;
			switch (num)
			{
			case 2003:
				text6 = "connect";
				break;
			case 2102:
				text6 = "disconnect";
				break;
			case 400:
			case 410:
			case 430:
				text6 = "connect";
				break;
			case 1006:
				text6 = ParsePartitionEventType(list.FirstOrDefault(x => x.Name.Equals("Capacity", StringComparison.OrdinalIgnoreCase))?.Value);
				break;
			default:
				text6 = "device_activity";
				break;
			}
			string eventType = text6;
			if (!string.IsNullOrWhiteSpace(text3) || text2.Contains("USB", StringComparison.OrdinalIgnoreCase) || text2.Contains("VID_", StringComparison.OrdinalIgnoreCase) || text2.Contains("PID_", StringComparison.OrdinalIgnoreCase) || text2.Contains("removable", StringComparison.OrdinalIgnoreCase) || text.Contains("Partition", StringComparison.OrdinalIgnoreCase))
			{
				target.Add(new UsbDeviceEventRecord
				{
					Provider = text,
					EventId = num,
					EventType = eventType,
					TimeCreatedUtc = timeCreatedUtc,
					DeviceId = (text3 ?? ""),
					Evidence = ((text2.Length > 1800) ? text2.Substring(0, 1800) : text2)
				});
			}
		}
		catch
		{
		}
	}

	private static string ParsePartitionEventType(string? rawCapacity)
	{
		if (ulong.TryParse(rawCapacity, out var result))
		{
			if (result != 0L)
			{
				return "connect";
			}
			return "disconnect";
		}
		return "partition_activity";
	}

	private static string? FindDeviceIdentifier(IEnumerable<string> values)
	{
		foreach (string value in values)
		{
			string text = value.Trim();
			if (text.Contains("USBSTOR\\", StringComparison.OrdinalIgnoreCase) || text.Contains("USB\\VID_", StringComparison.OrdinalIgnoreCase) || text.Contains("SWD\\WPDBUSENUM", StringComparison.OrdinalIgnoreCase) || (text.Contains("VID_", StringComparison.OrdinalIgnoreCase) && text.Contains("PID_", StringComparison.OrdinalIgnoreCase)))
			{
				return (text.Length > 500) ? text.Substring(0, 500) : text;
			}
		}
		return null;
	}

	private static string Normalize(string? value)
	{
		return Regex.Replace((value ?? "").ToUpperInvariant(), "[^A-Z0-9]+", "");
	}
}
