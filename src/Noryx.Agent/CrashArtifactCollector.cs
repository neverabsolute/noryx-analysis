using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Noryx.Agent;

internal static class CrashArtifactCollector
{
	public static List<CrashArtifactRecord> Collect()
	{
		List<CrashArtifactRecord> list = new List<CrashArtifactRecord>();
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		string folderPath2 = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string folderPath3 = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		foreach (string item in new string[6]
		{
			Path.Combine(folderPath2, "Microsoft", "Windows", "WER", "ReportArchive"),
			Path.Combine(folderPath2, "Microsoft", "Windows", "WER", "ReportQueue"),
			Path.Combine(folderPath, "Microsoft", "Windows", "WER", "ReportArchive"),
			Path.Combine(folderPath, "Microsoft", "Windows", "WER", "ReportQueue"),
			Path.Combine(folderPath3, "Minidump"),
			Path.Combine(folderPath, "CrashDumps")
		}.Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			if (Directory.Exists(item))
			{
				CollectRoot(item, list);
				if (list.Count >= 2500)
				{
					break;
				}
			}
		}
		return list.OrderByDescending((CrashArtifactRecord x) => x.TimestampUtc ?? DateTime.MinValue).Take(2500).ToList();
	}

	private static void CollectRoot(string root, List<CrashArtifactRecord> result)
	{
		IEnumerable<string> source;
		try
		{
			source = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
		}
		catch
		{
			return;
		}
		foreach (string item in source.Take(6000))
		{
			if (result.Count >= 2500)
			{
				break;
			}
			try
			{
				if (Path.GetFileName(item).Equals("Report.wer", StringComparison.OrdinalIgnoreCase))
				{
					ParseWer(item, result);
					continue;
				}
				string extension = Path.GetExtension(item);
				if (extension.Equals(".dmp", StringComparison.OrdinalIgnoreCase) || extension.Equals(".mdmp", StringComparison.OrdinalIgnoreCase))
				{
					FileInfo fileInfo = new FileInfo(item);
					result.Add(new CrashArtifactRecord
					{
						Source = "Crash dump",
						ArtifactPath = item,
						AppName = Path.GetFileNameWithoutExtension(item),
						TimestampUtc = fileInfo.LastWriteTimeUtc,
						Size = fileInfo.Length
					});
				}
			}
			catch
			{
			}
		}
	}

	private static void ParseWer(string path, List<CrashArtifactRecord> result)
	{
		try
		{
			string[] source = File.ReadAllLines(path);
			string appName = "";
			string appPath = "";
			string text = "";
			string eventType = "";
			foreach (string item in source.Take(4000))
			{
				string text2 = item.Trim();
				int num = text2.IndexOf('=');
				if (num <= 0)
				{
					continue;
				}
				string text3 = text2.Substring(0, num).Trim();
				string text4 = text2;
				int num2 = num + 1;
				string text5 = text4.Substring(num2, text4.Length - num2).Trim();
				if (text3.Equals("AppName", StringComparison.OrdinalIgnoreCase))
				{
					appName = text5;
				}
				else if (text3.Equals("AppPath", StringComparison.OrdinalIgnoreCase))
				{
					appPath = text5;
				}
				else if (text3.Contains("FaultModule", StringComparison.OrdinalIgnoreCase) || text3.Contains("FaultingModule", StringComparison.OrdinalIgnoreCase))
				{
					if (string.IsNullOrWhiteSpace(text) && (text5.Contains(".dll", StringComparison.OrdinalIgnoreCase) || text5.Contains(".exe", StringComparison.OrdinalIgnoreCase)))
					{
						text = text5;
					}
				}
				else if (text3.Equals("EventType", StringComparison.OrdinalIgnoreCase))
				{
					eventType = text5;
				}
			}
			FileInfo fileInfo = new FileInfo(path);
			result.Add(new CrashArtifactRecord
			{
				Source = "Windows Error Reporting",
				ArtifactPath = path,
				AppName = appName,
				AppPath = appPath,
				FaultingModulePath = text,
				EventType = eventType,
				TimestampUtc = fileInfo.LastWriteTimeUtc,
				Size = fileInfo.Length
			});
		}
		catch
		{
		}
	}
}
