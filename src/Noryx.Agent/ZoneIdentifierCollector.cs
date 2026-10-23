using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Noryx.Agent;

internal static class ZoneIdentifierCollector
{
	public static List<ZoneIdentifierRecord> Collect()
	{
		HashSet<string> roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
		Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
		Add(Path.GetTempPath());
		List<ZoneIdentifierRecord> list = new List<ZoneIdentifierRecord>();
		foreach (string item in roots)
		{
			foreach (string item2 in EnumerateFilesLimited(item, 3, 3500))
			{
				if (list.Count >= 5000)
				{
					break;
				}
				try
				{
					string path = item2 + ":Zone.Identifier";
					File.Exists(path);
					string text;
					using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
					{
						using StreamReader streamReader = new StreamReader(stream);
						char[] array = new char[8192];
						int val = streamReader.Read(array, 0, array.Length);
						text = new string(array, 0, Math.Max(0, val));
					}
					if (!string.IsNullOrWhiteSpace(text))
					{
						Dictionary<string, string> values = ParseIni(text);
						int.TryParse(Get(values, "ZoneId"), out var result);
						list.Add(new ZoneIdentifierRecord
						{
							FileName = Path.GetFileName(item2),
							Path = item2,
							ZoneId = result,
							HostUrl = Get(values, "HostUrl"),
							ReferrerUrl = Get(values, "ReferrerUrl"),
							LastWriteUtc = File.GetLastWriteTimeUtc(item2),
							FileExists = File.Exists(item2),
							Sha256 = TrySha256(item2)
						});
					}
				}
				catch
				{
				}
			}
		}
		return list.OrderByDescending((ZoneIdentifierRecord x) => x.LastWriteUtc).Take(5000).ToList();
		void Add(string value)
		{
			if (!string.IsNullOrWhiteSpace(value) && Directory.Exists(value))
			{
				roots.Add(value);
			}
		}
	}

	private static Dictionary<string, string> ParseIni(string text)
	{
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		string[] array = text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
		for (int i = 0; i < array.Length; i++)
		{
			string text2 = array[i].Trim();
			if (text2.Length != 0 && !text2.StartsWith("[") && !text2.StartsWith(";"))
			{
				int num = text2.IndexOf('=');
				if (num > 0)
				{
					string key = text2.Substring(0, num).Trim();
					string text3 = text2;
					int num2 = num + 1;
					string value = text3.Substring(num2, text3.Length - num2).Trim();
					dictionary[key] = value;
				}
			}
		}
		return dictionary;
	}

	private static string Get(Dictionary<string, string> values, string key)
	{
		if (!values.TryGetValue(key, out string value))
		{
			return "";
		}
		return value;
	}

	private static string TrySha256(string path)
	{
		try
		{
			if (new FileInfo(path).Length > 262144000)
			{
				return "";
			}
			using FileStream source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
			return Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
		}
		catch
		{
			return "";
		}
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
			foreach (string item2 in source.Take(150))
			{
				queue.Enqueue((item2, depth + 1));
			}
		}
	}
}
