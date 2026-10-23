using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AppCompatCache;

namespace Noryx.Agent;

internal static class ShimCacheExecutionCollector
{
	public static List<ShimCacheRecord> Collect()
	{
		List<ShimCacheRecord> list = new List<ShimCacheRecord>();
		try
		{
			foreach (IAppCompatCache cache in new global::AppCompatCache.AppCompatCache("", -1, noLogs: true).Caches)
			{
				foreach (CacheEntry entry in cache.Entries)
				{
					if (!string.IsNullOrWhiteSpace(entry.Path))
					{
						list.Add(new ShimCacheRecord
						{
							Path = entry.Path,
							Executed = entry.Executed.ToString(),
							LastModifiedUtc = entry.LastModifiedTimeUTC?.UtcDateTime,
							ControlSet = entry.ControlSet,
							InsertFlags = entry.InsertFlags.ToString(),
							FilePresent = SafeExists(entry.Path),
							DriveType = GetDriveType(entry.Path)
						});
						if (list.Count >= 6000)
						{
							break;
						}
					}
				}
				if (list.Count >= 6000)
				{
					break;
				}
			}
		}
		catch
		{
		}
		return list.OrderByDescending((ShimCacheRecord x) => x.LastModifiedUtc ?? DateTime.MinValue).Take(6000).ToList();
	}

	private static bool SafeExists(string path)
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
}
