using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Amcache;
using Amcache.Classes;

namespace Noryx.Agent;

internal static class AmcacheExecutionCollector
{
	public static List<AmcacheExecutionRecord> Collect()
	{
		List<AmcacheExecutionRecord> list = new List<AmcacheExecutionRecord>();
		string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve");
		if (!File.Exists(text))
		{
			return list;
		}
		try
		{
			if (!Helper.IsNewFormat(text, noLog: false))
			{
				return list;
			}
			AmcacheNew amcacheNew = new AmcacheNew(text, recoverDeleted: true, noLogs: false);
			foreach (FileEntryNew unassociatedFileEntry in amcacheNew.UnassociatedFileEntries)
			{
				AddEntry(list, unassociatedFileEntry, "Unassociated", null);
				if (list.Count >= 6000)
				{
					break;
				}
			}
			if (list.Count < 6000)
			{
				foreach (ProgramsEntryNew programsEntry in amcacheNew.ProgramsEntries)
				{
					foreach (FileEntryNew fileEntry in programsEntry.FileEntries)
					{
						AddEntry(list, fileEntry, programsEntry.Name, programsEntry.Publisher);
						if (list.Count >= 6000)
						{
							break;
						}
					}
					if (list.Count >= 6000)
					{
						break;
					}
				}
			}
		}
		catch
		{
		}
		return list.OrderByDescending((AmcacheExecutionRecord x) => x.FileKeyLastWriteUtc).Take(6000).ToList();
	}

	private static void AddEntry(List<AmcacheExecutionRecord> target, FileEntryNew entry, string applicationName, string? programPublisher)
	{
		try
		{
			string text = entry.FullPath ?? "";
			string text2 = ((!string.IsNullOrWhiteSpace(entry.Name)) ? entry.Name : Path.GetFileName(text));
			if (!string.IsNullOrWhiteSpace(text2) || !string.IsNullOrWhiteSpace(text))
			{
				target.Add(new AmcacheExecutionRecord
				{
					Name = (text2 ?? ""),
					FullPath = text,
					Sha1 = (entry.SHA1 ?? ""),
					ApplicationName = (applicationName ?? entry.ApplicationName ?? ""),
					ProductName = (entry.ProductName ?? ""),
					Publisher = ((!string.IsNullOrWhiteSpace(programPublisher)) ? programPublisher : (entry.Publisher ?? "")),
					Description = (entry.Description ?? ""),
					OriginalFileName = (entry.OriginalFileName ?? ""),
					IsPeFile = entry.IsPeFile,
					IsOsComponent = entry.IsOsComponent,
					FileSize = entry.Size,
					Usn = entry.Usn,
					FileKeyLastWriteUtc = entry.FileKeyLastWriteTimestamp.UtcDateTime,
					LinkDateUtc = entry.LinkDate?.UtcDateTime,
					FilePresent = SafeExists(text),
					DriveType = GetDriveType(text)
				});
			}
		}
		catch
		{
		}
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
