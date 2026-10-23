using System.Collections.Generic;
using System.IO;

namespace Noryx.Agent;

internal static class EvidenceFileWalker
{
	public static IEnumerable<string> Enumerate(string root, FileSearchCoverage coverage)
	{
		Stack<string> pending = new Stack<string>();
		pending.Push(root);
		while (pending.Count > 0)
		{
			string text = pending.Pop();
			if (!coverage.SeenDirectories.Add(text))
			{
				continue;
			}
			coverage.DirectoriesVisited++;
			string[] fileSystemEntries;
			try
			{
				fileSystemEntries = Directory.GetFileSystemEntries(text);
			}
			catch
			{
				coverage.Inaccessible++;
				continue;
			}
			string[] array = fileSystemEntries;
			foreach (string text2 in array)
			{
				FileAttributes attributes;
				try
				{
					attributes = File.GetAttributes(text2);
				}
				catch
				{
					coverage.Inaccessible++;
					continue;
				}
				if ((attributes & FileAttributes.ReparsePoint) != FileAttributes.None)
				{
					coverage.ReparsePointsSkipped++;
					continue;
				}
				if ((attributes & FileAttributes.Directory) != FileAttributes.None)
				{
					pending.Push(text2);
					continue;
				}
				coverage.FilesVisited++;
				yield return text2;
			}
		}
	}
}
