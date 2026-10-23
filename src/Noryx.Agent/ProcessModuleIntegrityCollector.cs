using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Noryx.Agent;

internal static class ProcessModuleIntegrityCollector
{
	private static readonly string[] HighValueProcesses = new string[11]
	{
		"rust", "rustclient", "steam", "steamwebhelper", "explorer", "dwm", "lsass", "csrss", "services", "winlogon",
		"svchost"
	};

	public static List<ProcessModuleIntegrityRecord> Collect()
	{
		List<ProcessModuleIntegrityRecord> list = new List<ProcessModuleIntegrityRecord>();
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
		string tempPath = Path.GetTempPath();
		Process[] processes = Process.GetProcesses();
		foreach (Process process in processes)
		{
			try
			{
				if (!HighValueProcesses.Contains<string>(process.ProcessName, StringComparer.OrdinalIgnoreCase))
				{
					continue;
				}
				string text = "";
				try
				{
					text = process.MainModule?.FileName ?? "";
				}
				catch
				{
				}
				bool processSigned = false;
				string processSigner = "";
				if (!string.IsNullOrWhiteSpace(text) && File.Exists(text))
				{
					(processSigned, processSigner) = AuthenticodeVerifier.Verify(text);
				}
				foreach (ProcessModule module in process.Modules)
				{
					try
					{
						string text2 = module.FileName ?? "";
						if (string.IsNullOrWhiteSpace(text2))
						{
							continue;
						}
						bool flag = IsPathUnder(text2, folderPath);
						bool flag2 = IsPathUnder(text2, tempPath);
						bool flag3 = !string.IsNullOrWhiteSpace(text) && IsPathUnder(text2, Path.GetDirectoryName(text) ?? "");
						if (flag || flag2)
						{
							var (flag4, moduleSigner) = AuthenticodeVerifier.Verify(text2);
							if (!flag4 && !flag3)
							{
								list.Add(new ProcessModuleIntegrityRecord
								{
									ProcessId = process.Id,
									ProcessName = process.ProcessName,
									ProcessPath = text,
									ProcessSigned = processSigned,
									ProcessSigner = processSigner,
									ModuleName = (module.ModuleName ?? Path.GetFileName(text2)),
									ModulePath = text2,
									ModuleSigned = flag4,
									ModuleSigner = moduleSigner,
									UnderUserProfile = flag,
									UnderTemp = flag2,
									UnderProcessDirectory = flag3,
									Suspicious = true
								});
							}
						}
					}
					catch
					{
					}
				}
			}
			catch
			{
			}
			finally
			{
				process.Dispose();
			}
		}
		return (from x in list.GroupBy<ProcessModuleIntegrityRecord, string>((ProcessModuleIntegrityRecord x) => $"{x.ProcessId}|{x.ModulePath}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(1200).ToList();
	}

	private static bool IsPathUnder(string path, string root)
	{
		if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root))
		{
			return false;
		}
		try
		{
			string fullPath = Path.GetFullPath(path);
			string value = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
			return fullPath.StartsWith(value, StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}
}
