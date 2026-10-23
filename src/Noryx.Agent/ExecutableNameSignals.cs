using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Noryx.Agent;

internal static class ExecutableNameSignals
{
	internal static bool LooksRandomFileName(string fileName)
	{
		try
		{
			string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
			if (IsGenericInstallerStem(fileNameWithoutExtension) || HasReadableExecutableToken(fileNameWithoutExtension))
			{
				return false;
			}
			fileNameWithoutExtension = Regex.Replace(fileNameWithoutExtension, "\\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$", "", RegexOptions.IgnoreCase);
			if (fileNameWithoutExtension.Length < 4 || fileNameWithoutExtension.Length > 28)
			{
				return false;
			}
			if (!fileNameWithoutExtension.All(char.IsLetterOrDigit))
			{
				return false;
			}
			if (Regex.IsMatch(fileNameWithoutExtension, "^(?=.*[a-f])(?=.*[0-9])[a-f0-9]{6,24}$", RegexOptions.IgnoreCase))
			{
				return true;
			}
			int num = fileNameWithoutExtension.Count(char.IsLetter);
			int num2 = fileNameWithoutExtension.Count(char.IsDigit);
			int num3 = fileNameWithoutExtension.Count((char ch) => "aeiouAEIOU".Contains(ch));
			int num4 = fileNameWithoutExtension.ToUpperInvariant().Distinct().Count();
			bool flag = fileNameWithoutExtension.All((char ch) => char.IsDigit(ch) || char.IsUpper(ch));
			double num5 = ((num > 0) ? ((double)num3 / (double)num) : 0.0);
			if (fileNameWithoutExtension.Length <= 5)
			{
				return flag && num4 >= Math.Max(4, fileNameWithoutExtension.Length - 1) && (num2 >= 1 || num3 == 0) && num5 <= 0.25;
			}
			if (flag && num4 >= Math.Min(6, fileNameWithoutExtension.Length - 1) && ((num2 >= 1) ? (num5 <= 0.35) : (num5 <= 0.12)))
			{
				return true;
			}
			if (fileNameWithoutExtension.Length >= 8 && fileNameWithoutExtension.Length <= 18 && num2 == 0 && num == fileNameWithoutExtension.Length && num4 >= 7 && num5 <= 0.22)
			{
				return true;
			}
			int num6 = 0;
			for (int num7 = 1; num7 < fileNameWithoutExtension.Length; num7++)
			{
				bool num8 = char.IsDigit(fileNameWithoutExtension[num7 - 1]);
				bool flag2 = char.IsDigit(fileNameWithoutExtension[num7]);
				if (num8 != flag2)
				{
					num6++;
				}
			}
			if (Regex.IsMatch(fileNameWithoutExtension, "^[A-Za-z]+[0-9]{1,4}$") && num >= 5 && num5 >= 0.16)
			{
				return false;
			}
			return fileNameWithoutExtension.Length >= 10 && num >= 6 && num2 >= 2 && num4 >= 8 && (num6 >= 3 || num5 <= 0.12);
		}
		catch
		{
			return false;
		}
	}

	private static bool IsGenericInstallerStem(string value)
	{
		switch ((value ?? "").Trim().ToLowerInvariant())
		{
		case "installer":
		case "uninstall":
		case "updater":
		case "install":
		case "setup32":
		case "setup64":
		case "setup":
		case "update":
		case "uninstaller":
		case "bootstrapper":
		case "launcherinstaller":
			return true;
		default:
			return false;
		}
	}

	private static bool HasReadableExecutableToken(string value)
	{
		string stem = (value ?? "").ToLowerInvariant().Replace("_", "").Replace("-", "")
			.Replace(".", "");
		return new string[33]
		{
			"installer", "install", "setup", "updater", "update", "uninstall", "bootstrapper", "launcher", "browser", "microsoft",
			"windows", "store", "opera", "avast", "crystal", "disk", "info", "control", "driver", "client",
			"helper", "service", "runtime", "manager", "discord", "chrome", "edge", "steam", "spotify", "firefox",
			"nvidia", "amd", "intel"
		}.Any((string token) => token.Length >= 4 && stem.Contains(token, StringComparison.OrdinalIgnoreCase));
	}
}
