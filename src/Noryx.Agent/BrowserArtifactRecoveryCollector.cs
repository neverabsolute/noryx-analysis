using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Noryx.Agent;

internal static class BrowserArtifactRecoveryCollector
{
	private static readonly Regex UrlRegex = new Regex("https?://[^\\s<>\"'\\x00]{6,1800}", RegexOptions.IgnoreCase | RegexOptions.Compiled);

	private static readonly Regex RiskyFileRegex = new Regex("(?<![A-Za-z0-9_.-])([A-Za-z0-9_-]{4,64}\\.(?:zip|rar|7z|pdf|jpg|jpeg|png|txt)\\.exe|[A-Za-z0-9_.-]{4,100}\\.(?:exe|com|scr|dll|msi|bat|cmd|ps1|zip|rar|7z))", RegexOptions.IgnoreCase | RegexOptions.Compiled);

	private static readonly string[] ContextTerms = new string[16]
	{
		"rust cheat", "rust hack", "rust script", "recoil script", "no recoil", "aimbot", "wallhack", "silent aim", "loader", "injector",
		"spoofer", "eac bypass", "easy anti cheat bypass", "discord.gg/", "cdn.discordapp.com/", "t.me/"
	};

	public static List<RecoveredBrowserArtifact> Collect(List<RustThreatIndicator> threatCatalog)
	{
		List<RecoveredBrowserArtifact> list = new List<RecoveredBrowserArtifact>();
		HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		foreach (BrowserRawArtifact item in EnumerateArtifacts())
		{
			try
			{
				CarveArtifact(item, threatCatalog, list, seen);
			}
			catch
			{
			}
			if (list.Count >= 3000)
			{
				break;
			}
		}
		return (from x in list
			orderby x.RiskScore descending, x.Browser
			select x).Take(3000).ToList();
	}

	private static void CarveArtifact(BrowserRawArtifact artifact, List<RustThreatIndicator> threatCatalog, List<RecoveredBrowserArtifact> target, HashSet<string> seen)
	{
		using FileStream fileStream = new FileStream(artifact.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
		long position = Math.Max(0L, fileStream.Length - 201326592);
		fileStream.Position = position;
		byte[] array = new byte[4194304];
		StringBuilder stringBuilder = new StringBuilder(4096);
		int num;
		while ((num = fileStream.Read(array, 0, array.Length)) > 0)
		{
			for (int i = 0; i < num; i++)
			{
				byte b = array[i];
				if (b >= 32 && b <= 126)
				{
					if (stringBuilder.Length < 8192)
					{
						stringBuilder.Append((char)b);
					}
					else
					{
						FlushPrintable(stringBuilder, artifact, threatCatalog, target, seen);
					}
				}
				else
				{
					FlushPrintable(stringBuilder, artifact, threatCatalog, target, seen);
				}
			}
			if (target.Count >= 3000)
			{
				break;
			}
		}
		FlushPrintable(stringBuilder, artifact, threatCatalog, target, seen);
	}

	private static void FlushPrintable(StringBuilder printable, BrowserRawArtifact artifact, List<RustThreatIndicator> threatCatalog, List<RecoveredBrowserArtifact> target, HashSet<string> seen)
	{
		if (printable.Length < 8)
		{
			printable.Clear();
			return;
		}
		string text = printable.ToString();
		printable.Clear();
		foreach (Match item in UrlRegex.Matches(text))
		{
			string text2 = CleanUrl(item.Value);
			AddCandidate(artifact, text2, "", text2, threatCatalog, target, seen);
		}
		foreach (Match item2 in RiskyFileRegex.Matches(text))
		{
			string value = item2.Groups[1].Value;
			int num = Math.Max(0, item2.Index - 192);
			int length = Math.Min(text.Length - num, item2.Length + 384);
			string context = text.Substring(num, length);
			AddCandidate(artifact, "", value, context, threatCatalog, target, seen);
		}
	}

	private static void AddCandidate(BrowserRawArtifact artifact, string url, string fileName, string context, List<RustThreatIndicator> threatCatalog, List<RecoveredBrowserArtifact> target, HashSet<string> seen)
	{
		string text = string.Join(" ", url, fileName).ToLowerInvariant();
		string combined = string.Join(" ", text, context).ToLowerInvariant();
		List<string> list = MatchCatalog(text, threatCatalog);
		if (list.Count == 0 && !string.IsNullOrWhiteSpace(fileName))
		{
			list = MatchCatalog(combined, threatCatalog);
		}
		List<string> list2 = ContextTerms.Where((string term) => combined.Contains(term, StringComparison.OrdinalIgnoreCase)).Distinct<string>(StringComparer.OrdinalIgnoreCase).ToList();
		bool flag = !string.IsNullOrWhiteSpace(fileName) && LooksRandomExecutableName(fileName);
		bool flag2 = !string.IsNullOrWhiteSpace(fileName) && Regex.IsMatch(fileName, "\\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)\\.exe$", RegexOptions.IgnoreCase);
		bool flag3 = combined.Contains("discord.gg/") || combined.Contains("discord.com/") || combined.Contains("cdn.discordapp.com/") || combined.Contains("discordapp.com/") || combined.Contains("t.me/") || combined.Contains("telegram.org/");
		if (list.Count > 0 || flag || flag2 || (list2.Count >= 2 && (combined.Contains("rust") || combined.Contains("eac") || combined.Contains("easy anti cheat"))) || (flag3 && !string.IsNullOrWhiteSpace(fileName)))
		{
			int num = 0;
			if (list.Count > 0)
			{
				num += 5;
			}
			if (flag)
			{
				num += 5;
			}
			if (flag2)
			{
				num += 4;
			}
			if (flag3)
			{
				num += 2;
			}
			if (list2.Count >= 2)
			{
				num += 2;
			}
			if (artifact.IsSidecar)
			{
				num++;
			}
			string item = $"{artifact.Browser}|{artifact.Profile}|{url}|{fileName}|{string.Join(",", list)}";
			if (seen.Add(item))
			{
				target.Add(new RecoveredBrowserArtifact
				{
					Browser = artifact.Browser,
					Profile = artifact.Profile,
					SourceArtifact = Path.GetFileName(artifact.Path),
					SourcePath = artifact.Path,
					RecoveredUrl = url,
					RecoveredFileName = fileName,
					CatalogMatches = list,
					MatchedTerms = list2,
					RandomLikeName = flag,
					DeceptiveDoubleExtension = flag2,
					SocialOrigin = flag3,
					RiskScore = num,
					RecoveryKind = (artifact.IsSidecar ? "SQLite WAL/journal" : "SQLite raw pages"),
					Note = (artifact.IsSidecar ? "Recuperado de artefato transacional do navegador. Pode sobreviver após limpeza do histórico até ser sobrescrito." : "String recuperada diretamente das páginas do banco SQLite. Pode representar registro ativo ou remanescente não sobrescrito.")
				});
			}
		}
	}

	private static List<string> MatchCatalog(string haystack, List<RustThreatIndicator> catalog)
	{
		List<string> list = new List<string>();
		foreach (RustThreatIndicator item in catalog)
		{
			if (item.Domains.Any((string value) => ContainsNeedle(haystack, value)) || item.DiscordInvites.Any((string value) => ContainsNeedle(haystack, "discord.gg/" + value)) || item.Aliases.Any(delegate(string value)
			{
				string value2 = StringValue(value);
				return IsDistinctiveCatalogAlias(value2) && ContainsNeedle(haystack, value2);
			}))
			{
				list.Add(item.Name);
			}
			if (list.Count >= 20)
			{
				break;
			}
		}
		return list;
	}

	private static bool IsDistinctiveCatalogAlias(string value)
	{
		string text = StringValue(value);
		if (text.Length >= 7)
		{
			return true;
		}
		if (!text.Contains("rust") && !text.Contains("cheat") && !text.Contains("script") && !text.Contains("aimbot") && !text.Contains("recoil") && !text.Contains("loader") && !text.Contains("private") && !text.Contains("dma") && !text.Contains("external"))
		{
			return text.Contains("internal");
		}
		return true;
	}

	private static bool ContainsNeedle(string haystack, string? value)
	{
		string text = StringValue(value);
		if (text.Length < 4)
		{
			return false;
		}
		int num = 0;
		while (num <= haystack.Length - text.Length)
		{
			int num2 = haystack.IndexOf(text, num, StringComparison.OrdinalIgnoreCase);
			if (num2 < 0)
			{
				return false;
			}
			int num3 = num2 + text.Length;
			bool num4 = num2 == 0 || !char.IsLetterOrDigit(haystack[num2 - 1]);
			bool flag = num3 == haystack.Length || !char.IsLetterOrDigit(haystack[num3]);
			if (num4 && flag)
			{
				return true;
			}
			num = num2 + 1;
		}
		return false;
	}

	private static string StringValue(string? value)
	{
		return (value ?? "").Trim().ToLowerInvariant();
	}

	private static string CleanUrl(string value)
	{
		string text = value;
		int num = text.IndexOfAny(new char[5] { ')', ']', '}', ',', ';' });
		if (num > 8)
		{
			text = text.Substring(0, num);
		}
		return text.TrimEnd('.', ':');
	}

	private static bool LooksRandomExecutableName(string value)
	{
		if (!Path.GetExtension(value).Equals(".exe", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}
		string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(value);
		if (IsGenericInstallerStem(fileNameWithoutExtension) || HasReadableExecutableToken(fileNameWithoutExtension))
		{
			return false;
		}
		fileNameWithoutExtension = Regex.Replace(fileNameWithoutExtension, "\\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$", "", RegexOptions.IgnoreCase);
		if (fileNameWithoutExtension.Length < 4 || fileNameWithoutExtension.Length > 28 || !fileNameWithoutExtension.All(char.IsLetterOrDigit))
		{
			return false;
		}
		int num = fileNameWithoutExtension.Count(char.IsLetter);
		int num2 = fileNameWithoutExtension.Count(char.IsDigit);
		int num3 = fileNameWithoutExtension.Count((char ch) => "aeiouAEIOU".Contains(ch));
		int num4 = fileNameWithoutExtension.ToUpperInvariant().Distinct().Count();
		bool flag = fileNameWithoutExtension.All((char ch) => char.IsDigit(ch) || char.IsUpper(ch));
		double num5 = ((num > 0) ? ((double)num3 / (double)num) : 0.0);
		if (fileNameWithoutExtension.Length <= 5)
		{
			if (flag && num4 >= Math.Max(4, fileNameWithoutExtension.Length - 1) && (num2 >= 1 || num3 == 0))
			{
				return num5 <= 0.25;
			}
			return false;
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
		if (fileNameWithoutExtension.Length >= 10 && num >= 6 && num2 >= 2 && num4 >= 8)
		{
			if (num6 < 3)
			{
				return num5 <= 0.12;
			}
			return true;
		}
		return false;
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

	private static IEnumerable<BrowserRawArtifact> EnumerateArtifacts()
	{
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		var array = new[]
		{
			new
			{
				Browser = "Google Chrome",
				Path = Path.Combine(folderPath, "Google", "Chrome", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Microsoft Edge",
				Path = Path.Combine(folderPath, "Microsoft", "Edge", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Brave",
				Path = Path.Combine(folderPath, "BraveSoftware", "Brave-Browser", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Chromium",
				Path = Path.Combine(folderPath, "Chromium", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Vivaldi",
				Path = Path.Combine(folderPath, "Vivaldi", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Yandex",
				Path = Path.Combine(folderPath, "Yandex", "YandexBrowser", "User Data"),
				RootIsProfile = false
			},
			new
			{
				Browser = "Opera",
				Path = Path.Combine(roaming, "Opera Software", "Opera Stable"),
				RootIsProfile = true
			},
			new
			{
				Browser = "Opera GX",
				Path = Path.Combine(roaming, "Opera Software", "Opera GX Stable"),
				RootIsProfile = true
			}
		};
		var array2 = array;
		foreach (var root in array2)
		{
			if (!Directory.Exists(root.Path))
			{
				continue;
			}
			if (root.RootIsProfile)
			{
				foreach (BrowserRawArtifact item in BuildArtifacts(root.Browser, Path.GetFileName(root.Path), Path.Combine(root.Path, "History")))
				{
					yield return item;
				}
				continue;
			}
			IEnumerable<string> enumerable;
			try
			{
				enumerable = Directory.EnumerateDirectories(root.Path);
			}
			catch
			{
				continue;
			}
			foreach (string item2 in enumerable)
			{
				string fileName = Path.GetFileName(item2);
				if (!fileName.Equals("Default", StringComparison.OrdinalIgnoreCase) && !fileName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase) && !fileName.Equals("Guest Profile", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				foreach (BrowserRawArtifact item3 in BuildArtifacts(root.Browser, fileName, Path.Combine(item2, "History")))
				{
					yield return item3;
				}
			}
		}
		string path = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
		if (!Directory.Exists(path))
		{
			yield break;
		}
		IEnumerable<string> enumerable2;
		try
		{
			enumerable2 = Directory.EnumerateDirectories(path);
		}
		catch
		{
			enumerable2 = Array.Empty<string>();
		}
		foreach (string item4 in enumerable2)
		{
			string fileName2 = Path.GetFileName(item4);
			foreach (BrowserRawArtifact item5 in BuildArtifacts("Mozilla Firefox", fileName2, Path.Combine(item4, "places.sqlite")))
			{
				yield return item5;
			}
		}
	}

	private static IEnumerable<BrowserRawArtifact> BuildArtifacts(string browser, string profile, string database)
	{
		string[] array = new string[3] { "", "-wal", "-journal" };
		foreach (string text in array)
		{
			string path = database + text;
			if (File.Exists(path))
			{
				yield return new BrowserRawArtifact
				{
					Browser = browser,
					Profile = profile,
					Path = path,
					IsSidecar = (text.Length > 0)
				};
			}
		}
	}
}
