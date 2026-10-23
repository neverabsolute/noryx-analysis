using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace Noryx.Agent;

internal static class BrowserHistoryCollector
{
	private static readonly DateTime ChromiumEpoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	private static readonly string[] StrongPhrases = new string[19]
	{
		"rust cheat", "rust hack", "rust script", "recoil script", "no recoil", "aimbot", "wallhack", "silent aim", "ragebot", "triggerbot",
		"cheat loader", "hack loader", "external cheat", "internal cheat", "undetected cheat", "hwid spoofer", "eac bypass", "easy anti cheat bypass", "rust injector"
	};

	private static readonly string[] KnownRustCheatBrands = new string[53]
	{
		"lethality rust", "lethality script", "lethality club", "revolex", "revolex script", "purge recoil", "purge rust", "zaza cheats", "zaza private", "slayer rust",
		"slayer private", "disconnect cheats", "beazt private", "beazt rust", "agera rust", "pure dma rust", "lordcheat", "aimsync rust", "rust smartai", "nowax cheats",
		"fcheats rust", "memez macros", "memez internalx", "memez external", "gamevantage rust", "blastaim rust", "auroracheats", "aegis rust cheat", "mirage rust external", "the darkest magic",
		"moonlight rust", "moonlight script", "poak rust", "poak script", "revelx", "revelx rust", "aimmy rust", "kosmos aimbot", "synthar aimbot", "lethality.club",
		"revolexscript.com", "purgerecoil.club", "zazacheats.net", "slayer.club", "disconnectcheats.com", "nowaxcheats.com", "fcheats.com", "aimsync.ai", "aptitude.pub", "discord.gg/lethalityrust",
		"discord.gg/zazacheats", "discord.gg/j4gp9t", "discord.me/zbscn"
	};

	private static readonly string[] ContextTerms = new string[13]
	{
		"cheat", "hack", "script", "loader", "injector", "aimbot", "wallhack", "esp", "recoil", "macro",
		"bypass", "spoofer", "exploit"
	};

	private static readonly string[] GameTerms = new string[5] { "rust", "facepunch", "eac", "easy anti cheat", "easyanticheat" };

	private static readonly string[] BenignPhrases = new string[5] { "anti-cheat", "anticheat", "anti cheat", "cheat sheet", "cheatsheet" };

	public static List<BrowserHistoryRecord> CollectSuspicious(IEnumerable<RustThreatIndicator>? threatCatalog = null)
	{
		List<BrowserHistoryRecord> list = new List<BrowserHistoryRecord>();
		IReadOnlyCollection<string> catalogTerms = BuildCatalogTerms(threatCatalog);
		foreach (HistoryProfile item in EnumerateChromiumProfiles())
		{
			try
			{
				list.AddRange(ReadChromium(item, catalogTerms));
			}
			catch
			{
			}
		}
		foreach (HistoryProfile item2 in EnumerateFirefoxProfiles())
		{
			try
			{
				list.AddRange(ReadFirefox(item2, catalogTerms));
			}
			catch
			{
			}
		}
		return (from x in list.GroupBy<BrowserHistoryRecord, string>((BrowserHistoryRecord x) => string.Join("|", x.Browser, x.Profile, x.Url, x.VisitTimeUtc?.Ticks ?? 0), StringComparer.OrdinalIgnoreCase)
			select x.First() into x
			orderby x.VisitTimeUtc ?? DateTime.MinValue descending
			select x).Take(1500).ToList();
	}

	private static List<BrowserHistoryRecord> ReadChromium(HistoryProfile profile, IReadOnlyCollection<string> catalogTerms)
	{
		List<BrowserHistoryRecord> list = new List<BrowserHistoryRecord>();
		string text = CreateSnapshot(profile.DatabasePath);
		if (text == null)
		{
			return list;
		}
		try
		{
			using SqliteConnection sqliteConnection = Open(text);
			if (!TableExists(sqliteConnection, "urls"))
			{
				return list;
			}
			bool flag = TableExists(sqliteConnection, "visits");
			using SqliteCommand sqliteCommand = sqliteConnection.CreateCommand();
			sqliteCommand.CommandText = (flag ? "SELECT\n                        u.url,\n                        u.title,\n                        u.visit_count,\n                        u.typed_count,\n                        MAX(v.visit_time) AS last_visit\n                    FROM urls u\n                    LEFT JOIN visits v ON v.url = u.id\n                    GROUP BY u.id\n                    ORDER BY last_visit DESC\n                    LIMIT 25000" : "SELECT\n                        url,\n                        title,\n                        visit_count,\n                        typed_count,\n                        last_visit_time\n                    FROM urls\n                    ORDER BY last_visit_time DESC\n                    LIMIT 25000");
			using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
			while (sqliteDataReader.Read())
			{
				string url = GetString(sqliteDataReader, 0);
				string title = GetString(sqliteDataReader, 1);
				int @int = GetInt32(sqliteDataReader, 2);
				int int2 = GetInt32(sqliteDataReader, 3);
				DateTime? visitTime = ChromiumTime(GetInt64(sqliteDataReader, 4));
				BrowserHistoryRecord browserHistoryRecord = Evaluate(profile.Browser, profile.Profile, url, title, visitTime, @int, int2, "Chromium History/urls+visits", catalogTerms);
				if (browserHistoryRecord != null)
				{
					list.Add(browserHistoryRecord);
				}
			}
			return list;
		}
		finally
		{
			Cleanup(text);
		}
	}

	private static List<BrowserHistoryRecord> ReadFirefox(HistoryProfile profile, IReadOnlyCollection<string> catalogTerms)
	{
		List<BrowserHistoryRecord> list = new List<BrowserHistoryRecord>();
		string text = CreateSnapshot(profile.DatabasePath);
		if (text == null)
		{
			return list;
		}
		try
		{
			using SqliteConnection sqliteConnection = Open(text);
			if (!TableExists(sqliteConnection, "moz_places"))
			{
				return list;
			}
			bool flag = TableExists(sqliteConnection, "moz_historyvisits");
			using SqliteCommand sqliteCommand = sqliteConnection.CreateCommand();
			sqliteCommand.CommandText = (flag ? "SELECT\n                        p.url,\n                        p.title,\n                        p.visit_count,\n                        p.typed,\n                        MAX(h.visit_date) AS last_visit\n                    FROM moz_places p\n                    LEFT JOIN moz_historyvisits h ON h.place_id = p.id\n                    GROUP BY p.id\n                    ORDER BY last_visit DESC\n                    LIMIT 25000" : "SELECT\n                        url,\n                        title,\n                        visit_count,\n                        typed,\n                        last_visit_date\n                    FROM moz_places\n                    ORDER BY last_visit_date DESC\n                    LIMIT 25000");
			using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
			while (sqliteDataReader.Read())
			{
				string url = GetString(sqliteDataReader, 0);
				string title = GetString(sqliteDataReader, 1);
				int @int = GetInt32(sqliteDataReader, 2);
				int int2 = GetInt32(sqliteDataReader, 3);
				DateTime? visitTime = FirefoxTime(GetInt64(sqliteDataReader, 4));
				BrowserHistoryRecord browserHistoryRecord = Evaluate(profile.Browser, profile.Profile, url, title, visitTime, @int, int2, "Firefox places.sqlite", catalogTerms);
				if (browserHistoryRecord != null)
				{
					list.Add(browserHistoryRecord);
				}
			}
			return list;
		}
		finally
		{
			Cleanup(text);
		}
	}

	private static BrowserHistoryRecord? Evaluate(string browser, string profile, string url, string title, DateTime? visitTime, int visitCount, int typedCount, string source, IReadOnlyCollection<string> catalogTerms)
	{
		if (string.IsNullOrWhiteSpace(url))
		{
			return null;
		}
		string text = SafeDecode(url);
		string text2 = ExtractSearchQuery(url);
		string text3 = ExtractHost(url);
		string combined = string.Join(" ", text, title ?? "", text2, text3).ToLowerInvariant();
		HashSet<string> matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		string[] strongPhrases = StrongPhrases;
		foreach (string text4 in strongPhrases)
		{
			if (combined.Contains(text4, StringComparison.OrdinalIgnoreCase))
			{
				matches.Add(text4);
			}
		}
		strongPhrases = ContextTerms;
		foreach (string text5 in strongPhrases)
		{
			if (combined.Contains(text5, StringComparison.OrdinalIgnoreCase))
			{
				matches.Add(text5);
			}
		}
		bool flag = KnownRustCheatBrands.Concat(catalogTerms).Distinct<string>(StringComparer.OrdinalIgnoreCase).Any(delegate(string term)
		{
			if (string.IsNullOrWhiteSpace(term) || !ContainsCatalogTerm(combined, term))
			{
				return false;
			}
			matches.Add(term);
			return true;
		});
		bool flag2 = GameTerms.Any((string term) => combined.Contains(term, StringComparison.OrdinalIgnoreCase));
		bool flag3 = !string.IsNullOrWhiteSpace(text3) && (text3.Contains("cheat", StringComparison.OrdinalIgnoreCase) || text3.Contains("hack", StringComparison.OrdinalIgnoreCase) || text.Contains("/cheat", StringComparison.OrdinalIgnoreCase) || text.Contains("/hack", StringComparison.OrdinalIgnoreCase));
		if (BenignPhrases.Any((string phrase) => combined.Contains(phrase, StringComparison.OrdinalIgnoreCase)) && matches.Count <= 1 && !flag2 && !flag3)
		{
			return null;
		}
		bool flag4 = flag || StrongPhrases.Any((string phrase) => matches.Contains(phrase));
		bool flag5 = !string.IsNullOrWhiteSpace(text2) && (flag4 || (flag2 && matches.Count >= 1) || matches.Count >= 2);
		bool flag6 = flag3 || flag4 || (flag2 && matches.Count >= 1);
		if (!flag5 && !flag6)
		{
			return null;
		}
		int num = 0;
		if (flag4)
		{
			num += 3;
		}
		if (flag)
		{
			num += 3;
		}
		if (flag3)
		{
			num += 2;
		}
		if (flag2)
		{
			num++;
		}
		if (flag5)
		{
			num += 2;
		}
		if (matches.Count >= 2)
		{
			num++;
		}
		if (typedCount > 0)
		{
			num++;
		}
		string riskLevel = ((num >= 5) ? "high" : ((num >= 3) ? "medium" : "low"));
		string reason = (flag ? "Nome conhecido de software/comunidade de cheat/script para Rust" : (flag5 ? "Pesquisa/consulta relacionada a cheat/script/hack" : (flag3 ? "Site/URL com indicador explícito de cheat/hack" : "Página relacionada a termos de cheat/script para Rust")));
		return new BrowserHistoryRecord
		{
			Browser = browser,
			Profile = profile,
			Url = url,
			Host = text3,
			Title = (title ?? ""),
			SearchQuery = text2,
			VisitTimeUtc = visitTime,
			VisitCount = visitCount,
			TypedCount = typedCount,
			MatchedTerms = matches.OrderBy<string, string>((string x) => x, StringComparer.OrdinalIgnoreCase).ToList(),
			RiskLevel = riskLevel,
			RiskScore = num,
			Reason = reason,
			DatabaseSource = source
		};
	}

	private static bool IsDistinctiveCatalogAlias(string value)
	{
		string text = (value ?? "").Trim();
		if (text.Length >= 7)
		{
			return true;
		}
		string text2 = text.ToLowerInvariant();
		if (!text2.Contains("rust") && !text2.Contains("cheat") && !text2.Contains("script") && !text2.Contains("aimbot") && !text2.Contains("recoil") && !text2.Contains("loader") && !text2.Contains("private") && !text2.Contains("dma") && !text2.Contains("external"))
		{
			return text2.Contains("internal");
		}
		return true;
	}

	private static bool ContainsCatalogTerm(string haystack, string value)
	{
		string text = (value ?? "").Trim();
		if (text.Length == 0)
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

	private static IReadOnlyCollection<string> BuildCatalogTerms(IEnumerable<RustThreatIndicator>? threatCatalog)
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		if (threatCatalog == null)
		{
			return hashSet;
		}
		foreach (RustThreatIndicator item in threatCatalog)
		{
			foreach (string item2 in item.Aliases ?? new List<string>())
			{
				string text = item2.Trim();
				if (!string.IsNullOrWhiteSpace(text) && IsDistinctiveCatalogAlias(text))
				{
					hashSet.Add(text);
				}
			}
			foreach (string item3 in item.Domains ?? new List<string>())
			{
				string text2 = item3.Trim();
				if (!string.IsNullOrWhiteSpace(text2))
				{
					hashSet.Add(text2);
				}
			}
			foreach (string item4 in item.DiscordInvites ?? new List<string>())
			{
				string text3 = item4.Trim();
				if (!string.IsNullOrWhiteSpace(text3))
				{
					hashSet.Add("discord.gg/" + text3);
					hashSet.Add("discord.com/invite/" + text3);
					hashSet.Add("discord.me/" + text3);
				}
			}
		}
		return hashSet;
	}

	private static string ExtractSearchQuery(string url)
	{
		try
		{
			if (!Uri.TryCreate(url, UriKind.Absolute, out Uri result))
			{
				return "";
			}
			HashSet<string> hashSet = new HashSet<string>(new string[8] { "q", "query", "search", "search_query", "text", "p", "keyword", "keywords" }, StringComparer.OrdinalIgnoreCase);
			string[] array = result.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
			for (int i = 0; i < array.Length; i++)
			{
				string[] array2 = array[i].Split('=', 2);
				if (array2.Length == 0)
				{
					continue;
				}
				string item = Uri.UnescapeDataString(array2[0].Replace('+', ' '));
				if (hashSet.Contains(item))
				{
					string text = ((array2.Length > 1) ? Uri.UnescapeDataString(array2[1].Replace('+', ' ')) : "");
					if (!string.IsNullOrWhiteSpace(text))
					{
						return text.Trim();
					}
				}
			}
		}
		catch
		{
		}
		return "";
	}

	private static string ExtractHost(string url)
	{
		try
		{
			Uri result;
			return Uri.TryCreate(url, UriKind.Absolute, out result) ? result.Host : "";
		}
		catch
		{
			return "";
		}
	}

	private static string SafeDecode(string value)
	{
		try
		{
			return Uri.UnescapeDataString(value.Replace('+', ' '));
		}
		catch
		{
			return value;
		}
	}

	private static IEnumerable<HistoryProfile> EnumerateChromiumProfiles()
	{
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		string folderPath2 = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
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
				Path = Path.Combine(folderPath2, "Opera Software", "Opera Stable"),
				RootIsProfile = true
			},
			new
			{
				Browser = "Opera GX",
				Path = Path.Combine(folderPath2, "Opera Software", "Opera GX Stable"),
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
				string text = Path.Combine(root.Path, "History");
				if (File.Exists(text))
				{
					yield return new HistoryProfile
					{
						Browser = root.Browser,
						Profile = Path.GetFileName(root.Path),
						DatabasePath = text
					};
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
			foreach (string item in enumerable)
			{
				string fileName = Path.GetFileName(item);
				if (fileName.Equals("Default", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase) || fileName.Equals("Guest Profile", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith("System Profile", StringComparison.OrdinalIgnoreCase))
				{
					string text2 = Path.Combine(item, "History");
					if (File.Exists(text2))
					{
						yield return new HistoryProfile
						{
							Browser = root.Browser,
							Profile = fileName,
							DatabasePath = text2
						};
					}
				}
			}
		}
	}

	private static IEnumerable<HistoryProfile> EnumerateFirefoxProfiles()
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox", "Profiles");
		if (!Directory.Exists(path))
		{
			yield break;
		}
		IEnumerable<string> enumerable;
		try
		{
			enumerable = Directory.EnumerateDirectories(path);
		}
		catch
		{
			yield break;
		}
		foreach (string item in enumerable)
		{
			string text = Path.Combine(item, "places.sqlite");
			if (File.Exists(text))
			{
				yield return new HistoryProfile
				{
					Browser = "Mozilla Firefox",
					Profile = Path.GetFileName(item),
					DatabasePath = text
				};
			}
		}
	}

	private static string? CreateSnapshot(string source)
	{
		string text = null;
		try
		{
			text = Path.Combine(Path.GetTempPath(), "Noryx", "BrowserHistoryDb", Guid.NewGuid().ToString("N"));
			Directory.CreateDirectory(text);
			string text2 = Path.Combine(text, Path.GetFileName(source));
			CopyOpenFile(source, text2);
			string[] array = new string[2] { "-wal", "-shm" };
			foreach (string text3 in array)
			{
				string text4 = source + text3;
				if (File.Exists(text4))
				{
					try
					{
						CopyOpenFile(text4, text2 + text3);
					}
					catch
					{
					}
				}
			}
			return text2;
		}
		catch
		{
			if (!string.IsNullOrWhiteSpace(text))
			{
				try
				{
					Directory.Delete(text, recursive: true);
				}
				catch
				{
				}
			}
			return null;
		}
	}

	private static void CopyOpenFile(string source, string destination)
	{
		using FileStream fileStream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
		using FileStream destination2 = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
		fileStream.CopyTo(destination2);
	}

	private static SqliteConnection Open(string path)
	{
		SqliteConnection sqliteConnection = new SqliteConnection(new SqliteConnectionStringBuilder
		{
			DataSource = path,
			Mode = SqliteOpenMode.ReadOnly,
			Cache = SqliteCacheMode.Private,
			Pooling = false
		}.ToString());
		sqliteConnection.Open();
		return sqliteConnection;
	}

	private static bool TableExists(SqliteConnection connection, string table)
	{
		using SqliteCommand sqliteCommand = connection.CreateCommand();
		sqliteCommand.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1";
		sqliteCommand.Parameters.AddWithValue("$name", table);
		return sqliteCommand.ExecuteScalar() != null;
	}

	private static DateTime? ChromiumTime(long microseconds)
	{
		if (microseconds <= 0)
		{
			return null;
		}
		try
		{
			return ChromiumEpoch.AddTicks(checked(microseconds * 10));
		}
		catch
		{
			return null;
		}
	}

	private static DateTime? FirefoxTime(long microseconds)
	{
		if (microseconds <= 0)
		{
			return null;
		}
		try
		{
			return DateTime.UnixEpoch.AddTicks(checked(microseconds * 10));
		}
		catch
		{
			return null;
		}
	}

	private static string GetString(SqliteDataReader reader, int ordinal)
	{
		if (reader.IsDBNull(ordinal))
		{
			return "";
		}
		try
		{
			return reader.GetString(ordinal) ?? "";
		}
		catch
		{
			return Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture) ?? "";
		}
	}

	private static long GetInt64(SqliteDataReader reader, int ordinal)
	{
		if (reader.IsDBNull(ordinal))
		{
			return 0L;
		}
		try
		{
			return reader.GetInt64(ordinal);
		}
		catch
		{
			try
			{
				return Convert.ToInt64(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
			}
			catch
			{
				return 0L;
			}
		}
	}

	private static int GetInt32(SqliteDataReader reader, int ordinal)
	{
		long @int = GetInt64(reader, ordinal);
		if (@int > int.MaxValue)
		{
			return int.MaxValue;
		}
		if (@int < int.MinValue)
		{
			return int.MinValue;
		}
		return (int)@int;
	}

	private static void Cleanup(string path)
	{
		try
		{
			string directoryName = Path.GetDirectoryName(path);
			if (!string.IsNullOrWhiteSpace(directoryName) && Directory.Exists(directoryName))
			{
				Directory.Delete(directoryName, recursive: true);
			}
		}
		catch
		{
		}
	}
}
