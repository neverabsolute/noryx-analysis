using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Noryx.Agent;

internal static class BrowserDownloadsCollector
{
	private static readonly DateTime ChromiumEpoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	private static readonly DateTime UnixEpoch = DateTime.UnixEpoch;

	public static List<BrowserDownloadRecord> Collect()
	{
		List<BrowserDownloadRecord> list = new List<BrowserDownloadRecord>();
		foreach (BrowserProfile item in EnumerateChromiumProfiles())
		{
			try
			{
				list.AddRange(ReadChromiumProfile(item));
			}
			catch
			{
			}
		}
		foreach (BrowserProfile item2 in EnumerateFirefoxProfiles())
		{
			try
			{
				list.AddRange(ReadFirefoxProfile(item2));
			}
			catch
			{
			}
		}
		return (from x in list.GroupBy<BrowserDownloadRecord, string>((BrowserDownloadRecord x) => string.Join("|", x.Browser, x.Profile, x.TargetPath, x.SourceUrl, x.StartTimeUtc?.Ticks ?? 0), StringComparer.OrdinalIgnoreCase)
			select x.First() into x
			orderby x.StartTimeUtc ?? DateTime.MinValue descending
			select x).Take(5000).ToList();
	}

	private static IEnumerable<BrowserProfile> EnumerateChromiumProfiles()
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
					yield return new BrowserProfile
					{
						Browser = root.Browser,
						Profile = Path.GetFileName(root.Path),
						DatabasePath = text,
						Kind = BrowserDatabaseKind.Chromium
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
						yield return new BrowserProfile
						{
							Browser = root.Browser,
							Profile = fileName,
							DatabasePath = text2,
							Kind = BrowserDatabaseKind.Chromium
						};
					}
				}
			}
		}
	}

	private static IEnumerable<BrowserProfile> EnumerateFirefoxProfiles()
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
				yield return new BrowserProfile
				{
					Browser = "Mozilla Firefox",
					Profile = Path.GetFileName(item),
					DatabasePath = text,
					Kind = BrowserDatabaseKind.Firefox
				};
			}
		}
	}

	private static List<BrowserDownloadRecord> ReadChromiumProfile(BrowserProfile profile)
	{
		List<BrowserDownloadRecord> list = new List<BrowserDownloadRecord>();
		string text = CreateSqliteSnapshot(profile.DatabasePath);
		if (text == null)
		{
			return list;
		}
		try
		{
			using SqliteConnection sqliteConnection = Open(text);
			if (!TableExists(sqliteConnection, "downloads"))
			{
				return list;
			}
			HashSet<string> columns = GetColumns(sqliteConnection, "downloads");
			string text2 = string.Join(",", Expr(columns, "id", "0"), Expr(columns, "current_path", "''"), Expr(columns, "target_path", "''"), Expr(columns, "start_time", "0"), Expr(columns, "end_time", "0"), Expr(columns, "state", "-1"), Expr(columns, "danger_type", "-1"), Expr(columns, "received_bytes", "0"), Expr(columns, "total_bytes", "0"), Expr(columns, "opened", "0"), Expr(columns, "referrer", "''"), Expr(columns, "site_url", "''"), Expr(columns, "tab_url", "''"), Expr(columns, "tab_referrer_url", "''"), Expr(columns, "http_method", "''"), Expr(columns, "by_ext_name", "''"), Expr(columns, "mime_type", "''"), Expr(columns, "original_mime_type", "''"));
			Dictionary<long, BrowserDownloadRecord> dictionary = new Dictionary<long, BrowserDownloadRecord>();
			using (SqliteCommand sqliteCommand = sqliteConnection.CreateCommand())
			{
				sqliteCommand.CommandText = "SELECT " + text2 + " FROM downloads ORDER BY start_time DESC LIMIT 5000";
				using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
				while (sqliteDataReader.Read())
				{
					long @int = GetInt64(sqliteDataReader, 0);
					string text3 = GetString(sqliteDataReader, 1);
					string text4 = GetString(sqliteDataReader, 2);
					string text5 = ((!string.IsNullOrWhiteSpace(text4)) ? text4 : text3);
					BrowserDownloadRecord browserDownloadRecord = new BrowserDownloadRecord();
					browserDownloadRecord.Browser = profile.Browser;
					browserDownloadRecord.Profile = profile.Profile;
					browserDownloadRecord.TargetPath = text5;
					browserDownloadRecord.CurrentPath = text3;
					browserDownloadRecord.FileName = SafeFileName(text5);
					browserDownloadRecord.FileExists = SafeExists(text5);
					browserDownloadRecord.StartTimeUtc = ChromiumTime(GetInt64(sqliteDataReader, 3));
					browserDownloadRecord.EndTimeUtc = ChromiumTime(GetInt64(sqliteDataReader, 4));
					browserDownloadRecord.State = ChromiumState(GetInt32(sqliteDataReader, 5));
					browserDownloadRecord.DangerType = GetInt32(sqliteDataReader, 6);
					browserDownloadRecord.ReceivedBytes = GetInt64(sqliteDataReader, 7);
					browserDownloadRecord.TotalBytes = GetInt64(sqliteDataReader, 8);
					browserDownloadRecord.Opened = GetInt32(sqliteDataReader, 9) != 0;
					browserDownloadRecord.ReferrerUrl = GetString(sqliteDataReader, 10);
					browserDownloadRecord.SiteUrl = GetString(sqliteDataReader, 11);
					browserDownloadRecord.PageUrl = FirstNonEmpty(GetString(sqliteDataReader, 12), GetString(sqliteDataReader, 13), GetString(sqliteDataReader, 10), GetString(sqliteDataReader, 11));
					browserDownloadRecord.HttpMethod = GetString(sqliteDataReader, 14);
					browserDownloadRecord.InitiatedByExtension = GetString(sqliteDataReader, 15);
					browserDownloadRecord.MimeType = FirstNonEmpty(GetString(sqliteDataReader, 16), GetString(sqliteDataReader, 17));
					browserDownloadRecord.DatabaseSource = "Chromium History/downloads";
					BrowserDownloadRecord browserDownloadRecord2 = browserDownloadRecord;
					browserDownloadRecord2.FileMissing = !string.IsNullOrWhiteSpace(browserDownloadRecord2.TargetPath) && !browserDownloadRecord2.FileExists;
					dictionary[@int] = browserDownloadRecord2;
					list.Add(browserDownloadRecord2);
				}
			}
			if (TableExists(sqliteConnection, "downloads_url_chains"))
			{
				using SqliteCommand sqliteCommand2 = sqliteConnection.CreateCommand();
				sqliteCommand2.CommandText = "SELECT id, chain_index, url\n                      FROM downloads_url_chains\n                      ORDER BY id ASC, chain_index ASC";
				using SqliteDataReader sqliteDataReader2 = sqliteCommand2.ExecuteReader();
				while (sqliteDataReader2.Read())
				{
					long int2 = GetInt64(sqliteDataReader2, 0);
					if (dictionary.TryGetValue(int2, out var value))
					{
						string text6 = GetString(sqliteDataReader2, 2);
						if (!string.IsNullOrWhiteSpace(text6))
						{
							value.UrlChain.Add(text6);
						}
					}
				}
				foreach (BrowserDownloadRecord item in list)
				{
					item.SourceUrl = item.UrlChain.FirstOrDefault() ?? "";
					item.FinalUrl = item.UrlChain.LastOrDefault() ?? item.SourceUrl;
				}
			}
			foreach (BrowserDownloadRecord item2 in list)
			{
				if (string.IsNullOrWhiteSpace(item2.SourceUrl))
				{
					item2.SourceUrl = FirstNonEmpty(item2.ReferrerUrl, item2.SiteUrl, item2.PageUrl);
				}
				if (string.IsNullOrWhiteSpace(item2.FinalUrl))
				{
					item2.FinalUrl = item2.SourceUrl;
				}
			}
			return list;
		}
		finally
		{
			CleanupSnapshot(text);
		}
	}

	private static List<BrowserDownloadRecord> ReadFirefoxProfile(BrowserProfile profile)
	{
		List<BrowserDownloadRecord> list = new List<BrowserDownloadRecord>();
		string text = CreateSqliteSnapshot(profile.DatabasePath);
		if (text == null)
		{
			return list;
		}
		try
		{
			using SqliteConnection sqliteConnection = Open(text);
			if (!TableExists(sqliteConnection, "moz_places") || !TableExists(sqliteConnection, "moz_annos") || !TableExists(sqliteConnection, "moz_anno_attributes"))
			{
				return list;
			}
			string commandText = "SELECT\n                    p.id,\n                    p.url,\n                    a.content,\n                    a.dateAdded,\n                    a.lastModified\n                  FROM moz_annos a\n                  JOIN moz_anno_attributes aa\n                    ON aa.id = a.anno_attribute_id\n                  JOIN moz_places p\n                    ON p.id = a.place_id\n                  WHERE aa.name = 'downloads/destinationFileURI'\n                  ORDER BY a.dateAdded DESC\n                  LIMIT 5000";
			using SqliteCommand sqliteCommand = sqliteConnection.CreateCommand();
			sqliteCommand.CommandText = commandText;
			using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
			while (sqliteDataReader.Read())
			{
				long @int = GetInt64(sqliteDataReader, 0);
				string text2 = GetString(sqliteDataReader, 1);
				string text3 = FileUriToPath(GetString(sqliteDataReader, 2));
				BrowserDownloadRecord browserDownloadRecord = new BrowserDownloadRecord
				{
					Browser = profile.Browser,
					Profile = profile.Profile,
					SourceUrl = text2,
					FinalUrl = text2,
					TargetPath = text3,
					CurrentPath = text3,
					FileName = SafeFileName(text3),
					FileExists = SafeExists(text3),
					StartTimeUtc = FirefoxTime(GetInt64(sqliteDataReader, 3)),
					EndTimeUtc = FirefoxTime(GetInt64(sqliteDataReader, 4)),
					State = "history",
					ReferrerUrl = "",
					SiteUrl = "",
					PageUrl = text2,
					MimeType = "",
					DatabaseSource = "Firefox places.sqlite/moz_annos",
					FirefoxPlaceId = @int
				};
				browserDownloadRecord.FileMissing = !string.IsNullOrWhiteSpace(browserDownloadRecord.TargetPath) && !browserDownloadRecord.FileExists;
				list.Add(browserDownloadRecord);
			}
			TryAddFirefoxMetadata(sqliteConnection, list);
			return list;
		}
		finally
		{
			CleanupSnapshot(text);
		}
	}

	private static void TryAddFirefoxMetadata(SqliteConnection connection, List<BrowserDownloadRecord> records)
	{
		if (records.Count == 0)
		{
			return;
		}
		Dictionary<long, BrowserDownloadRecord> dictionary = (from x in records
			where x.FirefoxPlaceId.HasValue
			group x by x.FirefoxPlaceId.Value).ToDictionary((IGrouping<long, BrowserDownloadRecord> x) => x.Key, (IGrouping<long, BrowserDownloadRecord> x) => x.First());
		try
		{
			using SqliteCommand sqliteCommand = connection.CreateCommand();
			sqliteCommand.CommandText = "SELECT\n                    a.place_id,\n                    a.content\n                  FROM moz_annos a\n                  JOIN moz_anno_attributes aa\n                    ON aa.id = a.anno_attribute_id\n                  WHERE aa.name = 'downloads/metaData'";
			using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
			while (sqliteDataReader.Read())
			{
				long @int = GetInt64(sqliteDataReader, 0);
				if (!dictionary.TryGetValue(@int, out var value))
				{
					continue;
				}
				string text = GetString(sqliteDataReader, 1);
				if (string.IsNullOrWhiteSpace(text))
				{
					continue;
				}
				try
				{
					using JsonDocument jsonDocument = JsonDocument.Parse(text);
					JsonElement rootElement = jsonDocument.RootElement;
					if (rootElement.TryGetProperty("fileSize", out var value2) && value2.TryGetInt64(out var value3))
					{
						value.TotalBytes = value3;
					}
					if (rootElement.TryGetProperty("state", out var value4))
					{
						BrowserDownloadRecord browserDownloadRecord = value;
						browserDownloadRecord.State = value4.ValueKind switch
						{
							JsonValueKind.Number => value4.GetInt32().ToString(CultureInfo.InvariantCulture), 
							JsonValueKind.String => value4.GetString() ?? value.State, 
							_ => value.State, 
						};
					}
					if (rootElement.TryGetProperty("endTime", out var value5) && value5.TryGetInt64(out var value6))
					{
						try
						{
							value.EndTimeUtc = DateTimeOffset.FromUnixTimeMilliseconds(value6).UtcDateTime;
						}
						catch
						{
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
	}

	private static string? CreateSqliteSnapshot(string source)
	{
		string text = null;
		try
		{
			text = Path.Combine(Path.GetTempPath(), "Noryx", "BrowserDb", Guid.NewGuid().ToString("N"));
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

	private static HashSet<string> GetColumns(SqliteConnection connection, string table)
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		using SqliteCommand sqliteCommand = connection.CreateCommand();
		sqliteCommand.CommandText = "PRAGMA table_info([" + table.Replace("]", "]]") + "])";
		using SqliteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();
		while (sqliteDataReader.Read())
		{
			string text = sqliteDataReader.GetString(1);
			if (!string.IsNullOrWhiteSpace(text))
			{
				hashSet.Add(text);
			}
		}
		return hashSet;
	}

	private static string Expr(HashSet<string> columns, string name, string fallback)
	{
		if (!columns.Contains(name))
		{
			return fallback;
		}
		return "[" + name + "]";
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
			return UnixEpoch.AddTicks(checked(microseconds * 10));
		}
		catch
		{
			return null;
		}
	}

	private static string ChromiumState(int value)
	{
		return value switch
		{
			0 => "in_progress", 
			1 => "complete", 
			2 => "cancelled", 
			3 => "interrupted", 
			4 => "interrupted", 
			_ => value.ToString(CultureInfo.InvariantCulture), 
		};
	}

	private static string FileUriToPath(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return "";
		}
		try
		{
			if (Uri.TryCreate(value, UriKind.Absolute, out Uri result) && result.IsFile)
			{
				return result.LocalPath;
			}
		}
		catch
		{
		}
		return Uri.UnescapeDataString(value.Replace("file:///", "", StringComparison.OrdinalIgnoreCase).Replace('/', Path.DirectorySeparatorChar));
	}

	private static string SafeFileName(string path)
	{
		try
		{
			return Path.GetFileName(path) ?? "";
		}
		catch
		{
			return "";
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

	private static void CleanupSnapshot(string path)
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

	private static string FirstNonEmpty(params string[] values)
	{
		return values.FirstOrDefault((string x) => !string.IsNullOrWhiteSpace(x)) ?? "";
	}
}
