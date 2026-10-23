using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class SteamAccountCollector
{
	private const ulong SteamId64Base = 76561197960265728uL;

	private static readonly Regex SteamIdBlockRegex = new Regex("^\\s*\"(?<id>\\d{17})\"\\s*$", RegexOptions.Compiled);

	private static readonly Regex VdfPairRegex = new Regex("^\\s*\"(?<key>[^\"]+)\"\\s*\"(?<value>[^\"]*)\"\\s*$", RegexOptions.Compiled);

	public static List<SteamAccountRecord> Collect()
	{
		Dictionary<string, SteamAccountRecord> dictionary = new Dictionary<string, SteamAccountRecord>(StringComparer.Ordinal);
		foreach (string item in DiscoverSteamRoots())
		{
			ReadLoginUsers(Path.Combine(item, "config", "loginusers.vdf"), dictionary);
			ReadUserData(Path.Combine(item, "userdata"), dictionary);
		}
		return (from item in dictionary.Values
			where Regex.IsMatch(item.SteamId64, "^7656119\\d{10}$")
			orderby item.MostRecent descending, item.LastSeenUtc ?? DateTime.MinValue descending
			select item).ThenBy<SteamAccountRecord, string>((SteamAccountRecord item) => item.SteamId64, StringComparer.Ordinal).ToList();
	}

	private static IEnumerable<string> DiscoverSteamRoots()
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		AddRegistryPath(hashSet, Registry.CurrentUser, "Software\\Valve\\Steam", "SteamPath");
		try
		{
			using RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			AddRegistryPath(hashSet, root, "SOFTWARE\\Valve\\Steam", "InstallPath");
		}
		catch
		{
		}
		try
		{
			using RegistryKey root2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
			AddRegistryPath(hashSet, root2, "SOFTWARE\\Valve\\Steam", "InstallPath");
		}
		catch
		{
		}
		AddCandidate(hashSet, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam"));
		AddCandidate(hashSet, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam"));
		return hashSet.Where(Directory.Exists).Distinct<string>(StringComparer.OrdinalIgnoreCase);
	}

	private static void AddRegistryPath(HashSet<string> paths, RegistryKey root, string keyPath, string valueName)
	{
		try
		{
			using RegistryKey registryKey = root.OpenSubKey(keyPath);
			AddCandidate(paths, Convert.ToString(registryKey?.GetValue(valueName)));
		}
		catch
		{
		}
	}

	private static void AddCandidate(HashSet<string> paths, string? value)
	{
		string text = String(value).Replace('/', Path.DirectorySeparatorChar).Trim().Trim('"');
		if (text.Length != 0)
		{
			try
			{
				text = Path.GetFullPath(text);
			}
			catch
			{
				return;
			}
			paths.Add(text);
		}
	}

	private static void ReadLoginUsers(string filePath, Dictionary<string, SteamAccountRecord> accounts)
	{
		if (!File.Exists(filePath))
		{
			return;
		}
		string text = null;
		foreach (string item in File.ReadLines(filePath))
		{
			Match match = SteamIdBlockRegex.Match(item);
			if (match.Success)
			{
				text = match.Groups["id"].Value;
				SteamAccountRecord orCreate = GetOrCreate(accounts, text);
				orCreate.SavedLogin = true;
				AddSource(orCreate, "loginusers.vdf");
			}
			else
			{
				if (text == null)
				{
					continue;
				}
				Match match2 = VdfPairRegex.Match(item);
				if (!match2.Success)
				{
					continue;
				}
				SteamAccountRecord orCreate2 = GetOrCreate(accounts, text);
				string value = match2.Groups["key"].Value;
				string value2 = match2.Groups["value"].Value;
				switch (value.ToLowerInvariant())
				{
				case "accountname":
					orCreate2.AccountName = value2;
					break;
				case "personaname":
					orCreate2.PersonaName = value2;
					break;
				case "mostrecent":
					orCreate2.MostRecent = value2 == "1" || value2.Equals("true", StringComparison.OrdinalIgnoreCase);
					break;
				case "rememberpassword":
					orCreate2.RememberPassword = value2 == "1" || value2.Equals("true", StringComparison.OrdinalIgnoreCase);
					break;
				case "timestamp":
				{
					if (long.TryParse(value2, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) && result > 0)
					{
						try
						{
							orCreate2.LastSeenUtc = DateTimeOffset.FromUnixTimeSeconds(result).UtcDateTime;
						}
						catch
						{
						}
					}
					break;
				}
				}
			}
		}
	}

	private static void ReadUserData(string userDataPath, Dictionary<string, SteamAccountRecord> accounts)
	{
		if (!Directory.Exists(userDataPath))
		{
			return;
		}
		IEnumerable<string> enumerable;
		try
		{
			enumerable = Directory.EnumerateDirectories(userDataPath);
		}
		catch
		{
			return;
		}
		foreach (string item in enumerable)
		{
			if (!ulong.TryParse(Path.GetFileName(item), NumberStyles.None, CultureInfo.InvariantCulture, out var result) || result == 0L || result > uint.MaxValue)
			{
				continue;
			}
			string steamId = (76561197960265728L + result).ToString(CultureInfo.InvariantCulture);
			SteamAccountRecord orCreate = GetOrCreate(accounts, steamId);
			orCreate.AccountId = result.ToString(CultureInfo.InvariantCulture);
			orCreate.UserDataPresent = true;
			AddSource(orCreate, "userdata");
			try
			{
				DateTime lastWriteTimeUtc = Directory.GetLastWriteTimeUtc(item);
				if (lastWriteTimeUtc.Year > 2000 && (!orCreate.LastSeenUtc.HasValue || lastWriteTimeUtc > orCreate.LastSeenUtc.Value))
				{
					orCreate.LastSeenUtc = lastWriteTimeUtc;
				}
			}
			catch
			{
			}
		}
	}

	private static SteamAccountRecord GetOrCreate(Dictionary<string, SteamAccountRecord> accounts, string steamId64)
	{
		if (accounts.TryGetValue(steamId64, out SteamAccountRecord value))
		{
			return value;
		}
		ulong num = 0uL;
		if (ulong.TryParse(steamId64, NumberStyles.None, CultureInfo.InvariantCulture, out var result) && result >= 76561197960265728L)
		{
			num = result - 76561197960265728L;
		}
		return accounts[steamId64] = new SteamAccountRecord
		{
			SteamId64 = steamId64,
			AccountId = ((num != 0) ? num.ToString(CultureInfo.InvariantCulture) : ""),
			ProfileUrl = "https://steamcommunity.com/profiles/" + steamId64
		};
	}

	private static void AddSource(SteamAccountRecord account, string source)
	{
		if (!account.Sources.Contains<string>(source, StringComparer.OrdinalIgnoreCase))
		{
			account.Sources.Add(source);
		}
	}

	private static string String(string? value)
	{
		return value ?? "";
	}
}
