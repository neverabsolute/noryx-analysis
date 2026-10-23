using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Noryx.Agent;

internal static class AgentRecoveryStore
{
	private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Noryx.Recovery.v1");

	private static string FileFor(string key)
	{
		string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Noryx", "Recovery");
		Directory.CreateDirectory(text);
		return Path.Combine(text, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".bin");
	}

	private static byte[]? Read(string key)
	{
		string path = FileFor(key);
		if (!File.Exists(path))
		{
			return null;
		}
		if (DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > TimeSpan.FromHours(24.0))
		{
			File.Delete(path);
			return null;
		}
		return ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser);
	}

	private static void Write(string key, byte[] value)
	{
		string text = FileFor(key);
		string text2 = text + "." + Guid.NewGuid().ToString("N") + ".tmp";
		File.WriteAllBytes(text2, ProtectedData.Protect(value, Entropy, DataProtectionScope.CurrentUser));
		File.Move(text2, text, overwrite: true);
	}

	private static string SessionKey(string server, string code)
	{
		return server.TrimEnd('/') + "|code|" + code.Trim().Replace("-", "").ToUpperInvariant();
	}

	internal static string ClaimSecret(string server, string code)
	{
		string key = SessionKey(server, code) + "|secret";
		byte[] array = Read(key);
		if (array != null)
		{
			return Encoding.UTF8.GetString(array);
		}
		string text = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
		Write(key, Encoding.UTF8.GetBytes(text));
		return text;
	}

	internal static void RememberToken(string server, string code, string token)
	{
		Write(SessionKey(server, code) + "|token", Encoding.UTF8.GetBytes(token));
	}

	internal static string? PendingToken(string server, string code)
	{
		byte[] array = Read(SessionKey(server, code) + "|token");
		if (array == null)
		{
			return null;
		}
		string text = Encoding.UTF8.GetString(array);
		if (LoadReport(server, text) == null)
		{
			return null;
		}
		return text;
	}

	internal static byte[]? LoadReport(string server, string token)
	{
		return Read(server.TrimEnd('/') + "|report|" + token);
	}

	internal static void SaveReport(string server, string token, byte[] bytes)
	{
		Write(server.TrimEnd('/') + "|report|" + token, bytes);
	}

	internal static void DeleteReport(string server, string token)
	{
		File.Delete(FileFor(server.TrimEnd('/') + "|report|" + token));
	}
}
