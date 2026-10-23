using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Noryx.Agent;

internal static class PeInspectionCollector
{
	private static readonly string[] PackerTokens = new string[13]
	{
		"UPX0", "UPX1", "UPX!", "VMProtect", ".vmp0", ".vmp1", "Themida", "WinLicense", "Enigma Protector", "MPRESS",
		"ASPack", "PECompact", "Obsidium"
	};

	private static readonly string[] SuspiciousApiTokens = new string[16]
	{
		"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "NtCreateThreadEx", "SetWindowsHookEx", "QueueUserAPC", "MapViewOfFile", "MiniDumpWriteDump", "mouse_event",
		"SendInput", "SetCursorPos", "GetAsyncKeyState", "WinVerifyTrust", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
	};

	private static readonly string[] EnvironmentProbeTokens = new string[9] { "VMware", "VirtualBox", "VBox", "QEMU", "Sandboxie", "Wireshark", "ProcessHacker", "x64dbg", "ollydbg" };

	public static List<PeInspectionRecord> Collect(List<FileRecord> files)
	{
		List<PeInspectionRecord> list = new List<PeInspectionRecord>();
		foreach (FileRecord file in files)
		{
			if (list.Count >= 1200)
			{
				break;
			}
			switch ((file.Extension ?? "").ToLowerInvariant())
			{
			case ".exe":
			case ".dll":
			case ".sys":
			case ".scr":
			case ".com":
				if (string.IsNullOrWhiteSpace(file.Path) || !File.Exists(file.Path))
				{
					break;
				}
				try
				{
					FileInfo fileInfo = new FileInfo(file.Path);
					if (fileInfo.Length <= 0 || fileInfo.Length > 367001600)
					{
						break;
					}
					byte[] array = ReadSample(file.Path, 8388608);
					if (array.Length >= 64)
					{
						double num = ShannonEntropy(array);
						List<string> list2 = TryReadPeSectionNames(array);
						string haystack = ToSearchableAscii(array);
						List<string> list3 = MatchTokens(haystack, PackerTokens);
						List<string> list4 = MatchTokens(haystack, SuspiciousApiTokens);
						List<string> list5 = MatchTokens(haystack, EnvironmentProbeTokens);
						bool flag = num >= 7.35 && fileInfo.Length >= 65536;
						bool packedLike = list3.Count > 0 || (flag && !file.Signed && list2.Any((string x) => x.StartsWith(".vmp", StringComparison.OrdinalIgnoreCase) || x.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)));
						if (flag || list3.Count != 0 || list4.Count != 0 || list5.Count != 0 || file.RandomLikeName)
						{
							list.Add(new PeInspectionRecord
							{
								Name = file.Name,
								Path = file.Path,
								Sha256 = (file.Sha256 ?? ""),
								Signed = file.Signed,
								SignerSubject = (file.SignerSubject ?? ""),
								Size = fileInfo.Length,
								Entropy = Math.Round(num, 3),
								HighEntropy = flag,
								PackedLike = packedLike,
								PackerIndicators = list3,
								SuspiciousApis = list4,
								EnvironmentProbeIndicators = list5,
								SectionNames = list2,
								CompilationTimeUtc = file.CompilationTimeUtc,
								RandomLikeName = file.RandomLikeName
							});
						}
					}
				}
				catch
				{
				}
				break;
			}
		}
		return list;
	}

	private static byte[] ReadSample(string path, int maxBytes)
	{
		using FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
		int num = (int)Math.Min(fileStream.Length, maxBytes);
		byte[] array = new byte[num];
		int i;
		int num2;
		for (i = 0; i < num; i += num2)
		{
			num2 = fileStream.Read(array, i, num - i);
			if (num2 <= 0)
			{
				break;
			}
		}
		if (i == num)
		{
			return array;
		}
		return array[..i];
	}

	private static double ShannonEntropy(byte[] data)
	{
		if (data.Length == 0)
		{
			return 0.0;
		}
		Span<int> span = stackalloc int[256];
		for (int i = 0; i < data.Length; i++)
		{
			span[data[i]]++;
		}
		double num = 0.0;
		for (int j = 0; j < span.Length; j++)
		{
			if (span[j] != 0)
			{
				double num2 = (double)span[j] / (double)data.Length;
				num -= num2 * Math.Log2(num2);
			}
		}
		return num;
	}

	private static string ToSearchableAscii(byte[] data)
	{
		StringBuilder stringBuilder = new StringBuilder(data.Length);
		foreach (byte b in data)
		{
			stringBuilder.Append((char)((b >= 32 && b <= 126) ? b : 32));
		}
		return stringBuilder.ToString();
	}

	private static List<string> MatchTokens(string haystack, IEnumerable<string> tokens)
	{
		return tokens.Where((string token) => haystack.Contains(token, StringComparison.OrdinalIgnoreCase)).Distinct<string>(StringComparer.OrdinalIgnoreCase).Take(40)
			.ToList();
	}

	private static List<string> TryReadPeSectionNames(byte[] bytes)
	{
		List<string> list = new List<string>();
		try
		{
			if (bytes.Length < 256 || bytes[0] != 77 || bytes[1] != 90)
			{
				return list;
			}
			int num = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(60, 4));
			if (num < 0 || num + 24 >= bytes.Length)
			{
				return list;
			}
			if (bytes[num] != 80 || bytes[num + 1] != 69 || bytes[num + 2] != 0 || bytes[num + 3] != 0)
			{
				return list;
			}
			ushort val = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(num + 6, 2));
			ushort num2 = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(num + 20, 2));
			int num3 = num + 24 + num2;
			for (int i = 0; i < Math.Min(val, (ushort)32); i++)
			{
				int num4 = num3 + i * 40;
				if (num4 + 8 <= bytes.Length)
				{
					string text = Encoding.ASCII.GetString(bytes, num4, 8).TrimEnd('\0', ' ');
					if (!string.IsNullOrWhiteSpace(text))
					{
						list.Add(text);
					}
					continue;
				}
				break;
			}
		}
		catch
		{
		}
		return list;
	}
}
