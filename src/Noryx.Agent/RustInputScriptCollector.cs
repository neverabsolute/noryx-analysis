using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Noryx.Agent;

internal static class RustInputScriptCollector
{
	private const int MaximumScriptBytes = 524288;

	public static List<RustInputScriptRecord> Collect(IEnumerable<string> paths, List<string> errors)
	{
		List<RustInputScriptRecord> list = new List<RustInputScriptRecord>();
		foreach (string item in paths.Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			try
			{
				FileInfo fileInfo = new FileInfo(item);
				if (!fileInfo.Exists || fileInfo.Length > 524288)
				{
					errors.Add("Script pendente (ausente ou acima de 512 KiB): " + item);
					continue;
				}
				using FileStream fileStream = new FileStream(item, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
				byte[] array = new byte[524289];
				int i;
				int num;
				for (i = 0; i < array.Length; i += num)
				{
					if ((num = fileStream.Read(array, i, array.Length - i)) <= 0)
					{
						break;
					}
				}
				if (i > 524288)
				{
					errors.Add("Script pendente (cresceu durante a leitura): " + item);
					continue;
				}
				List<string> list2 = Inspect(Encoding.UTF8.GetString(array, 0, i));
				if (list2.Count != 0)
				{
					list.Add(new RustInputScriptRecord
					{
						Path = item,
						Sha256 = Convert.ToHexString(SHA256.HashData(array.AsSpan(0, i))).ToLowerInvariant(),
						Size = i,
						LastWriteUtc = fileInfo.LastWriteTimeUtc,
						Signals = list2
					});
				}
			}
			catch (Exception ex)
			{
				errors.Add("Script pendente: " + item + " (" + ex.GetType().Name + ")");
			}
		}
		return list;
	}

	internal static List<string> Inspect(string text)
	{
		text = Regex.Replace(text, "--\\[\\[[\\s\\S]*?\\]\\]", "");
		text = Regex.Replace(text, "(?m)^\\s*(--|;|//).*$", "");
		List<string> list = new List<string>();
		if (Regex.IsMatch(text, "\\b(MoveMouseRelative|mouse_event|SendInput|DllCall\\s*\\(\\s*[\"']mouse_event)\\b", RegexOptions.IgnoreCase))
		{
			list.Add("relative_mouse_input");
		}
		if (Regex.IsMatch(text, "\\b(IsMouseButtonPressed|GetKeyState|GetAsyncKeyState)\\s*\\(", RegexOptions.IgnoreCase))
		{
			list.Add("button_state");
		}
		if (Regex.IsMatch(text, "\\b(repeat|while|loop)\\b", RegexOptions.IgnoreCase) && Regex.IsMatch(text, "\\b(Sleep|SetTimer)\\b", RegexOptions.IgnoreCase))
		{
			list.Add("timed_loop");
		}
		if (Regex.IsMatch(text, "\\b(ak47|lr300|mp5a4|rustclient|thompson)\\b", RegexOptions.IgnoreCase))
		{
			list.Add("rust_weapon_context");
		}
		if (Regex.IsMatch(text, "\\b(anti[_\\s-]?recoil|no[_\\s-]?recoil|recoil[_\\s-]?pattern)\\b", RegexOptions.IgnoreCase))
		{
			list.Add("recoil_label");
		}
		if (Regex.IsMatch(text, "\\brevolex\\b", RegexOptions.IgnoreCase))
		{
			list.Add("catalog_label_revolex");
		}
		if (!list.Contains("relative_mouse_input") || !list.Contains("timed_loop") || (!list.Contains("rust_weapon_context") && !list.Contains("recoil_label")))
		{
			return new List<string>();
		}
		return list;
	}
}
