using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Noryx.Agent;

internal static class NetworkIndicatorCollector
{
	private enum TcpTableClass
	{
		TCP_TABLE_BASIC_LISTENER,
		TCP_TABLE_BASIC_CONNECTIONS,
		TCP_TABLE_BASIC_ALL,
		TCP_TABLE_OWNER_PID_LISTENER,
		TCP_TABLE_OWNER_PID_CONNECTIONS,
		TCP_TABLE_OWNER_PID_ALL
	}

	private struct MIB_TCPROW_OWNER_PID
	{
		public uint dwState;

		public uint dwLocalAddr;

		public uint dwLocalPort;

		public uint dwRemoteAddr;

		public uint dwRemotePort;

		public uint dwOwningPid;
	}

	private static readonly string[] AuthDomains = new string[3] { "keyauth.cc", "keyauth.win", "eauth.us.to" };

	public static List<NetworkIndicatorRecord> Collect(List<RustThreatIndicator> threatCatalog)
	{
		List<NetworkIndicatorRecord> list = new List<NetworkIndicatorRecord>();
		CollectDnsCache(threatCatalog, list);
		CollectTcpConnections(list);
		return (from x in list.GroupBy<NetworkIndicatorRecord, string>((NetworkIndicatorRecord x) => $"{x.Source}|{x.ProcessId}|{x.Domain}|{x.RemoteAddress}|{x.RemotePort}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(3000).ToList();
	}

	private static void CollectDnsCache(List<RustThreatIndicator> threatCatalog, List<NetworkIndicatorRecord> result)
	{
		string text = Run("ipconfig.exe", "/displaydns", 12000);
		if (string.IsNullOrWhiteSpace(text))
		{
			return;
		}
		string text2 = "";
		string[] array = text.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
		for (int i = 0; i < array.Length; i++)
		{
			string text3 = array[i].Trim();
			Match match = Regex.Match(text3, "^(Record Name|Nome do Registro)\\s*\\.\\s*:\\s*(.+)$", RegexOptions.IgnoreCase);
			if (match.Success)
			{
				text2 = match.Groups[2].Value.Trim().TrimEnd('.');
				AddDnsIfInteresting(text2, threatCatalog, result);
			}
			else if (text2.Length == 0 && LooksLikeDomain(text3))
			{
				AddDnsIfInteresting(text3.Trim().TrimEnd('.'), threatCatalog, result);
			}
		}
	}

	private static void AddDnsIfInteresting(string domain, List<RustThreatIndicator> threatCatalog, List<NetworkIndicatorRecord> result)
	{
		string text = domain.ToLowerInvariant();
		List<string> list = new List<string>();
		string[] authDomains = AuthDomains;
		foreach (string text2 in authDomains)
		{
			if (text.Equals(text2, StringComparison.OrdinalIgnoreCase) || text.EndsWith("." + text2, StringComparison.OrdinalIgnoreCase))
			{
				list.Add(text2);
			}
		}
		foreach (RustThreatIndicator item in threatCatalog)
		{
			foreach (string domain2 in item.Domains)
			{
				string text3 = (domain2 ?? "").Trim().TrimEnd('.').ToLowerInvariant();
				if (text3.Length >= 4 && (text.Equals(text3, StringComparison.OrdinalIgnoreCase) || text.EndsWith("." + text3, StringComparison.OrdinalIgnoreCase)))
				{
					list.Add(item.Name);
				}
			}
		}
		if (list.Count != 0)
		{
			result.Add(new NetworkIndicatorRecord
			{
				Source = "DNS Cache",
				Domain = domain,
				MatchedIndicators = list.Distinct<string>(StringComparer.OrdinalIgnoreCase).Take(20).ToList(),
				Note = "Entrada encontrada no cache DNS do Windows. Não atribui, por si só, a consulta a um processo específico."
			});
		}
	}

	private static void CollectTcpConnections(List<NetworkIndicatorRecord> result)
	{
		int dwOutBufLen = 0;
		if (GetExtendedTcpTable(IntPtr.Zero, ref dwOutBufLen, sort: true, 2, TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0u) != 122 && dwOutBufLen <= 0)
		{
			return;
		}
		nint num = Marshal.AllocHGlobal(dwOutBufLen);
		try
		{
			if (GetExtendedTcpTable(num, ref dwOutBufLen, sort: true, 2, TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0u) != 0)
			{
				return;
			}
			int num2 = Marshal.ReadInt32(num);
			nint num3 = IntPtr.Add(num, 4);
			int offset = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
			for (int i = 0; i < num2 && i < 5000; i++)
			{
				MIB_TCPROW_OWNER_PID mIB_TCPROW_OWNER_PID = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(num3);
				num3 = IntPtr.Add(num3, offset);
				if (mIB_TCPROW_OWNER_PID.dwState != 5 && mIB_TCPROW_OWNER_PID.dwState != 2)
				{
					continue;
				}
				string text = new IPAddress(mIB_TCPROW_OWNER_PID.dwRemoteAddr).ToString();
				int num4 = Port(mIB_TCPROW_OWNER_PID.dwRemotePort);
				if (num4 <= 0 || text == "0.0.0.0")
				{
					continue;
				}
				string processName = "";
				string text2 = "";
				bool processSigned = false;
				string processSigner = "";
				try
				{
					using Process process = Process.GetProcessById(checked((int)mIB_TCPROW_OWNER_PID.dwOwningPid));
					processName = process.ProcessName;
					try
					{
						text2 = process.MainModule?.FileName ?? "";
						if (!string.IsNullOrWhiteSpace(text2) && File.Exists(text2))
						{
							(processSigned, processSigner) = AuthenticodeVerifier.Verify(text2);
						}
					}
					catch
					{
					}
				}
				catch
				{
				}
				result.Add(new NetworkIndicatorRecord
				{
					Source = "TCP",
					ProcessId = mIB_TCPROW_OWNER_PID.dwOwningPid,
					ProcessName = processName,
					ProcessPath = text2,
					ProcessSigned = processSigned,
					ProcessSigner = processSigner,
					RemoteAddress = text,
					RemotePort = num4,
					State = mIB_TCPROW_OWNER_PID.dwState.ToString()
				});
			}
		}
		finally
		{
			Marshal.FreeHGlobal(num);
		}
	}

	private static int Port(uint value)
	{
		byte[] bytes = BitConverter.GetBytes(value);
		return (bytes[0] << 8) + bytes[1];
	}

	private static bool LooksLikeDomain(string value)
	{
		return Regex.IsMatch(value, "^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
	}

	private static string Run(string fileName, string arguments, int timeoutMs)
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo
			{
				FileName = fileName,
				Arguments = arguments,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			if (process == null)
			{
				return "";
			}
			string text = process.StandardOutput.ReadToEnd();
			process.StandardError.ReadToEnd();
			if (!process.WaitForExit(timeoutMs))
			{
				try
				{
					process.Kill(entireProcessTree: true);
				}
				catch
				{
				}
				return "";
			}
			return (process.ExitCode == 0) ? text : "";
		}
		catch
		{
			return "";
		}
	}

	[DllImport("iphlpapi.dll", SetLastError = true)]
	private static extern uint GetExtendedTcpTable(nint pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved);
}
