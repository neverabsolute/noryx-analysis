using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Noryx.Agent;

internal static class WindowProtectionCollector
{
	private delegate bool EnumWindowsProc(nint hwnd, nint lParam);

	private const uint WDA_NONE = 0u;

	private const uint WDA_MONITOR = 1u;

	private const uint WDA_EXCLUDEFROMCAPTURE = 17u;

	public static List<WindowProtectionRecord> Collect()
	{
		List<WindowProtectionRecord> result = new List<WindowProtectionRecord>();
		EnumWindows(delegate(nint hwnd, nint _)
		{
			try
			{
				if (!IsWindowVisible(hwnd))
				{
					return true;
				}
				uint pdwAffinity = 0u;
				if (!GetWindowDisplayAffinity(hwnd, out pdwAffinity) || pdwAffinity == 0)
				{
					return true;
				}
				GetWindowThreadProcessId(hwnd, out var lpdwProcessId);
				string processName = "";
				string text = "";
				bool signed = false;
				string signerSubject = "";
				try
				{
					using Process process = Process.GetProcessById(checked((int)lpdwProcessId));
					processName = process.ProcessName;
					try
					{
						text = process.MainModule?.FileName ?? "";
						if (!string.IsNullOrWhiteSpace(text) && File.Exists(text))
						{
							(signed, signerSubject) = AuthenticodeVerifier.Verify(text);
						}
					}
					catch
					{
					}
				}
				catch
				{
				}
				StringBuilder stringBuilder = new StringBuilder(512);
				_ = GetClassNameW(hwnd, stringBuilder, stringBuilder.Capacity);
				result.Add(new WindowProtectionRecord
				{
					ProcessId = lpdwProcessId,
					ProcessName = processName,
					ProcessPath = text,
					Signed = signed,
					SignerSubject = signerSubject,
					WindowClass = stringBuilder.ToString(),
					DisplayAffinity = pdwAffinity,
					ExcludedFromCapture = (pdwAffinity == 17),
					MonitorOnly = (pdwAffinity == 1)
				});
			}
			catch
			{
			}
			return true;
		}, IntPtr.Zero);
		return (from x in result
			group x by $"{x.ProcessId}|{x.WindowClass}|{x.DisplayAffinity}" into x
			select x.First()).Take(1000).ToList();
	}

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool IsWindowVisible(nint hWnd);

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetWindowDisplayAffinity(nint hWnd, out uint pdwAffinity);

	[DllImport("user32.dll")]
	private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

	[DllImport("user32.dll", CharSet = CharSet.Unicode)]
	private static extern int GetClassNameW(nint hWnd, StringBuilder lpClassName, int nMaxCount);
}
