using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Noryx.Agent;

internal static class AuthenticodeVerifier
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WINTRUST_FILE_INFO
	{
		public uint cbStruct;

		public nint pcwszFilePath;

		public nint hFile;

		public nint pgKnownSubject;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WINTRUST_DATA
	{
		public uint cbStruct;

		public nint pPolicyCallbackData;

		public nint pSIPClientData;

		public uint dwUIChoice;

		public uint fdwRevocationChecks;

		public uint dwUnionChoice;

		public nint pFile;

		public uint dwStateAction;

		public nint hWVTStateData;

		public nint pwszURLReference;

		public uint dwProvFlags;

		public uint dwUIContext;

		public nint pSignatureSettings;
	}

	private static readonly Guid WinTrustActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

	private const uint WTD_UI_NONE = 2u;

	private const uint WTD_REVOKE_NONE = 0u;

	private const uint WTD_CHOICE_FILE = 1u;

	private const uint WTD_STATEACTION_IGNORE = 0u;

	private static readonly ConcurrentDictionary<string, Lazy<(bool Trusted, string Subject)>> Cache = new ConcurrentDictionary<string, Lazy<(bool, string)>>(StringComparer.OrdinalIgnoreCase);

	public static void ResetCache()
	{
		Cache.Clear();
	}

	public static (bool Trusted, string Subject) Verify(string path)
	{
		try
		{
			FileInfo fileInfo = new FileInfo(path);
			if (!fileInfo.Exists)
			{
				return (Trusted: false, Subject: "");
			}
			string text = fileInfo.FullName + "|" + fileInfo.Length + "|" + fileInfo.LastWriteTimeUtc.Ticks + "|" + fileInfo.CreationTimeUtc.Ticks;
			(bool, string) value = Cache.GetOrAdd(text, (string _) => new Lazy<(bool, string)>(() => VerifyCore(path))).Value;
			fileInfo.Refresh();
			if (!fileInfo.Exists || text != fileInfo.FullName + "|" + fileInfo.Length + "|" + fileInfo.LastWriteTimeUtc.Ticks + "|" + fileInfo.CreationTimeUtc.Ticks)
			{
				Cache.TryRemove(text, out Lazy<(bool, string)> _);
				return (Trusted: false, Subject: "");
			}
			return value;
		}
		catch
		{
			return (Trusted: false, Subject: "");
		}
	}

	private static (bool Trusted, string Subject) VerifyCore(string path)
	{
		if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
		{
			return (Trusted: false, Subject: "");
		}
		nint num = IntPtr.Zero;
		nint num2 = IntPtr.Zero;
		nint num3 = IntPtr.Zero;
		try
		{
			num = Marshal.StringToCoTaskMemUni(path);
			WINTRUST_FILE_INFO structure = new WINTRUST_FILE_INFO
			{
				cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
				pcwszFilePath = num,
				hFile = IntPtr.Zero,
				pgKnownSubject = IntPtr.Zero
			};
			num2 = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
			Marshal.StructureToPtr(structure, num2, fDeleteOld: false);
			WINTRUST_DATA structure2 = new WINTRUST_DATA
			{
				cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
				pPolicyCallbackData = IntPtr.Zero,
				pSIPClientData = IntPtr.Zero,
				dwUIChoice = 2u,
				fdwRevocationChecks = 0u,
				dwUnionChoice = 1u,
				pFile = num2,
				dwStateAction = 0u,
				hWVTStateData = IntPtr.Zero,
				pwszURLReference = IntPtr.Zero,
				dwProvFlags = 4096u,
				dwUIContext = 0u,
				pSignatureSettings = IntPtr.Zero
			};
			num3 = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_DATA>());
			Marshal.StructureToPtr(structure2, num3, fDeleteOld: false);
			Guid pgActionID = WinTrustActionGenericVerifyV2;
			int num4 = WinVerifyTrust(IntPtr.Zero, ref pgActionID, num3);
			string item = "";
			try
			{
				using X509Certificate2 x509Certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
				item = x509Certificate.Subject ?? "";
			}
			catch
			{
			}
			return (Trusted: num4 == 0, Subject: item);
		}
		catch
		{
			return (Trusted: false, Subject: "");
		}
		finally
		{
			if (num3 != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(num3);
			}
			if (num2 != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(num2);
			}
			if (num != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(num);
			}
		}
	}

	[DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
	private static extern int WinVerifyTrust(nint hwnd, ref Guid pgActionID, nint pWVTData);
}
