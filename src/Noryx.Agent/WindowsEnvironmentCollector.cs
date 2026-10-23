using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace Noryx.Agent;

internal static class WindowsEnvironmentCollector
{
	public static string ComputeMachineFingerprint()
	{
		List<string> parts = new List<string>();
		AddWmiValue("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");
		AddWmiValue("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber");
		AddWmiValue("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber");
		AddWmiValue("SELECT ProcessorId FROM Win32_Processor", "ProcessorId");
		if (parts.Count == 0)
		{
			return "";
		}
		string s = string.Join("|", parts.Select((string x) => x.Trim().ToUpperInvariant()).OrderBy<string, string>((string x) => x, StringComparer.Ordinal));
		return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
		void AddWmiValue(string query, string property)
		{
			try
			{
				using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(query);
				using ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectSearcher.Get().GetEnumerator();
				if (managementObjectEnumerator.MoveNext())
				{
					string text = Convert.ToString(((ManagementObject)managementObjectEnumerator.Current)[property]) ?? "";
					text = text.Trim();
					if (!string.IsNullOrWhiteSpace(text) && !text.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) && !text.Equals("Default string", StringComparison.OrdinalIgnoreCase) && !text.Equals("None", StringComparison.OrdinalIgnoreCase))
					{
						parts.Add(property + "=" + text);
					}
				}
			}
			catch
			{
			}
		}
	}

	public static List<RecycleBinRecord> CollectRecycleBin()
	{
		List<RecycleBinRecord> list = new List<RecycleBinRecord>();
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			try
			{
				if (!driveInfo.IsReady)
				{
					continue;
				}
				string path = Path.Combine(driveInfo.RootDirectory.FullName, "$Recycle.Bin");
				if (!Directory.Exists(path))
				{
					continue;
				}
				foreach (string item in SafeDirectories(path).Take(200))
				{
					foreach (string item2 in SafeFiles(item, "$I*").Take(3000))
					{
						if (list.Count >= 5000)
						{
							return list;
						}
						RecycleBinRecord recycleBinRecord = TryParseRecycleInfo(item2);
						if (recycleBinRecord != null)
						{
							list.Add(recycleBinRecord);
						}
					}
				}
			}
			catch
			{
			}
		}
		return list.OrderByDescending((RecycleBinRecord x) => x.DeletedAtUtc ?? DateTime.MinValue).Take(5000).ToList();
	}

	public static VmEnvironmentRecord CollectVmEnvironment()
	{
		VmEnvironmentRecord vmEnvironmentRecord = new VmEnvironmentRecord();
		try
		{
			using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Manufacturer,Model FROM Win32_ComputerSystem");
			using ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectSearcher.Get().GetEnumerator();
			if (managementObjectEnumerator.MoveNext())
			{
				ManagementObject managementObject = (ManagementObject)managementObjectEnumerator.Current;
				vmEnvironmentRecord.Manufacturer = Convert.ToString(managementObject["Manufacturer"]) ?? "";
				vmEnvironmentRecord.Model = Convert.ToString(managementObject["Model"]) ?? "";
			}
		}
		catch
		{
		}
		try
		{
			using ManagementObjectSearcher managementObjectSearcher2 = new ManagementObjectSearcher("SELECT Manufacturer,SMBIOSBIOSVersion,SerialNumber FROM Win32_BIOS");
			using ManagementObjectCollection.ManagementObjectEnumerator managementObjectEnumerator = managementObjectSearcher2.Get().GetEnumerator();
			if (managementObjectEnumerator.MoveNext())
			{
				ManagementObject managementObject2 = (ManagementObject)managementObjectEnumerator.Current;
				vmEnvironmentRecord.BiosManufacturer = Convert.ToString(managementObject2["Manufacturer"]) ?? "";
				vmEnvironmentRecord.BiosVersion = Convert.ToString(managementObject2["SMBIOSBIOSVersion"]) ?? "";
			}
		}
		catch
		{
		}
		string text = string.Join(" ", vmEnvironmentRecord.Manufacturer, vmEnvironmentRecord.Model, vmEnvironmentRecord.BiosManufacturer, vmEnvironmentRecord.BiosVersion).ToLowerInvariant();
		string text2 = new string[10] { "vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "parallels", "hyper-v", "virtual machine", "microsoft corporation virtual" }.FirstOrDefault(text.Contains);
		vmEnvironmentRecord.IsVirtualMachine = text2 != null;
		VmEnvironmentRecord vmEnvironmentRecord2 = vmEnvironmentRecord;
		string detectedPlatform;
		switch (text2)
		{
		case "vmware":
			detectedPlatform = "VMware";
			break;
		case "vbox":
		case "virtualbox":
			detectedPlatform = "VirtualBox";
			break;
		case "qemu":
		case "kvm":
			detectedPlatform = "QEMU/KVM";
			break;
		case "xen":
			detectedPlatform = "Xen";
			break;
		case "parallels":
			detectedPlatform = "Parallels";
			break;
		case "hyper-v":
		case "microsoft corporation virtual":
			detectedPlatform = "Hyper-V";
			break;
		case "virtual machine":
			detectedPlatform = "Virtual Machine";
			break;
		default:
			detectedPlatform = "";
			break;
		}
		vmEnvironmentRecord2.DetectedPlatform = detectedPlatform;
		return vmEnvironmentRecord;
	}

	private static RecycleBinRecord? TryParseRecycleInfo(string infoPath)
	{
		try
		{
			byte[] array = File.ReadAllBytes(infoPath);
			if (array.Length < 24)
			{
				return null;
			}
			long num = BitConverter.ToInt64(array, 0);
			long originalSize = BitConverter.ToInt64(array, 8);
			long num2 = BitConverter.ToInt64(array, 16);
			string text = "";
			if (num >= 2 && array.Length >= 28)
			{
				int num3 = BitConverter.ToInt32(array, 24);
				if (num3 > 0 && num3 < 32768 && 28 + num3 * 2 <= array.Length)
				{
					text = Encoding.Unicode.GetString(array, 28, num3 * 2).TrimEnd('\0');
				}
			}
			if (string.IsNullOrWhiteSpace(text) && array.Length > 24)
			{
				text = Encoding.Unicode.GetString(array, 24, array.Length - 24).TrimEnd('\0');
			}
			DateTime? deletedAtUtc = null;
			try
			{
				if (num2 > 0)
				{
					deletedAtUtc = DateTime.FromFileTimeUtc(num2);
				}
			}
			catch
			{
			}
			string fileName = Path.GetFileName(infoPath);
			object obj2;
			if (fileName.Length < 2)
			{
				obj2 = "";
			}
			else
			{
				string text2 = fileName;
				obj2 = "$R" + text2.Substring(2, text2.Length - 2);
			}
			string text3 = (string)obj2;
			string text4 = (string.IsNullOrWhiteSpace(text3) ? "" : Path.Combine(Path.GetDirectoryName(infoPath) ?? "", text3));
			return new RecycleBinRecord
			{
				OriginalPath = text,
				FileName = SafeFileName(text),
				DeletedAtUtc = deletedAtUtc,
				OriginalSize = originalSize,
				InfoPath = infoPath,
				RecycledDataPath = text4,
				RecycledDataPresent = (!string.IsNullOrWhiteSpace(text4) && File.Exists(text4)),
				Version = num
			};
		}
		catch
		{
			return null;
		}
	}

	private static IEnumerable<string> SafeDirectories(string path)
	{
		try
		{
			return Directory.EnumerateDirectories(path).ToArray();
		}
		catch
		{
			return Array.Empty<string>();
		}
	}

	private static IEnumerable<string> SafeFiles(string path, string pattern)
	{
		try
		{
			return Directory.EnumerateFiles(path, pattern, SearchOption.TopDirectoryOnly).ToArray();
		}
		catch
		{
			return Array.Empty<string>();
		}
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
}
