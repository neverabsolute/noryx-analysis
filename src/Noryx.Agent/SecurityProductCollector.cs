using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace Noryx.Agent;

internal static class SecurityProductCollector
{
	public static List<SecurityProductRecord> Collect()
	{
		List<SecurityProductRecord> list = new List<SecurityProductRecord>();
		CollectNamespace("root\\SecurityCenter2", "AntiVirusProduct", "Antivirus", list);
		CollectNamespace("root\\SecurityCenter2", "FirewallProduct", "Firewall", list);
		CollectNamespace("root\\SecurityCenter2", "AntiSpywareProduct", "AntiSpyware", list);
		return (from x in list.GroupBy<SecurityProductRecord, string>((SecurityProductRecord x) => $"{x.Category}|{x.DisplayName}|{x.InstanceGuid}", StringComparer.OrdinalIgnoreCase)
			select x.First()).Take(250).ToList();
	}

	private static void CollectNamespace(string scopePath, string className, string category, List<SecurityProductRecord> result)
	{
		try
		{
			ManagementScope managementScope = new ManagementScope(scopePath);
			managementScope.Connect();
			using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(managementScope, new ObjectQuery("SELECT * FROM " + className));
			foreach (ManagementObject item in managementObjectSearcher.Get())
			{
				result.Add(new SecurityProductRecord
				{
					Category = category,
					DisplayName = (Convert.ToString(item["displayName"]) ?? ""),
					InstanceGuid = (Convert.ToString(item["instanceGuid"]) ?? ""),
					PathToSignedProductExe = (Convert.ToString(item["pathToSignedProductExe"]) ?? ""),
					PathToSignedReportingExe = (Convert.ToString(item["pathToSignedReportingExe"]) ?? ""),
					ProductState = (Convert.ToString(item["productState"]) ?? ""),
					Timestamp = (Convert.ToString(item["timestamp"]) ?? "")
				});
			}
		}
		catch
		{
		}
	}
}
