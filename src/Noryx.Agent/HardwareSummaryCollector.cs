using System;
using System.Collections.Generic;
using System.Management;

namespace Noryx.Agent;

internal static class HardwareSummaryCollector
{
	public static HardwareSummaryRecord Build(List<SerialDeviceRecord> devices)
	{
		HardwareSummaryRecord hardwareSummaryRecord = new HardwareSummaryRecord
		{
			TotalRelevantDevices = devices.Count
		};
		foreach (SerialDeviceRecord device in devices)
		{
			string text = string.Join(" ", device.Name, device.DeviceId, device.PnpDeviceId, device.Manufacturer, device.PnpClass, device.Service).ToLowerInvariant();
			bool num = text.Contains("arduino") || text.Contains("vid_2341") || text.Contains("vid_2a03");
			bool flag = text.Contains("makcu") || text.Contains("moku") || text.Contains("vid_1a86&pid_55d3") || text.Contains("vid_303a&pid_0009") || text.Contains("vid_303a&pid_1001");
			bool flag2 = text.Contains("ch340") || text.Contains("ch341") || text.Contains("ch343") || text.Contains("vid_1a86");
			bool flag3 = text.Contains("cp210") || text.Contains("vid_10c4");
			bool flag4 = text.Contains("ftdi") || text.Contains("vid_0403");
			if (num)
			{
				hardwareSummaryRecord.ArduinoCount++;
			}
			if (flag)
			{
				hardwareSummaryRecord.MakcuCount++;
			}
			if (flag2)
			{
				hardwareSummaryRecord.Ch34xCount++;
			}
			if (flag3)
			{
				hardwareSummaryRecord.Cp210xCount++;
			}
			if (flag4)
			{
				hardwareSummaryRecord.FtdiCount++;
			}
			if (!num && !flag && !flag2 && !flag3 && !flag4)
			{
				hardwareSummaryRecord.OtherSerialCount++;
			}
		}
		try
		{
			using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(new ManagementScope("\\\\.\\root\\cimv2"), new ObjectQuery("SELECT Name, PNPDeviceID, Manufacturer, Service, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'PCI%'"), new EnumerationOptions
			{
				Timeout = TimeSpan.FromSeconds(20.0),
				ReturnImmediately = false
			});
			using ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
			foreach (ManagementObject item in managementObjectCollection)
			{
				using (item)
				{
					hardwareSummaryRecord.PciDevices.Add(new PciDeviceEvidence
					{
						Name = (Convert.ToString(item["Name"]) ?? ""),
						DeviceId = (Convert.ToString(item["PNPDeviceID"]) ?? ""),
						Manufacturer = (Convert.ToString(item["Manufacturer"]) ?? ""),
						Service = (Convert.ToString(item["Service"]) ?? ""),
						StatusCode = (Convert.ToString(item["ConfigManagerErrorCode"]) ?? "")
					});
				}
			}
			hardwareSummaryRecord.PciCollectionStatus = "Coletado. Inventário para revisão; não confirma DMA ou cheat.";
		}
		catch (Exception ex)
		{
			hardwareSummaryRecord.PciCollectionStatus = "Coleta PCI incompleta: " + ex.Message;
		}
		return hardwareSummaryRecord;
	}
}
