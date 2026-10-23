using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class HardwareSummaryRecord
{
	public List<PciDeviceEvidence> PciDevices { get; set; } = new List<PciDeviceEvidence>();

	public string PciCollectionStatus { get; set; } = "Não coletado";

	public int TotalRelevantDevices { get; set; }

	public int ArduinoCount { get; set; }

	public int MakcuCount { get; set; }

	public int Ch34xCount { get; set; }

	public int Cp210xCount { get; set; }

	public int FtdiCount { get; set; }

	public int OtherSerialCount { get; set; }
}
