using System;

namespace Noryx.Agent;

internal sealed class UsbHistoryRecord
{
	public string DeviceClass { get; set; } = "";

	public string InstanceId { get; set; } = "";

	public string FriendlyName { get; set; } = "";

	public string DeviceDescription { get; set; } = "";

	public string Manufacturer { get; set; } = "";

	public bool Present { get; set; }

	public DateTime? LastConnectedUtc { get; set; }

	public DateTime? LastDisconnectedUtc { get; set; }

	public string TimelineSource { get; set; } = "";
}
