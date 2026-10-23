using System;

namespace Noryx.Agent;

internal sealed class UsbDeviceEventRecord
{
	public string Provider { get; set; } = "";

	public int EventId { get; set; }

	public string EventType { get; set; } = "";

	public DateTime TimeCreatedUtc { get; set; }

	public string DeviceId { get; set; } = "";

	public string Evidence { get; set; } = "";
}
