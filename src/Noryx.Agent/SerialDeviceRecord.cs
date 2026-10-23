namespace Noryx.Agent;

internal sealed class SerialDeviceRecord
{
	public string Name { get; set; } = "";

	public string DeviceId { get; set; } = "";

	public string PnpDeviceId { get; set; } = "";

	public string Manufacturer { get; set; } = "";

	public string Status { get; set; } = "";

	public string PnpClass { get; set; } = "";

	public string Service { get; set; } = "";
}
