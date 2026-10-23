namespace Noryx.Agent;

internal sealed class UsbDeviceRecord
{
	public string Name { get; set; } = "";

	public string DeviceId { get; set; } = "";

	public string PnpDeviceId { get; set; } = "";

	public string Manufacturer { get; set; } = "";

	public string Status { get; set; } = "";

	public bool Present { get; set; }
}
