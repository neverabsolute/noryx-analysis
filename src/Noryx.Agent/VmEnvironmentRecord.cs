namespace Noryx.Agent;

internal sealed class VmEnvironmentRecord
{
	public bool IsVirtualMachine { get; set; }

	public string DetectedPlatform { get; set; } = "";

	public string Manufacturer { get; set; } = "";

	public string Model { get; set; } = "";

	public string BiosManufacturer { get; set; } = "";

	public string BiosVersion { get; set; } = "";
}
