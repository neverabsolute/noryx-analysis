namespace Noryx.Agent;

internal sealed class DosDeviceRecord
{
	public string DriveLetter { get; set; } = "";

	public string DevicePath { get; set; } = "";

	public string VolumeGuidPath { get; set; } = "";

	public string VolumeSerialNumber { get; set; } = "";

	public string DriveType { get; set; } = "";
}
