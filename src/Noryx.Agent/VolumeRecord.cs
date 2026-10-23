namespace Noryx.Agent;

internal sealed class VolumeRecord
{
	public string DeviceId { get; set; } = "";

	public string Label { get; set; } = "";

	public string FileSystem { get; set; } = "";

	public ulong? Capacity { get; set; }

	public bool BootVolume { get; set; }

	public bool SystemVolume { get; set; }

	public bool ExpectedSystemVolume { get; set; }
}
