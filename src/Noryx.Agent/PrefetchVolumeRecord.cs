using System;

namespace Noryx.Agent;

internal sealed class PrefetchVolumeRecord
{
	public string DeviceName { get; set; } = "";

	public string SerialNumber { get; set; } = "";

	public DateTime CreationTimeUtc { get; set; }

	public string? CurrentDriveLetter { get; set; }

	public string? CurrentDriveType { get; set; }

	public bool CurrentlyMounted { get; set; }
}
