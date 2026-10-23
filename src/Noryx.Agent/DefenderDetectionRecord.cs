using System;

namespace Noryx.Agent;

internal sealed class DefenderDetectionRecord
{
	public int EventId { get; set; }

	public DateTime TimeCreatedUtc { get; set; }

	public string ThreatName { get; set; } = "";

	public string Path { get; set; } = "";

	public string Action { get; set; } = "";

	public string DetectionOrigin { get; set; } = "";
}
