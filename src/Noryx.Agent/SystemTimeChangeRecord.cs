using System;

namespace Noryx.Agent;

internal sealed class SystemTimeChangeRecord
{
	public DateTime TimeCreatedUtc { get; set; }

	public string PreviousTime { get; set; } = "";

	public string NewTime { get; set; } = "";

	public string ProcessName { get; set; } = "";
}
