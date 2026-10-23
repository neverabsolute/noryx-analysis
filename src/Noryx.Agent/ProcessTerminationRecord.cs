using System;

namespace Noryx.Agent;

internal sealed class ProcessTerminationRecord
{
	public DateTime TimeCreatedUtc { get; set; }

	public string ProcessName { get; set; } = "";

	public string ProcessPath { get; set; } = "";

	public string ProcessId { get; set; } = "";

	public string ExitStatus { get; set; } = "";
}
