using System;

namespace Noryx.Agent;

internal sealed class SystemIntegrityExpansionRecord
{
	public string Kind { get; set; } = "";

	public string Name { get; set; } = "";

	public string SeverityHint { get; set; } = "info";

	public DateTime? TimestampUtc { get; set; }

	public string Detail { get; set; } = "";
}
