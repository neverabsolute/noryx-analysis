using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class PowerShellArtifactRecord
{
	public string Source { get; set; } = "";

	public string SourcePath { get; set; } = "";

	public int? EventId { get; set; }

	public DateTime? TimestampUtc { get; set; }

	public string Command { get; set; } = "";

	public List<string> MatchedIndicators { get; set; } = new List<string>();

	public bool LongEncodedPayload { get; set; }
}
