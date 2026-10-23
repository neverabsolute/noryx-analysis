using System;

namespace Noryx.Agent;

internal sealed class CrashArtifactRecord
{
	public string Source { get; set; } = "";

	public string ArtifactPath { get; set; } = "";

	public string AppName { get; set; } = "";

	public string AppPath { get; set; } = "";

	public string FaultingModulePath { get; set; } = "";

	public string EventType { get; set; } = "";

	public DateTime? TimestampUtc { get; set; }

	public long Size { get; set; }
}
