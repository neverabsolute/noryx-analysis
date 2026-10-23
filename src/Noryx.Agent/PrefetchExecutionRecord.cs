using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class PrefetchExecutionRecord
{
	public string ExecutableName { get; set; } = "";

	public string PrefetchFile { get; set; } = "";

	public string PrefetchHash { get; set; } = "";

	public string Version { get; set; } = "";

	public int RunCount { get; set; }

	public List<DateTime> LastRunTimesUtc { get; set; } = new List<DateTime>();

	public DateTime? LastRunUtc { get; set; }

	public string? NativeExecutablePath { get; set; }

	public string? ResolvedExecutablePath { get; set; }

	public bool? ExecutablePresent { get; set; }

	public bool VolumeNotMounted { get; set; }

	public bool CurrentRemovable { get; set; }

	public bool NonSystemVolume { get; set; }

	public bool LikelyDetachedOrRemovable { get; set; }

	public List<PrefetchVolumeRecord> Volumes { get; set; } = new List<PrefetchVolumeRecord>();
}
