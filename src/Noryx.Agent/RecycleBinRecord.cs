using System;

namespace Noryx.Agent;

internal sealed class RecycleBinRecord
{
	public string FileName { get; set; } = "";

	public string OriginalPath { get; set; } = "";

	public DateTime? DeletedAtUtc { get; set; }

	public long OriginalSize { get; set; }

	public string InfoPath { get; set; } = "";

	public string RecycledDataPath { get; set; } = "";

	public bool RecycledDataPresent { get; set; }

	public long Version { get; set; }
}
