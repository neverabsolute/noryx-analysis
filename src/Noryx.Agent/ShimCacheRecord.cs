using System;

namespace Noryx.Agent;

internal sealed class ShimCacheRecord
{
	public string Path { get; set; } = "";

	public string Executed { get; set; } = "";

	public DateTime? LastModifiedUtc { get; set; }

	public int ControlSet { get; set; }

	public string InsertFlags { get; set; } = "";

	public bool FilePresent { get; set; }

	public string DriveType { get; set; } = "";
}
