using System;

namespace Noryx.Agent;

internal sealed class BamRecord
{
	public string Sid { get; set; } = "";

	public string Path { get; set; } = "";

	public DateTime? LastExecutionUtc { get; set; }

	public bool FileExists { get; set; }
}
