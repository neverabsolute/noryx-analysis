using System;

namespace Noryx.Agent;

internal sealed class PrefetchRecord
{
	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public DateTime LastWriteUtc { get; set; }

	public long Size { get; set; }
}
