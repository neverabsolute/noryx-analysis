using System;

namespace Noryx.Agent;

internal sealed class PrefetchIntegrityRecord
{
	public string Kind { get; set; } = "";

	public string Name { get; set; } = "";

	public string Detail { get; set; } = "";

	public string? Sha256 { get; set; }

	public DateTime? LastWriteUtc { get; set; }
}
