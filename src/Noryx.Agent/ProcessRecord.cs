using System;

namespace Noryx.Agent;

internal sealed class ProcessRecord
{
	public int Pid { get; set; }

	public string Name { get; set; } = "";

	public string? Path { get; set; }

	public string? Sha256 { get; set; }

	public bool Signed { get; set; }

	public string? SignerSubject { get; set; }

	public DateTime? StartTimeUtc { get; set; }
}
