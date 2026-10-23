using System;

namespace Noryx.Agent;

internal sealed class ExtensionMismatchRecord
{
	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public string Extension { get; set; } = "";

	public long Size { get; set; }

	public DateTime LastWriteUtc { get; set; }

	public string Reason { get; set; } = "";
}
