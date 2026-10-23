using System;

namespace Noryx.Agent;

internal sealed class FileInventoryRecord
{
	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public long Size { get; set; }

	public DateTime? LastWriteUtc { get; set; }

	public string? AnalysisError { get; set; }

	public bool DeepSelected { get; set; }

	public string SelectionReason { get; set; } = "";
}
