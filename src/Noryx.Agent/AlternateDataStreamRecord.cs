namespace Noryx.Agent;

internal sealed class AlternateDataStreamRecord
{
	public string Path { get; set; } = "";

	public string StreamName { get; set; } = "";

	public long StreamSize { get; set; }

	public bool ExecutableLike { get; set; }

	public bool Suspicious { get; set; }
}
