namespace Noryx.Agent;

internal sealed class BrowserRawArtifact
{
	public string Browser { get; set; } = "";

	public string Profile { get; set; } = "";

	public string Path { get; set; } = "";

	public bool IsSidecar { get; set; }
}
