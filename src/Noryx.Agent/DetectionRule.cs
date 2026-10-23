namespace Noryx.Agent;

internal sealed class DetectionRule
{
	public long Id { get; set; }

	public string Name { get; set; } = "";

	public string Type { get; set; } = "";

	public string Pattern { get; set; } = "";

	public string Severity { get; set; } = "";

	public string Description { get; set; } = "";
}
