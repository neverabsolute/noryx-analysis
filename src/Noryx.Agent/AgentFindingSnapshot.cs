using System.Text.Json;

namespace Noryx.Agent;

internal sealed class AgentFindingSnapshot
{
	public long Id { get; set; }

	public string Title { get; set; } = "";

	public string Severity { get; set; } = "info";

	public string ArtifactType { get; set; } = "";

	public string ArtifactValue { get; set; } = "";

	public JsonElement Evidence { get; set; }
}
