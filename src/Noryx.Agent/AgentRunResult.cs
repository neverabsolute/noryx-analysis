namespace Noryx.Agent;

internal sealed class AgentRunResult
{
	public bool CollectionIncomplete { get; set; }

	public int ExitCode { get; set; }

	public string? Error { get; set; }

	public AgentResultSnapshot? Result { get; set; }
}
