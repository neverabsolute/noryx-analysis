using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class AgentResultSnapshot
{
	public long AnalysisId { get; set; }

	public string Label { get; set; } = "";

	public string Status { get; set; } = "";

	public string ProcessingStage { get; set; } = "";

	public string ProcessingMessage { get; set; } = "";

	public string VerificationState { get; set; } = "";

	public string VerificationMessage { get; set; } = "";

	public string? ExternalDecision { get; set; }

	public string? ExternalDecisionResult { get; set; }

	public bool DetailsReleased { get; set; }

	public DateTimeOffset? StartedAt { get; set; }

	public DateTimeOffset? FinishedAt { get; set; }

	public AgentResultSummary Summary { get; set; } = new AgentResultSummary();

	public List<AgentFindingSnapshot> Findings { get; set; } = new List<AgentFindingSnapshot>();
}
