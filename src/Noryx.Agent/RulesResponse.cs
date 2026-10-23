using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class RulesResponse
{
	public string GameId { get; set; } = "rust";

	public string Profile { get; set; } = "rust-v1";

	public long AnalysisId { get; set; }

	public List<DetectionRule> Rules { get; set; } = new List<DetectionRule>();

	public List<RustThreatIndicator> ThreatCatalog { get; set; } = new List<RustThreatIndicator>();

	public List<string> KnownCheatExecutableNames { get; set; } = new List<string>();
}
