using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class RecoveredBrowserArtifact
{
	public string Browser { get; set; } = "";

	public string Profile { get; set; } = "";

	public string SourceArtifact { get; set; } = "";

	public string SourcePath { get; set; } = "";

	public string RecoveredUrl { get; set; } = "";

	public string RecoveredFileName { get; set; } = "";

	public List<string> CatalogMatches { get; set; } = new List<string>();

	public List<string> MatchedTerms { get; set; } = new List<string>();

	public bool RandomLikeName { get; set; }

	public bool DeceptiveDoubleExtension { get; set; }

	public bool SocialOrigin { get; set; }

	public int RiskScore { get; set; }

	public string RecoveryKind { get; set; } = "";

	public string Note { get; set; } = "";
}
