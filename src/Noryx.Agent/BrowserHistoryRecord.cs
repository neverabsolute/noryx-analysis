using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class BrowserHistoryRecord
{
	public string Browser { get; set; } = "";

	public string Profile { get; set; } = "";

	public string Url { get; set; } = "";

	public string Host { get; set; } = "";

	public string Title { get; set; } = "";

	public string SearchQuery { get; set; } = "";

	public DateTime? VisitTimeUtc { get; set; }

	public int VisitCount { get; set; }

	public int TypedCount { get; set; }

	public List<string> MatchedTerms { get; set; } = new List<string>();

	public string RiskLevel { get; set; } = "low";

	public int RiskScore { get; set; }

	public string Reason { get; set; } = "";

	public string DatabaseSource { get; set; } = "";
}
