namespace Noryx.Agent;

internal sealed class PowerShellRuleHit
{
	public long RuleId { get; set; }

	public string RuleName { get; set; } = "";

	public string Pattern { get; set; } = "";

	public string SourceFile { get; set; } = "";

	public int LineNumber { get; set; }

	public string MatchedLine { get; set; } = "";
}
