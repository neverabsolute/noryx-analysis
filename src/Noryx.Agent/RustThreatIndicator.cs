using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class RustThreatIndicator
{
	public string Name { get; set; } = "";

	public List<string> Aliases { get; set; } = new List<string>();

	public List<string> Domains { get; set; } = new List<string>();

	public List<string> DiscordInvites { get; set; } = new List<string>();

	public string Severity { get; set; } = "high";
}
