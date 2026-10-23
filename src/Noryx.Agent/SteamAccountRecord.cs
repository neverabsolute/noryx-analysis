using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class SteamAccountRecord
{
	public string SteamId64 { get; set; } = "";

	public string AccountId { get; set; } = "";

	public string AccountName { get; set; } = "";

	public string PersonaName { get; set; } = "";

	public string ProfileUrl { get; set; } = "";

	public bool SavedLogin { get; set; }

	public bool UserDataPresent { get; set; }

	public bool MostRecent { get; set; }

	public bool RememberPassword { get; set; }

	public DateTime? LastSeenUtc { get; set; }

	public List<string> Sources { get; set; } = new List<string>();
}
