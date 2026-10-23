using System;

namespace Noryx.Agent;

internal sealed class RecentShortcutRecord
{
	public string ShortcutName { get; set; } = "";

	public DateTime ShortcutLastWriteUtc { get; set; }

	public string TargetPath { get; set; } = "";

	public string WorkingDirectory { get; set; } = "";

	public bool TargetExists { get; set; }
}
