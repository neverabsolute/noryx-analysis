using System;

namespace Noryx.Agent;

internal sealed class ProcessCreationRecord
{
	public DateTime TimeCreatedUtc { get; set; }

	public string ProcessName { get; set; } = "";

	public string ProcessPath { get; set; } = "";

	public string ParentProcessName { get; set; } = "";

	public string ParentProcessPath { get; set; } = "";

	public bool ProcessPresent { get; set; }

	public string DriveType { get; set; } = "";
}
