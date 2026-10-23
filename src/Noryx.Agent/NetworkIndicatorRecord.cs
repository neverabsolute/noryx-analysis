using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class NetworkIndicatorRecord
{
	public string Source { get; set; } = "";

	public uint ProcessId { get; set; }

	public string ProcessName { get; set; } = "";

	public string ProcessPath { get; set; } = "";

	public bool ProcessSigned { get; set; }

	public string ProcessSigner { get; set; } = "";

	public string RemoteAddress { get; set; } = "";

	public int RemotePort { get; set; }

	public string State { get; set; } = "";

	public string Domain { get; set; } = "";

	public List<string> MatchedIndicators { get; set; } = new List<string>();

	public string Note { get; set; } = "";
}
