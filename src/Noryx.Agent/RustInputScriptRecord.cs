using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class RustInputScriptRecord
{
	public string Path { get; set; } = "";

	public string Sha256 { get; set; } = "";

	public long Size { get; set; }

	public DateTime LastWriteUtc { get; set; }

	public List<string> Signals { get; set; } = new List<string>();
}
