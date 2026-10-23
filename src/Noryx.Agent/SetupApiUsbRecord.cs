using System;

namespace Noryx.Agent;

internal sealed class SetupApiUsbRecord
{
	public int LineNumber { get; set; }

	public string Section { get; set; } = "";

	public DateTime? SectionTimeUtc { get; set; }

	public string Evidence { get; set; } = "";
}
