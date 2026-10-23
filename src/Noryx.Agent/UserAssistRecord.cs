using System;

namespace Noryx.Agent;

internal sealed class UserAssistRecord
{
	public string Guid { get; set; } = "";

	public string EncodedName { get; set; } = "";

	public string DecodedName { get; set; } = "";

	public int DataLength { get; set; }

	public int? RunCount { get; set; }

	public DateTime? LastExecutionUtc { get; set; }
}
