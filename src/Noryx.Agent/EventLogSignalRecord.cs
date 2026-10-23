using System;

namespace Noryx.Agent;

internal sealed class EventLogSignalRecord
{
	public string Channel { get; set; } = "";

	public string Signal { get; set; } = "";

	public int WindowHours { get; set; }

	public string Evidence { get; set; } = "";

	public string Provider { get; set; } = "";

	public int? EventId { get; set; }

	public long? RecordId { get; set; }

	public DateTime? TimestampUtc { get; set; }
}
