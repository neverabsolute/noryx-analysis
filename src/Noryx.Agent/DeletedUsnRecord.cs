using System;

namespace Noryx.Agent;

internal sealed class DeletedUsnRecord
{
	public string Volume { get; set; } = "";

	public string DriveType { get; set; } = "";

	public string FileName { get; set; } = "";

	public string Extension { get; set; } = "";

	public DateTime TimestampUtc { get; set; }

	public string Reason { get; set; } = "";

	public long Usn { get; set; }

	public ulong FileReferenceNumber { get; set; }

	public ulong ParentFileReferenceNumber { get; set; }

	public bool RandomLikeName { get; set; }

	public bool DeceptiveDoubleExtension { get; set; }
}
