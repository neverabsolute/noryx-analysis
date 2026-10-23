using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class UsnActivityRecord
{
	public string Volume { get; set; } = "";

	public string DriveType { get; set; } = "";

	public string FileName { get; set; } = "";

	public string Extension { get; set; } = "";

	public DateTime TimestampUtc { get; set; }

	public long Usn { get; set; }

	public ulong FileReferenceNumber { get; set; }

	public ulong ParentFileReferenceNumber { get; set; }

	public uint ReasonMask { get; set; }

	public List<string> Reasons { get; set; } = new List<string>();

	public bool Deleted { get; set; }

	public bool Created { get; set; }

	public bool Renamed { get; set; }

	public bool Modified { get; set; }

	public bool UnderPrefetchDirectory { get; set; }

	public bool BrowserDatabase { get; set; }

	public bool WindowsForensicArtifact { get; set; }
}
