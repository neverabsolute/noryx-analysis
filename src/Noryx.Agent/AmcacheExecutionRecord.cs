using System;

namespace Noryx.Agent;

internal sealed class AmcacheExecutionRecord
{
	public string Name { get; set; } = "";

	public string FullPath { get; set; } = "";

	public string Sha1 { get; set; } = "";

	public string ApplicationName { get; set; } = "";

	public string ProductName { get; set; } = "";

	public string Publisher { get; set; } = "";

	public string Description { get; set; } = "";

	public string OriginalFileName { get; set; } = "";

	public bool IsPeFile { get; set; }

	public bool IsOsComponent { get; set; }

	public long FileSize { get; set; }

	public ulong Usn { get; set; }

	public DateTime FileKeyLastWriteUtc { get; set; }

	public DateTime? LinkDateUtc { get; set; }

	public bool FilePresent { get; set; }

	public string DriveType { get; set; } = "";
}
