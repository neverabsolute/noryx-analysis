using System;

namespace Noryx.Agent;

internal sealed class ZoneIdentifierRecord
{
	public string FileName { get; set; } = "";

	public string Path { get; set; } = "";

	public int ZoneId { get; set; }

	public string HostUrl { get; set; } = "";

	public string ReferrerUrl { get; set; } = "";

	public DateTime? LastWriteUtc { get; set; }

	public bool FileExists { get; set; }

	public string Sha256 { get; set; } = "";
}
