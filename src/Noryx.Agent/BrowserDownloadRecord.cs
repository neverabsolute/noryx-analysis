using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class BrowserDownloadRecord
{
	public string Browser { get; set; } = "";

	public string Profile { get; set; } = "";

	public string FileName { get; set; } = "";

	public string TargetPath { get; set; } = "";

	public string CurrentPath { get; set; } = "";

	public bool FileExists { get; set; }

	public bool FileMissing { get; set; }

	public DateTime? StartTimeUtc { get; set; }

	public DateTime? EndTimeUtc { get; set; }

	public string State { get; set; } = "";

	public int DangerType { get; set; }

	public long ReceivedBytes { get; set; }

	public long TotalBytes { get; set; }

	public bool Opened { get; set; }

	public string SourceUrl { get; set; } = "";

	public string FinalUrl { get; set; } = "";

	public string ReferrerUrl { get; set; } = "";

	public string SiteUrl { get; set; } = "";

	public string PageUrl { get; set; } = "";

	public string HttpMethod { get; set; } = "";

	public string InitiatedByExtension { get; set; } = "";

	public string MimeType { get; set; } = "";

	public string DatabaseSource { get; set; } = "";

	public List<string> UrlChain { get; set; } = new List<string>();

	public long? FirefoxPlaceId { get; set; }
}
