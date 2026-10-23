using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class FileRecord
{
	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public string Extension { get; set; } = "";

	public long Size { get; set; }

	public DateTime? CreatedUtc { get; set; }

	public DateTime? LastWriteUtc { get; set; }

	public string? Sha256 { get; set; }

	public bool Signed { get; set; }

	public string? SignerSubject { get; set; }

	public DateTime? PrefetchEvidenceUtc { get; set; }

	public DateTime? CompilationTimeUtc { get; set; }

	public bool RandomLikeName { get; set; }

	public List<string> ArchiveEntries { get; set; } = new List<string>();

	public string DriveType { get; set; } = "";
}
