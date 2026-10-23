using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class PeInspectionRecord
{
	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public string Sha256 { get; set; } = "";

	public bool Signed { get; set; }

	public string SignerSubject { get; set; } = "";

	public long Size { get; set; }

	public double Entropy { get; set; }

	public bool HighEntropy { get; set; }

	public bool PackedLike { get; set; }

	public List<string> PackerIndicators { get; set; } = new List<string>();

	public List<string> SuspiciousApis { get; set; } = new List<string>();

	public List<string> EnvironmentProbeIndicators { get; set; } = new List<string>();

	public List<string> SectionNames { get; set; } = new List<string>();

	public DateTime? CompilationTimeUtc { get; set; }

	public bool RandomLikeName { get; set; }
}
