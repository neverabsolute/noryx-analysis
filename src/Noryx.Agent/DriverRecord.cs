namespace Noryx.Agent;

internal sealed class DriverRecord
{
	public string Name { get; set; } = "";

	public string DisplayName { get; set; } = "";

	public string State { get; set; } = "";

	public string StartMode { get; set; } = "";

	public string PathName { get; set; } = "";

	public string ResolvedPath { get; set; } = "";

	public string? Sha256 { get; set; }

	public bool Signed { get; set; }

	public string? SignerSubject { get; set; }
}
