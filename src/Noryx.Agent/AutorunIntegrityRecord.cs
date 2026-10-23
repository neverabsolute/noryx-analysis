namespace Noryx.Agent;

internal sealed class AutorunIntegrityRecord
{
	public string Source { get; set; } = "";

	public string Name { get; set; } = "";

	public string Command { get; set; } = "";

	public string ExecutablePath { get; set; } = "";

	public bool FileExists { get; set; }

	public bool Signed { get; set; }

	public string SignerSubject { get; set; } = "";

	public bool UserWritablePath { get; set; }

	public bool Enabled { get; set; }

	public string RunAs { get; set; } = "";

	public bool Suspicious { get; set; }
}
