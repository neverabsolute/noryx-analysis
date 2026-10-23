namespace Noryx.Agent;

internal sealed class RustModuleRecord
{
	public int ProcessId { get; set; }

	public string ProcessName { get; set; } = "";

	public string ModuleName { get; set; } = "";

	public string Path { get; set; } = "";

	public bool Signed { get; set; }

	public string SignerSubject { get; set; } = "";

	public string CompanyName { get; set; } = "";

	public bool UnderGameDirectory { get; set; }

	public bool UnderWindows { get; set; }

	public bool UnderProgramFiles { get; set; }

	public bool UnderUserProfile { get; set; }

	public bool UnderTemp { get; set; }
}
