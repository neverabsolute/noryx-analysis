namespace Noryx.Agent;

internal sealed class ProcessModuleIntegrityRecord
{
	public int ProcessId { get; set; }

	public string ProcessName { get; set; } = "";

	public string ProcessPath { get; set; } = "";

	public bool ProcessSigned { get; set; }

	public string ProcessSigner { get; set; } = "";

	public string ModuleName { get; set; } = "";

	public string ModulePath { get; set; } = "";

	public bool ModuleSigned { get; set; }

	public string ModuleSigner { get; set; } = "";

	public bool UnderUserProfile { get; set; }

	public bool UnderTemp { get; set; }

	public bool UnderProcessDirectory { get; set; }

	public bool Suspicious { get; set; }
}
