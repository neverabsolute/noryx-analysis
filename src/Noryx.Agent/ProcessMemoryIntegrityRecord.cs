namespace Noryx.Agent;

internal sealed class ProcessMemoryIntegrityRecord
{
	public int ProcessId { get; set; }

	public string ProcessName { get; set; } = "";

	public string ProcessPath { get; set; } = "";

	public bool ProcessSigned { get; set; }

	public string ProcessSigner { get; set; } = "";

	public string BaseAddress { get; set; } = "";

	public ulong RegionSize { get; set; }

	public uint Protection { get; set; }

	public string MemoryType { get; set; } = "";

	public bool Executable { get; set; }

	public bool MzHeader { get; set; }

	public bool PotentialManualMap { get; set; }
}
