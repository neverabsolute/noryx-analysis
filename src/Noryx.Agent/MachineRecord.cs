namespace Noryx.Agent;

internal sealed class MachineRecord
{
	public string MachineName { get; set; } = "";

	public string OsVersion { get; set; } = "";

	public bool Is64BitOs { get; set; }

	public string Fingerprint { get; set; } = "";
}
