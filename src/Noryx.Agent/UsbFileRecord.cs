using System;

namespace Noryx.Agent;

internal sealed class UsbFileRecord
{
	public string Drive { get; set; } = "";

	public string VolumeLabel { get; set; } = "";

	public string Name { get; set; } = "";

	public string Path { get; set; } = "";

	public string RelativePath { get; set; } = "";

	public string Extension { get; set; } = "";

	public long Size { get; set; }

	public DateTime? CreatedUtc { get; set; }

	public DateTime? LastWriteUtc { get; set; }
}
