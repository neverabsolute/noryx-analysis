namespace Noryx.Agent;

internal sealed class SystemArtifactRecord
{
	public bool PrefetchDirectoryExists { get; set; }

	public int? EnablePrefetcher { get; set; }

	public bool AmcacheExists { get; set; }

	public bool SetupApiLogExists { get; set; }

	public int? BamStart { get; set; }
}
