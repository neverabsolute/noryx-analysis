namespace Noryx.Agent;

internal sealed class UsnJournalStateRecord
{
	public string Volume { get; set; } = "";

	public bool Active { get; set; }

	public string Detail { get; set; } = "";
}
