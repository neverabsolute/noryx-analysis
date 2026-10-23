using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class ScanDiagnosticsRecord
{
	public string CollectionMode { get; set; } = "rust-broad-15m";

	public int CollectionBudgetSeconds { get; set; } = 900;

	public bool CollectionLimitReached { get; set; }

	public List<string> IncompleteModules { get; set; } = new List<string>();

	public List<string> PendingFiles { get; set; } = new List<string>();

	public int DirectoriesVisited { get; set; }

	public int InaccessibleEntries { get; set; }

	public int ReparsePointsSkipped { get; set; }

	public int FailedCandidates { get; set; }

	public string Scope { get; set; } = "";

	public int InventoryCount { get; set; }

	public int DeepSelectedCount { get; set; }

	public int DeepCompletedCount { get; set; }

	public int MetadataOnlyCount { get; set; }

	public bool HashRulesRequireAll { get; set; }

	public Dictionary<string, double> ModuleSeconds { get; set; } = new Dictionary<string, double>();
}
