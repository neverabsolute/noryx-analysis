using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Noryx.Agent;

internal sealed class FileSearchCoverage
{
	public int DirectoriesVisited;

	public int FilesVisited;

	public int Inaccessible;

	public int ReparsePointsSkipped;

	public bool LimitReached;

	public HashSet<string> SeenDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

	public Stopwatch Clock = Stopwatch.StartNew();
}
