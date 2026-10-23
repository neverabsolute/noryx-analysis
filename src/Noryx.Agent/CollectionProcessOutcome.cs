namespace Noryx.Agent;

internal sealed record CollectionProcessOutcome(bool DeadlineReached, bool Completed, int ExitCode);
