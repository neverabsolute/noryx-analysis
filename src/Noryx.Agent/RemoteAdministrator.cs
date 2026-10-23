namespace Noryx.Agent;

internal sealed record RemoteAdministrator(long Id, string DisplayName)
{
	public override string ToString()
	{
		return DisplayName;
	}
}
