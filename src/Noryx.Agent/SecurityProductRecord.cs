namespace Noryx.Agent;

internal sealed class SecurityProductRecord
{
	public string Category { get; set; } = "";

	public string DisplayName { get; set; } = "";

	public string InstanceGuid { get; set; } = "";

	public string PathToSignedProductExe { get; set; } = "";

	public string PathToSignedReportingExe { get; set; } = "";

	public string ProductState { get; set; } = "";

	public string Timestamp { get; set; } = "";
}
