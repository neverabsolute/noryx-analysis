using System;
using System.Collections.Generic;

namespace Noryx.Agent;

internal sealed class ScanReport
{
	public List<RustInputScriptRecord> RustInputScripts { get; set; } = new List<RustInputScriptRecord>();

	public string AgentVersion { get; set; } = "";

	public DateTime CollectedAtUtc { get; set; }

	public MachineRecord Machine { get; set; } = new MachineRecord();

	public List<SteamAccountRecord> SteamAccounts { get; set; } = new List<SteamAccountRecord>();

	public List<UsbDeviceRecord> UsbCurrent { get; set; } = new List<UsbDeviceRecord>();

	public List<UsbHistoryRecord> UsbHistory { get; set; } = new List<UsbHistoryRecord>();

	public List<UsbDeviceEventRecord> UsbTimeline { get; set; } = new List<UsbDeviceEventRecord>();

	public List<UsbFileRecord> UsbFiles { get; set; } = new List<UsbFileRecord>();

	public List<SerialDeviceRecord> SerialDevices { get; set; } = new List<SerialDeviceRecord>();

	public HardwareSummaryRecord HardwareSummary { get; set; } = new HardwareSummaryRecord();

	public List<ProcessRecord> Processes { get; set; } = new List<ProcessRecord>();

	public List<PrefetchRecord> Prefetch { get; set; } = new List<PrefetchRecord>();

	public List<PrefetchExecutionRecord> PrefetchExecutions { get; set; } = new List<PrefetchExecutionRecord>();

	public List<ServiceRecord> Services { get; set; } = new List<ServiceRecord>();

	public List<DriverRecord> Drivers { get; set; } = new List<DriverRecord>();

	public List<StartupRecord> Startup { get; set; } = new List<StartupRecord>();

	public List<FileRecord> Files { get; set; } = new List<FileRecord>();

	public List<FileInventoryRecord> FileInventory { get; set; } = new List<FileInventoryRecord>();

	public ScanDiagnosticsRecord ScanDiagnostics { get; set; } = new ScanDiagnosticsRecord();

	public List<PeInspectionRecord> PeInspections { get; set; } = new List<PeInspectionRecord>();

	public List<ZoneIdentifierRecord> ZoneIdentifiers { get; set; } = new List<ZoneIdentifierRecord>();

	public List<AlternateDataStreamRecord> AlternateDataStreams { get; set; } = new List<AlternateDataStreamRecord>();

	public List<AutorunIntegrityRecord> AutorunIntegrity { get; set; } = new List<AutorunIntegrityRecord>();

	public List<ProcessModuleIntegrityRecord> ProcessModuleIntegrity { get; set; } = new List<ProcessModuleIntegrityRecord>();

	public List<ProcessMemoryIntegrityRecord> ProcessMemoryIntegrity { get; set; } = new List<ProcessMemoryIntegrityRecord>();

	public List<WindowProtectionRecord> ProtectedWindows { get; set; } = new List<WindowProtectionRecord>();

	public List<BamRecord> Bam { get; set; } = new List<BamRecord>();

	public List<UserAssistRecord> UserAssist { get; set; } = new List<UserAssistRecord>();

	public List<MuiCacheRecord> MuiCache { get; set; } = new List<MuiCacheRecord>();

	public List<PcaRecord> Pca { get; set; } = new List<PcaRecord>();

	public List<AmcacheExecutionRecord> Amcache { get; set; } = new List<AmcacheExecutionRecord>();

	public List<ShimCacheRecord> ShimCache { get; set; } = new List<ShimCacheRecord>();

	public List<SetupApiUsbRecord> SetupApiUsb { get; set; } = new List<SetupApiUsbRecord>();

	public List<PowerShellRuleHit> PowerShellHits { get; set; } = new List<PowerShellRuleHit>();

	public List<PowerShellArtifactRecord> PowerShellArtifacts { get; set; } = new List<PowerShellArtifactRecord>();

	public List<PrefetchIntegrityRecord> PrefetchIntegrity { get; set; } = new List<PrefetchIntegrityRecord>();

	public List<VolumeRecord> HiddenVolumes { get; set; } = new List<VolumeRecord>();

	public List<EventLogSignalRecord> LogClearSignals { get; set; } = new List<EventLogSignalRecord>();

	public List<ProcessCreationRecord> ProcessCreationEvents { get; set; } = new List<ProcessCreationRecord>();

	public List<ProcessTerminationRecord> ProcessTerminationEvents { get; set; } = new List<ProcessTerminationRecord>();

	public List<DefenderDetectionRecord> DefenderDetections { get; set; } = new List<DefenderDetectionRecord>();

	public List<RecentShortcutRecord> RecentShortcuts { get; set; } = new List<RecentShortcutRecord>();

	public List<CrashArtifactRecord> CrashArtifacts { get; set; } = new List<CrashArtifactRecord>();

	public List<SecurityProductRecord> SecurityProducts { get; set; } = new List<SecurityProductRecord>();

	public List<RecycleBinRecord> RecycleBin { get; set; } = new List<RecycleBinRecord>();

	public VmEnvironmentRecord VmEnvironment { get; set; } = new VmEnvironmentRecord();

	public List<BrowserDownloadRecord> BrowserDownloads { get; set; } = new List<BrowserDownloadRecord>();

	public List<BrowserHistoryRecord> BrowserHistorySignals { get; set; } = new List<BrowserHistoryRecord>();

	public List<RecoveredBrowserArtifact> BrowserRecoveredArtifacts { get; set; } = new List<RecoveredBrowserArtifact>();

	public List<NetworkIndicatorRecord> NetworkIndicators { get; set; } = new List<NetworkIndicatorRecord>();

	public List<DeletedUsnRecord> DeletedUsnRecords { get; set; } = new List<DeletedUsnRecord>();

	public List<ExtensionMismatchRecord> ExtensionMismatches { get; set; } = new List<ExtensionMismatchRecord>();

	public List<DefenderExclusionRecord> DefenderExclusions { get; set; } = new List<DefenderExclusionRecord>();

	public List<BootIntegrityRecord> BootIntegrity { get; set; } = new List<BootIntegrityRecord>();

	public ActivityHistoryState ActivityHistory { get; set; } = new ActivityHistoryState();

	public List<SystemTimeChangeRecord> SystemTimeChanges { get; set; } = new List<SystemTimeChangeRecord>();

	public List<VirtualDiskRecord> VirtualDisks { get; set; } = new List<VirtualDiskRecord>();

	public List<RustModuleRecord> RustModules { get; set; } = new List<RustModuleRecord>();

	public List<UsnJournalStateRecord> UsnJournalState { get; set; } = new List<UsnJournalStateRecord>();

	public List<UsnActivityRecord> UsnActivity { get; set; } = new List<UsnActivityRecord>();

	public List<SystemIntegrityExpansionRecord> SystemIntegrityExpansion { get; set; } = new List<SystemIntegrityExpansionRecord>();

	public SystemArtifactRecord SystemArtifacts { get; set; } = new SystemArtifactRecord();

	public List<string> Errors { get; set; } = new List<string>();
}
