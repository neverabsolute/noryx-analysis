using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Noryx.Agent;

internal static class Program
{
	private sealed class FileWorkerReply
	{
		public string Stage { get; set; } = "";

		public long Bytes { get; set; }

		public FileRecord? Result { get; set; }

		public string? Error { get; set; }
	}

	private sealed class FileInspectionWorkerClient : IDisposable
	{
		private Process? child;

		private string stage = "Inicialização";

		private long lastBytes;

		private void Start()
		{
			if (child == null || child.HasExited)
			{
				ProcessStartInfo processStartInfo = new ProcessStartInfo(Environment.ProcessPath ?? throw new InvalidOperationException("Executável não localizado."))
				{
					UseShellExecute = false,
					RedirectStandardInput = true,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					CreateNoWindow = true
				};
				processStartInfo.ArgumentList.Add("--file-worker");
				processStartInfo.ArgumentList.Add(Environment.ProcessId.ToString());
				child = Process.Start(processStartInfo) ?? throw new InvalidOperationException("Não foi possível iniciar coletor auxiliar.");
				child.ErrorDataReceived += delegate
				{
				};
				child.BeginErrorReadLine();
			}
		}

		public FileRecord Inspect(string path)
		{
			for (int i = 0; i < 2; i++)
			{
				try
				{
					Start();
					lastBytes = 0L;
					stage = "Inicialização";
					child.StandardInput.WriteLine(JsonSerializer.Serialize(path, JsonOptions));
					child.StandardInput.Flush();
					FileWorkerReply fileWorkerReply;
					do
					{
						fileWorkerReply = JsonSerializer.Deserialize<FileWorkerReply>(child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60.0)).GetAwaiter()
							.GetResult() ?? throw new IOException("Coletor auxiliar encerrou na etapa " + stage), JsonOptions) ?? throw new IOException("Resposta inválida do coletor.");
						stage = fileWorkerReply.Stage;
						if (fileWorkerReply.Bytes > lastBytes)
						{
							Interlocked.Add(ref _fileBytesRead, fileWorkerReply.Bytes - lastBytes);
							lastBytes = fileWorkerReply.Bytes;
						}
						if (fileWorkerReply.Error != null)
						{
							throw new IOException(stage + ": " + fileWorkerReply.Error);
						}
					}
					while (fileWorkerReply.Result == null);
					return fileWorkerReply.Result;
				}
				catch (TimeoutException)
				{
					string text = stage;
					Dispose();
					if (i == 1)
					{
						throw new IOException("Sem resposta por 60s em " + text + " após nova tentativa. Arquivo pendente para staff.");
					}
				}
				catch
				{
					Dispose();
					throw;
				}
			}
			throw new IOException("Arquivo não concluído.");
		}

		public void Dispose()
		{
			if (child == null)
			{
				return;
			}
			try
			{
				if (!child.HasExited)
				{
					child.Kill(entireProcessTree: true);
				}
			}
			catch
			{
			}
			try
			{
				child.WaitForExit(3000);
			}
			catch
			{
			}
			child.Dispose();
			child = null;
		}
	}

	private static readonly object WorkerOutputLock = new object();

	private static bool _collectionWorker;

	private static readonly Dictionary<string, string> CollectionProperties = new Dictionary<string, string>
	{
		{ "USB atual", "usbCurrent" },
		{ "Histórico USB", "usbHistory" },
		{ "Linha do tempo USB", "usbTimeline" },
		{ "Arquivos em pendrives conectados", "usbFiles" },
		{ "Dispositivos seriais", "serialDevices" },
		{ "Prefetch básico", "prefetch" },
		{ "Prefetch detalhado", "prefetchExecutions" },
		{ "Processos", "processes" },
		{ "Drivers", "drivers" },
		{ "BAM/DAM", "bam" },
		{ "UserAssist", "userAssist" },
		{ "PCA Store", "pca" },
		{ "Amcache", "amcache" },
		{ "ShimCache", "shimCache" },
		{ "Arquivos", "files" },
		{ "Scripts de entrada / perfil Rust", "rustInputScripts" },
		{ "Análise PE / entropia / packers", "peInspections" },
		{ "Zone.Identifier / origem de downloads", "zoneIdentifiers" },
		{ "Alternate Data Streams", "alternateDataStreams" },
		{ "Autoruns e tarefas agendadas", "autorunIntegrity" },
		{ "Módulos em processos críticos", "processModuleIntegrity" },
		{ "Memória executável privada / manual-map", "processMemoryIntegrity" },
		{ "Janelas excluídas de captura", "protectedWindows" },
		{ "Serviços", "services" },
		{ "Inicialização", "startup" },
		{ "MUICache", "muiCache" },
		{ "SetupAPI USB", "setupApiUsb" },
		{ "PowerShell por regra", "powerShellHits" },
		{ "PowerShell histórico / eventos", "powerShellArtifacts" },
		{ "Integridade do Prefetch", "prefetchIntegrity" },
		{ "Volumes sem letra", "hiddenVolumes" },
		{ "Sinais de limpeza de logs", "logClearSignals" },
		{ "Event Log 4688", "processCreationEvents" },
		{ "Event Log 4689", "processTerminationEvents" },
		{ "Histórico do Microsoft Defender", "defenderDetections" },
		{ "Atalhos recentes", "recentShortcuts" },
		{ "Windows Error Reporting / crashes", "crashArtifacts" },
		{ "Produtos de segurança registrados", "securityProducts" },
		{ "Lixeira do Windows", "recycleBin" },
		{ "Histórico de downloads", "browserDownloads" },
		{ "Histórico suspeito de navegação", "browserHistorySignals" },
		{ "Vestígios de histórico apagado", "browserRecoveredArtifacts" },
		{ "Rede / DNS / conexões TCP", "networkIndicators" },
		{ "Arquivos apagados no USN Journal", "deletedUsnRecords" },
		{ "Extensões modificadas", "extensionMismatches" },
		{ "Exclusões do Defender", "defenderExclusions" },
		{ "Integridade de boot", "bootIntegrity" },
		{ "Alterações de horário", "systemTimeChanges" },
		{ "Discos virtuais", "virtualDisks" },
		{ "Módulos do Rust", "rustModules" },
		{ "Estado do USN Journal", "usnJournalState" },
		{ "JournalTrace / atividade USN", "usnActivity" },
		{ "Integridade ampliada do Windows", "systemIntegrityExpansion" },
		{ "Contas Steam", "steamAccounts" }
	};

	private static readonly string AgentVersion = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

	private const string DefaultServerUrl = "https://noryx-anticheat.shardweb.app";

	private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
	{
		WriteIndented = false,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
	};

	private static readonly ConcurrentDictionary<string, (long Length, long Modified, long Created, string Hash)> ScanHashes = new ConcurrentDictionary<string, (long, long, long, string)>(StringComparer.OrdinalIgnoreCase);

	private static long _fileBytesRead;

	private static Action<long>? _fileWorkerHashProgress;

	private static Action<string>? _statusSink;

	private static Action<int, string>? _progressSink;

	private static int _completedModules;

	private static int _completedUnits;

	private static int _activeModuleWeight = 1;

	private static readonly Dictionary<string, double> ModuleSeconds = new Dictionary<string, double>();

	private const int CollectionModuleCount = 54;

	private static void WorkerEmit(object value)
	{
		if (!_collectionWorker)
		{
			return;
		}
		lock (WorkerOutputLock)
		{
			Console.Out.WriteLine("NORYX_COLLECTION:" + JsonSerializer.Serialize(value, JsonOptions));
			Console.Out.Flush();
		}
	}

	private static void WorkerAppend(string key, object items)
	{
		WorkerEmit(new
		{
			kind = "append",
			key = key,
			items = items
		});
	}

	private static void WorkerValue(string key, object value)
	{
		WorkerEmit(new
		{
			kind = "value",
			key = key,
			value = value
		});
	}

	private static void WorkerModule<T>(string module, List<T> value, List<string> errors)
	{
		if (CollectionProperties.TryGetValue(module, out string value2))
		{
			WorkerValue(value2, value);
		}
		WorkerValue("errors", errors);
	}

	private static bool TryRunCollectionWorker(string[] args)
	{
		if (args.Length != 2 || args[0] != "--collection-worker" || !int.TryParse(args[1], out var parent))
		{
			return false;
		}
		_collectionWorker = true;
		using (new System.Threading.Timer(delegate
		{
			try
			{
				using Process process = Process.GetProcessById(parent);
				if (process.HasExited)
				{
					Environment.Exit(4);
				}
			}
			catch
			{
				Environment.Exit(4);
			}
		}, null, 2000, 2000))
		{
			try
			{
				AgentRunResult result = RunAnalysisCoreAsync(JsonSerializer.Deserialize<string[]>(Console.ReadLine() ?? "[]", JsonOptions) ?? throw new IOException("Sessão inválida."), delegate(string text)
				{
					WorkerEmit(new
					{
						kind = "status",
						text = text
					});
				}, delegate(int percent, string text)
				{
					WorkerEmit(new
					{
						kind = "progress",
						percent = percent,
						text = text
					});
				}).GetAwaiter().GetResult();
				if (result.ExitCode != 0)
				{
					WorkerEmit(new
					{
						kind = "error",
						text = (result.Error ?? "Coleta incompleta.")
					});
				}
			}
			catch (Exception ex)
			{
				WorkerEmit(new
				{
					kind = "error",
					text = ex.Message
				});
			}
			return true;
		}
	}

	internal static async Task<AgentRunResult> RunAnalysisAsync(string[] args, Action<string>? status = null, Action<int, string>? progress = null)
	{
		_statusSink = status;
		_progressSink = progress;
		try
		{
			AgentConfig config = LoadConfig(args);
			using HttpClient http = new HttpClient
			{
				BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
				Timeout = TimeSpan.FromSeconds(35.0)
			};
			byte[] array = AgentRecoveryStore.LoadReport(config.ServerUrl, config.Token);
			if (array != null)
			{
				if (array.Length > 6291456)
				{
					using JsonDocument jsonDocument = JsonDocument.Parse(array);
					array = TransportReport.Encode(jsonDocument.RootElement);
					AgentRecoveryStore.SaveReport(config.ServerUrl, config.Token, array);
				}
				ReportProgress(90, "Coleta já concluída. Reenviando relatório salvo.");
				return await UploadSavedReportAsync(http, config, array);
			}
			Dictionary<string, JsonElement> state = new Dictionary<string, JsonElement>();
			Dictionary<string, List<JsonElement>> appended = new Dictionary<string, List<JsonElement>>();
			HashSet<string> completedKeys = new HashSet<string>();
			JsonElement? complete = null;
			string stage = "Preparação";
			string workerError = "";
			int lastPercent = 0;
			Stopwatch clock = Stopwatch.StartNew();
			using System.Threading.Timer countdown = new System.Threading.Timer(delegate
			{
				ReportProgress(lastPercent, stage + " · orçamento restante " + TimeSpan.FromSeconds(Math.Max(0.0, 900.0 - clock.Elapsed.TotalSeconds)).ToString("mm\\:ss"));
			}, null, 0, 1000);
			CollectionProcessOutcome collectionProcessOutcome = await CollectionProcessRunner.RunAsync(new ProcessStartInfo(Environment.ProcessPath ?? throw new IOException("EXE indisponível."))
			{
				UseShellExecute = false,
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
				ArgumentList = 
				{
					"--collection-worker",
					Environment.ProcessId.ToString()
				}
			}, JsonSerializer.Serialize(args, JsonOptions), TimeSpan.FromSeconds(900.0), delegate(JsonElement message)
			{
				switch (message.GetProperty("kind").GetString())
				{
				case "value":
				{
					string text = message.GetProperty("key").GetString();
					state[text] = message.GetProperty("value").Clone();
					completedKeys.Add(text);
					break;
				}
				case "append":
				{
					string key = message.GetProperty("key").GetString();
					if (!appended.TryGetValue(key, out List<JsonElement> value2))
					{
						value2 = new List<JsonElement>();
						appended[key] = value2;
					}
					{
						foreach (JsonElement item in message.GetProperty("items").EnumerateArray())
						{
							value2.Add(item.Clone());
						}
						break;
					}
				}
				case "completed":
					complete = message.GetProperty("report").Clone();
					break;
				case "error":
					workerError = message.GetProperty("text").GetString() ?? "Coleta interrompida.";
					break;
				case "status":
					ReportStatus(message.GetProperty("text").GetString() ?? "");
					break;
				case "progress":
					stage = message.GetProperty("text").GetString() ?? stage;
					lastPercent = Math.Min(88, message.GetProperty("percent").GetInt32());
					ReportProgress(lastPercent, stage + " · coleta ampla, orçamento de 15 min");
					break;
				}
			});
			countdown.Dispose();
			if (!complete.HasValue && state.Count == 0)
			{
				throw new IOException(string.IsNullOrEmpty(workerError) ? "A coleta não iniciou. Confira a conexão com o painel." : workerError);
			}
			if (!complete.HasValue)
			{
				foreach (KeyValuePair<string, List<JsonElement>> item2 in appended)
				{
					if (!state.ContainsKey(item2.Key))
					{
						state[item2.Key] = JsonSerializer.SerializeToElement(item2.Value, JsonOptions);
					}
				}
			}
			appended.Clear();
			ScanReport scanReport = JsonSerializer.Deserialize<ScanReport>(complete?.GetRawText() ?? JsonSerializer.Serialize(state, JsonOptions), JsonOptions) ?? new ScanReport();
			scanReport.AgentVersion = AgentVersion;
			scanReport.CollectedAtUtc = DateTime.UtcNow;
			scanReport.ScanDiagnostics.CollectionMode = "rust-broad-15m";
			if (string.IsNullOrEmpty(scanReport.ScanDiagnostics.Scope))
			{
				scanReport.ScanDiagnostics.Scope = "Busca ampla em discos locais e removíveis acessíveis, com prioridade para evidências de execução. Limites e inacessíveis exigem revisão.";
			}
			scanReport.ScanDiagnostics.CollectionBudgetSeconds = 900;
			if (!complete.HasValue)
			{
				scanReport.ScanDiagnostics.CollectionLimitReached = collectionProcessOutcome.DeadlineReached;
				scanReport.ScanDiagnostics.IncompleteModules = (from x in CollectionProperties
					where !completedKeys.Contains(x.Value)
					select x.Key).ToList();
				if (state.TryGetValue("moduleSeconds", out var value))
				{
					scanReport.ScanDiagnostics.ModuleSeconds = value.Deserialize<Dictionary<string, double>>(JsonOptions) ?? new Dictionary<string, double>();
				}
				scanReport.Errors.Add(collectionProcessOutcome.DeadlineReached ? ("Limite da coleta local atingido. Etapa em andamento: " + stage + ". Cobertura incompleta; revisão obrigatória.") : ("Coletor interrompido: " + workerError + ". Revisão obrigatória."));
				ReportStatus("Coleta encerrada com pendências. Não será classificada como limpa.");
			}
			byte[] array2 = TransportReport.Encode(scanReport);
			AgentRecoveryStore.SaveReport(config.ServerUrl, config.Token, array2);
			ReportProgress(90, "Coleta encerrada. Enviando relatório.");
			return await UploadSavedReportAsync(http, config, array2);
		}
		catch (Exception ex)
		{
			ReportStatus(ex.Message);
			return new AgentRunResult
			{
				ExitCode = 1,
				Error = ex.Message
			};
		}
	}

	private static void WorkerReply(FileWorkerReply message)
	{
		Console.Out.WriteLine(JsonSerializer.Serialize(message, JsonOptions));
		Console.Out.Flush();
	}

	private static bool TryRunFileWorker(string[] args)
	{
		if (args.Length != 2 || args[0] != "--file-worker" || !int.TryParse(args[1], out var parentId))
		{
			return false;
		}
		using (new System.Threading.Timer(delegate
		{
			try
			{
				using Process process = Process.GetProcessById(parentId);
				if (process.HasExited)
				{
					Environment.Exit(4);
				}
			}
			catch
			{
				Environment.Exit(4);
			}
		}, null, 2000, 2000))
		{
			string json;
			while ((json = Console.ReadLine()) != null)
			{
				try
				{
					string text = JsonSerializer.Deserialize<string>(json, JsonOptions) ?? throw new InvalidOperationException("Caminho inválido.");
					WorkerReply(new FileWorkerReply
					{
						Stage = "Metadados"
					});
					FileInfo fileInfo = new FileInfo(text);
					if (!fileInfo.Exists)
					{
						throw new FileNotFoundException("Arquivo não disponível.");
					}
					Interlocked.Exchange(ref _fileBytesRead, 0L);
					Stopwatch pulse = Stopwatch.StartNew();
					_fileWorkerHashProgress = delegate(long bytes)
					{
						if (pulse.ElapsedMilliseconds >= 1000)
						{
							WorkerReply(new FileWorkerReply
							{
								Stage = "Leitura/hash",
								Bytes = bytes
							});
							pulse.Restart();
						}
					};
					WorkerReply(new FileWorkerReply
					{
						Stage = "Leitura/hash"
					});
					string sha = TrySha256(text);
					WorkerReply(new FileWorkerReply
					{
						Stage = "Leitura/hash",
						Bytes = Interlocked.Read(in _fileBytesRead)
					});
					_fileWorkerHashProgress = null;
					WorkerReply(new FileWorkerReply
					{
						Stage = "Assinatura digital"
					});
					var (signed, signerSubject) = TrySigner(text);
					WorkerReply(new FileWorkerReply
					{
						Stage = "Cabeçalho PE"
					});
					DateTime? compilationTimeUtc = TryPeCompileTimeUtc(text);
					WorkerReply(new FileWorkerReply
					{
						Stage = "Arquivo compactado"
					});
					List<string> archiveEntries = (fileInfo.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ? TryListZipEntries(text) : new List<string>());
					WorkerReply(new FileWorkerReply
					{
						Stage = "Volume"
					});
					string driveType = GetDriveType(text);
					WorkerReply(new FileWorkerReply
					{
						Stage = "Concluído",
						Result = new FileRecord
						{
							Name = fileInfo.Name,
							Path = fileInfo.FullName,
							Extension = fileInfo.Extension,
							Size = fileInfo.Length,
							CreatedUtc = SafeDate(fileInfo.CreationTimeUtc),
							LastWriteUtc = SafeDate(fileInfo.LastWriteTimeUtc),
							Sha256 = sha,
							Signed = signed,
							SignerSubject = signerSubject,
							CompilationTimeUtc = compilationTimeUtc,
							RandomLikeName = LooksRandomFileName(fileInfo.Name),
							ArchiveEntries = archiveEntries,
							DriveType = driveType
						}
					});
				}
				catch (Exception ex)
				{
					WorkerReply(new FileWorkerReply
					{
						Stage = "Erro",
						Error = ex.Message
					});
				}
				finally
				{
					_fileWorkerHashProgress = null;
				}
			}
			return true;
		}
	}

	private static int LocalProgress(double fraction = 0.0)
	{
		return 5 + (int)(83.0 * ((double)_completedUnits + (double)_activeModuleWeight * fraction) / 78.0);
	}

	private static void ReportModuleProgress(double fraction, string stage)
	{
		ReportProgress(LocalProgress(Math.Clamp(fraction, 0.0, 1.0)), stage);
	}

	private static void ReportProgress(int value, string stage)
	{
		try
		{
			_progressSink?.Invoke(Math.Clamp(value, 0, 100), stage);
		}
		catch
		{
		}
	}

	[STAThread]
	public static void Main(string[] args)
	{
		if (!TryRunFileWorker(args) && !TryRunCollectionWorker(args))
		{
			ApplicationConfiguration.Initialize();
			Application.Run(new AgentMainForm(args));
		}
	}

	private static async Task<AgentRunResult> RunAnalysisCoreAsync(string[] args, Action<string>? status = null, Action<int, string>? progress = null)
	{
		_statusSink = status;
		_progressSink = progress;
		_completedModules = 0;
		_completedUnits = 0;
		ModuleSeconds.Clear();
		ScanHashes.Clear();
		AuthenticodeVerifier.ResetCache();
		ReportProgress(0, "Preparando conexão");
		ReportStatus(AgentLocalization.Pick("Preparando a análise...", "Preparando el análisis...", "Preparing analysis..."));
		try
		{
			AgentConfig config = LoadConfig(args);
			ReportStatus(AgentLocalization.Pick("Conectando ao servidor do Noryx...", "Conectando al servidor de Noryx...", "Connecting to the Noryx server..."));
			HashSet<string> evidencePaths;
			using (HttpClient http = new HttpClient
			{
				BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
				Timeout = TimeSpan.FromSeconds(15.0)
			})
			{
				RulesResponse rulesPayload = await LoadRulesAsync(http, config.Token);
				ReportStatus(AgentLocalization.Pick("Configuração recebida. Iniciando coleta segura...", "Configuración recibida. Iniciando recopilación segura...", "Configuration received. Starting secure collection..."));
				ReportProgress(3, "Configuração recebida");
				if (!string.Equals(rulesPayload.GameId, "rust", StringComparison.OrdinalIgnoreCase))
				{
					throw new InvalidOperationException("Perfil de jogo não suportado por este cliente. Esta versão suporta Rust.");
				}
				List<DetectionRule> rules = rulesPayload.Rules;
				string machineFingerprint = WindowsEnvironmentCollector.ComputeMachineFingerprint();
				WorkerValue("machine", new MachineRecord
				{
					MachineName = Environment.MachineName,
					OsVersion = Environment.OSVersion.VersionString,
					Is64BitOs = Environment.Is64BitOperatingSystem,
					Fingerprint = machineFingerprint
				});
				await PostJsonAsync(http, "api/agent/" + Uri.EscapeDataString(config.Token) + "/start", new
				{
					machineName = Environment.MachineName,
					osVersion = Environment.OSVersion.VersionString,
					agentVersion = AgentVersion,
					machineFingerprint = machineFingerprint
				});
				ReportStatus(AgentLocalization.Pick("Coletando evidências técnicas do computador...", "Recopilando evidencias técnicas del equipo...", "Collecting technical evidence from the computer..."));
				ReportProgress(5, "Iniciando coleta local");
				List<string> errors = new List<string>();
				List<PrefetchRecord> prefetch = SafeCollect("Prefetch básico", CollectPrefetch, errors);
				List<PrefetchExecutionRecord> list = SafeCollect("Prefetch detalhado", PrefetchExecutionCollector.Collect, errors);
				List<ProcessRecord> list2 = SafeCollect("Processos", CollectProcesses, errors);
				List<DriverRecord> list3 = SafeCollect("Drivers", CollectDrivers, errors);
				List<BamRecord> list4 = SafeCollect("BAM/DAM", AdvancedCollectors.CollectBam, errors);
				List<UserAssistRecord> list5 = SafeCollect("UserAssist", AdvancedCollectors.CollectUserAssist, errors);
				List<PcaRecord> list6 = SafeCollect("PCA Store", AdvancedCollectors.CollectPcaStore, errors);
				List<AmcacheExecutionRecord> list7 = SafeCollect("Amcache", AmcacheExecutionCollector.Collect, errors);
				List<ShimCacheRecord> list8 = SafeCollect("ShimCache", ShimCacheExecutionCollector.Collect, errors);
				evidencePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				foreach (ProcessRecord item in list2)
				{
					AddEvidencePath(item.Path);
				}
				foreach (DriverRecord item2 in list3)
				{
					AddEvidencePath(item2.ResolvedPath);
				}
				foreach (PrefetchExecutionRecord item3 in list)
				{
					AddEvidencePath(item3.ResolvedExecutablePath);
				}
				foreach (BamRecord item4 in list4)
				{
					AddEvidencePath(item4.Path);
				}
				foreach (UserAssistRecord item5 in list5)
				{
					AddEvidencePath(item5.DecodedName);
				}
				foreach (PcaRecord item6 in list6)
				{
					AddEvidencePath(item6.Path);
				}
				foreach (AmcacheExecutionRecord item7 in list7)
				{
					AddEvidencePath(item7.FullPath);
				}
				foreach (ShimCacheRecord item8 in list8)
				{
					AddEvidencePath(item8.Path);
				}
				List<FileInventoryRecord> fileInventory = new List<FileInventoryRecord>();
				HashSet<string> inputScriptPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				ScanDiagnosticsRecord diagnostics = new ScanDiagnosticsRecord();
				List<ZoneIdentifierRecord> zoneIdentifiers = SafeCollect("Zone.Identifier / origem de downloads", ZoneIdentifierCollector.Collect, errors);
				List<AutorunIntegrityRecord> autorunIntegrity = SafeCollect("Autoruns e tarefas agendadas", AutorunIntegrityCollector.Collect, errors);
				List<ProcessModuleIntegrityRecord> processModuleIntegrity = SafeCollect("Módulos em processos críticos", ProcessModuleIntegrityCollector.Collect, errors);
				List<ProcessMemoryIntegrityRecord> processMemoryIntegrity = SafeCollect("Memória executável privada / manual-map", ProcessMemoryIntegrityCollector.Collect, errors);
				List<WindowProtectionRecord> protectedWindows = SafeCollect("Janelas excluídas de captura", WindowProtectionCollector.Collect, errors);
				List<ServiceRecord> services = SafeCollect("Serviços", CollectServices, errors);
				List<StartupRecord> startup = SafeCollect("Inicialização", CollectStartupEntries, errors);
				List<UsbDeviceRecord> usbCurrent = SafeCollect("USB atual", CollectCurrentUsbDevices, errors);
				List<UsbHistoryRecord> list9 = SafeCollect("Histórico USB", () => CollectUsbHistory(usbCurrent), errors);
				List<UsbDeviceEventRecord> list10 = SafeCollect("Linha do tempo USB", UsbEventCollector.Collect, errors);
				List<UsbFileRecord> usbFiles = SafeCollect("Arquivos em pendrives conectados", CollectConnectedUsbFiles, errors);
				try
				{
					UsbEventCollector.EnrichUsbHistory(list9, list10);
					WorkerValue("usbHistory", list9);
					Console.WriteLine("  ✓ Horários USB correlacionados");
				}
				catch (Exception ex)
				{
					errors.Add("Correlação USB: " + ex.Message);
					Console.WriteLine("  ! Correlação USB: indisponível");
				}
				List<SerialDeviceRecord> list11 = SafeCollect("Dispositivos seriais", CollectSerialDevices, errors);
				HardwareSummaryRecord hardwareSummaryRecord = HardwareSummaryCollector.Build(list11);
				Console.WriteLine($"  ✓ Placas: {hardwareSummaryRecord.TotalRelevantDevices} | Arduino: {hardwareSummaryRecord.ArduinoCount} | MAKCU/Moku: {hardwareSummaryRecord.MakcuCount}");
				List<MuiCacheRecord> muiCache = SafeCollect("MUICache", AdvancedCollectors.CollectMuiCache, errors);
				List<SetupApiUsbRecord> setupApiUsb = SafeCollect("SetupAPI USB", AdvancedCollectors.CollectSetupApiUsb, errors);
				List<PowerShellRuleHit> powerShellHits = SafeCollect("PowerShell por regra", () => AdvancedCollectors.CollectPowerShellRuleHits(rules), errors);
				List<PowerShellArtifactRecord> powerShellArtifacts = SafeCollect("PowerShell histórico / eventos", PowerShellForensicsCollector.Collect, errors);
				List<PrefetchIntegrityRecord> prefetchIntegrity = SafeCollect("Integridade do Prefetch", AdvancedCollectors.CollectPrefetchIntegrity, errors);
				List<VolumeRecord> hiddenVolumes = SafeCollect("Volumes sem letra", AdvancedCollectors.CollectVolumesWithoutDriveLetter, errors);
				List<EventLogSignalRecord> logClearSignals = SafeCollect("Sinais de limpeza de logs", () => AdvancedCollectors.CollectRecentLogClearSignals(errors), errors);
				List<ProcessCreationRecord> processCreationEvents = SafeCollect("Event Log 4688", DeepForensicCollector.CollectProcessCreationEvents, errors);
				List<ProcessTerminationRecord> processTerminationEvents = SafeCollect("Event Log 4689", DeepForensicCollector.CollectProcessTerminationEvents, errors);
				List<DefenderDetectionRecord> defenderDetections = SafeCollect("Histórico do Microsoft Defender", DeepForensicCollector.CollectDefenderDetections, errors);
				List<RecentShortcutRecord> recentShortcuts = SafeCollect("Atalhos recentes", DeepForensicCollector.CollectRecentShortcuts, errors);
				List<CrashArtifactRecord> crashArtifacts = SafeCollect("Windows Error Reporting / crashes", CrashArtifactCollector.Collect, errors);
				List<SecurityProductRecord> securityProducts = SafeCollect("Produtos de segurança registrados", SecurityProductCollector.Collect, errors);
				List<RecycleBinRecord> recycleBin = SafeCollect("Lixeira do Windows", WindowsEnvironmentCollector.CollectRecycleBin, errors);
				VmEnvironmentRecord vmEnvironmentRecord;
				try
				{
					vmEnvironmentRecord = WindowsEnvironmentCollector.CollectVmEnvironment();
					Console.WriteLine(vmEnvironmentRecord.IsVirtualMachine ? ("  ✓ Ambiente virtual: " + vmEnvironmentRecord.DetectedPlatform) : "  ✓ Ambiente virtual: não detectado");
				}
				catch (Exception ex2)
				{
					errors.Add("Ambiente virtual: " + ex2.Message);
					vmEnvironmentRecord = new VmEnvironmentRecord();
					Console.WriteLine("  ! Ambiente virtual: indisponível");
				}
				List<BrowserDownloadRecord> browserDownloads = SafeCollect("Histórico de downloads", BrowserDownloadsCollector.Collect, errors);
				List<BrowserHistoryRecord> browserHistorySignals = SafeCollect("Histórico suspeito de navegação", () => BrowserHistoryCollector.CollectSuspicious(rulesPayload.ThreatCatalog), errors);
				List<RecoveredBrowserArtifact> browserRecoveredArtifacts = SafeCollect("Vestígios de histórico apagado", () => BrowserArtifactRecoveryCollector.Collect(rulesPayload.ThreatCatalog), errors);
				List<NetworkIndicatorRecord> networkIndicators = SafeCollect("Rede / DNS / conexões TCP", () => NetworkIndicatorCollector.Collect(rulesPayload.ThreatCatalog), errors);
				List<DeletedUsnRecord> deletedUsnRecords = SafeCollect("Arquivos apagados no USN Journal", UsnDeletionCollector.Collect, errors);
				List<ExtensionMismatchRecord> extensionMismatches = SafeCollect("Extensões modificadas", DeepForensicCollector.CollectModifiedExtensions, errors);
				List<DefenderExclusionRecord> defenderExclusions = SafeCollect("Exclusões do Defender", DeepForensicCollector.CollectDefenderExclusions, errors);
				List<BootIntegrityRecord> bootIntegrity = SafeCollect("Integridade de boot", DeepForensicCollector.CollectBootIntegrityFlags, errors);
				List<SystemTimeChangeRecord> systemTimeChanges = SafeCollect("Alterações de horário", DeepForensicCollector.CollectSystemTimeChanges, errors);
				List<VirtualDiskRecord> virtualDisks = SafeCollect("Discos virtuais", DeepForensicCollector.CollectVirtualDiskIndicators, errors);
				List<RustModuleRecord> rustModules = SafeCollect("Módulos do Rust", DeepForensicCollector.CollectRustModules, errors);
				List<UsnJournalStateRecord> usnJournalState = SafeCollect("Estado do USN Journal", DeepForensicCollector.CollectUsnJournalState, errors);
				List<UsnActivityRecord> usnActivity = SafeCollect("JournalTrace / atividade USN", UsnActivityCollector.Collect, errors);
				List<SystemIntegrityExpansionRecord> systemIntegrityExpansion = SafeCollect("Integridade ampliada do Windows", SystemIntegrityExpansionCollector.Collect, errors);
				ActivityHistoryState activityHistory;
				try
				{
					activityHistory = DeepForensicCollector.CollectActivityHistoryState();
					Console.WriteLine("  ✓ Activity History");
				}
				catch (Exception ex3)
				{
					errors.Add("Activity History: " + ex3.Message);
					activityHistory = new ActivityHistoryState();
					Console.WriteLine("  ! Activity History: indisponível");
				}
				SystemArtifactRecord systemArtifacts;
				try
				{
					systemArtifacts = AdvancedCollectors.CollectSystemArtifactState();
					Console.WriteLine("  ✓ Estado dos artefatos do Windows");
				}
				catch (Exception ex4)
				{
					errors.Add("Estado dos artefatos: " + ex4.Message);
					systemArtifacts = new SystemArtifactRecord();
					Console.WriteLine("  ! Estado dos artefatos: indisponível");
				}
				List<SteamAccountRecord> steamAccounts = SafeCollect("Contas Steam", SteamAccountCollector.Collect, errors);
				List<RustInputScriptRecord> inputScriptResults = new List<RustInputScriptRecord>();
				ConcurrentBag<PeInspectionRecord> peResults = new ConcurrentBag<PeInspectionRecord>();
				ConcurrentBag<AlternateDataStreamRecord> streamResults = new ConcurrentBag<AlternateDataStreamRecord>();
				List<FileRecord> files = SafeCollect("Arquivos", () => CollectCandidateFiles(prefetch, rules, rulesPayload.ThreatCatalog, rulesPayload.KnownCheatExecutableNames, evidencePaths, fileInventory, diagnostics, errors, inputScriptPaths, inputScriptResults, peResults, streamResults), errors);
				List<RustInputScriptRecord> rustInputScripts = SafeCollect("Scripts de entrada / perfil Rust", () => inputScriptResults, errors);
				List<PeInspectionRecord> peInspections = SafeCollect("Análise PE / entropia / packers", () => peResults.ToList(), errors);
				List<AlternateDataStreamRecord> alternateDataStreams = SafeCollect("Alternate Data Streams", () => streamResults.ToList(), errors);
				WorkerValue("fileInventory", fileInventory);
				WorkerValue("scanDiagnostics", diagnostics);
				ScanReport report = new ScanReport
				{
					AgentVersion = AgentVersion,
					CollectedAtUtc = DateTime.UtcNow,
					Machine = new MachineRecord
					{
						MachineName = Environment.MachineName,
						OsVersion = Environment.OSVersion.VersionString,
						Is64BitOs = Environment.Is64BitOperatingSystem,
						Fingerprint = machineFingerprint
					},
					SteamAccounts = steamAccounts,
					UsbCurrent = usbCurrent,
					UsbHistory = list9,
					UsbTimeline = list10,
					UsbFiles = usbFiles,
					SerialDevices = list11,
					HardwareSummary = hardwareSummaryRecord,
					Processes = list2,
					Prefetch = prefetch,
					PrefetchExecutions = list,
					Services = services,
					Drivers = list3,
					Startup = startup,
					Files = files,
					FileInventory = fileInventory,
					ScanDiagnostics = diagnostics,
					RustInputScripts = rustInputScripts,
					PeInspections = peInspections,
					ZoneIdentifiers = zoneIdentifiers,
					AlternateDataStreams = alternateDataStreams,
					AutorunIntegrity = autorunIntegrity,
					ProcessModuleIntegrity = processModuleIntegrity,
					ProcessMemoryIntegrity = processMemoryIntegrity,
					ProtectedWindows = protectedWindows,
					Bam = list4,
					UserAssist = list5,
					MuiCache = muiCache,
					Pca = list6,
					Amcache = list7,
					ShimCache = list8,
					SetupApiUsb = setupApiUsb,
					PowerShellHits = powerShellHits,
					PowerShellArtifacts = powerShellArtifacts,
					PrefetchIntegrity = prefetchIntegrity,
					HiddenVolumes = hiddenVolumes,
					LogClearSignals = logClearSignals,
					ProcessCreationEvents = processCreationEvents,
					ProcessTerminationEvents = processTerminationEvents,
					DefenderDetections = defenderDetections,
					RecentShortcuts = recentShortcuts,
					CrashArtifacts = crashArtifacts,
					SecurityProducts = securityProducts,
					RecycleBin = recycleBin,
					VmEnvironment = vmEnvironmentRecord,
					BrowserDownloads = browserDownloads,
					BrowserHistorySignals = browserHistorySignals,
					BrowserRecoveredArtifacts = browserRecoveredArtifacts,
					NetworkIndicators = networkIndicators,
					DeletedUsnRecords = deletedUsnRecords,
					ExtensionMismatches = extensionMismatches,
					DefenderExclusions = defenderExclusions,
					BootIntegrity = bootIntegrity,
					ActivityHistory = activityHistory,
					SystemTimeChanges = systemTimeChanges,
					VirtualDisks = virtualDisks,
					RustModules = rustModules,
					UsnJournalState = usnJournalState,
					UsnActivity = usnActivity,
					SystemIntegrityExpansion = systemIntegrityExpansion,
					SystemArtifacts = systemArtifacts,
					Errors = errors
				};
				ReportStatus(AgentLocalization.Pick("Preparando o relatório completo para envio...", "Preparando el informe completo para envío...", "Preparing the complete report for upload..."));
				diagnostics.ModuleSeconds = new Dictionary<string, double>(ModuleSeconds);
				ReportProgress(90, "Enviando relatório ao painel");
				WorkerEmit(new
				{
					kind = "completed",
					report = report
				});
				return new AgentRunResult
				{
					ExitCode = 0
				};
			}
			void AddEvidencePath(string? path)
			{
				if (!string.IsNullOrWhiteSpace(path))
				{
					evidencePaths.Add(path);
				}
			}
		}
		catch (Exception ex5)
		{
			ReportStatus(AgentLocalization.Pick("Falha no Noryx: ", "Error de Noryx: ", "Noryx failure: ") + ex5.Message);
			return new AgentRunResult
			{
				ExitCode = 1,
				Error = ex5.Message
			};
		}
	}

	private static async Task<AgentRunResult> UploadSavedReportAsync(HttpClient http, AgentConfig config, byte[] reportBytes)
	{
		await ReportUploadRetry.SendAsync(http, "api/agent/" + Uri.EscapeDataString(config.Token) + "/report", reportBytes, ReportStatus);
		AgentRecoveryStore.DeleteReport(config.ServerUrl, config.Token);
		ReportProgress(100, "Coleta encerrada e relatório recebido pelo painel. Processamento no servidor.");
		using JsonDocument jsonDocument = JsonDocument.Parse(reportBytes);
		JsonElement value;
		bool collectionIncomplete = !jsonDocument.RootElement.TryGetProperty("errors", out value) || value.GetArrayLength() > 0;
		return new AgentRunResult
		{
			ExitCode = 0,
			Result = null,
			CollectionIncomplete = collectionIncomplete
		};
	}

	internal static async Task<AgentResultSnapshot?> FetchCurrentResultAsync(string[] args)
	{
		AgentConfig agentConfig = LoadConfig(args);
		using HttpClient http = new HttpClient
		{
			BaseAddress = new Uri(agentConfig.ServerUrl.TrimEnd('/') + "/"),
			Timeout = TimeSpan.FromSeconds(30.0)
		};
		using HttpResponseMessage response = await http.GetAsync("api/agent/" + Uri.EscapeDataString(agentConfig.Token) + "/result");
		if (!response.IsSuccessStatusCode)
		{
			return null;
		}
		return await response.Content.ReadFromJsonAsync<AgentResultSnapshot>(JsonOptions);
	}

	private static async Task<AgentResultSnapshot?> WaitForAnalysisResultAsync(HttpClient http, string token)
	{
		using CancellationTokenSource deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60.0));
		while (!deadline.IsCancellationRequested)
		{
			using (CancellationTokenSource requestLimit = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token))
			{
				requestLimit.CancelAfter(TimeSpan.FromSeconds(8.0));
				try
				{
					using HttpResponseMessage response = await http.GetAsync("api/agent/" + Uri.EscapeDataString(token) + "/result", requestLimit.Token);
					if (response.IsSuccessStatusCode)
					{
						AgentResultSnapshot agentResultSnapshot = await response.Content.ReadFromJsonAsync<AgentResultSnapshot>(JsonOptions, requestLimit.Token);
						if (agentResultSnapshot?.Status == "completed")
						{
							return agentResultSnapshot;
						}
					}
				}
				catch (OperationCanceledException)
				{
					if (deadline.IsCancellationRequested)
					{
						break;
					}
				}
				catch (HttpRequestException)
				{
				}
				try
				{
					await Task.Delay(2000, deadline.Token);
				}
				catch (OperationCanceledException)
				{
					goto end_IL_0050;
				}
				continue;
				end_IL_0050:;
			}
			break;
		}
		ReportStatus("Relatório enviado. O processamento continuará no painel.");
		return null;
	}

	private static void ReportStatus(string message)
	{
		try
		{
			_statusSink?.Invoke(message);
		}
		catch
		{
		}
	}

	private static void PrintBanner()
	{
		Console.Clear();
		Console.BackgroundColor = ConsoleColor.Black;
		Console.ForegroundColor = ConsoleColor.Cyan;
		Console.WriteLine("╔══════════════════════════════════════════════════════╗");
		Console.WriteLine("║                                                      ║");
		Console.WriteLine("║              N O R Y X      A N T I C H E A T         ║");
		Console.WriteLine("║                                                      ║");
		Console.WriteLine($"║                    AGENT v{AgentVersion,-8}                 ║");
		Console.WriteLine("╚══════════════════════════════════════════════════════╝");
		Console.ResetColor();
		Console.ForegroundColor = ConsoleColor.DarkGray;
		Console.WriteLine("  Defensive forensic scanner · consent-based inspection");
		Console.ResetColor();
		Console.WriteLine();
	}

	private static void WriteInfo(string value)
	{
		Console.ForegroundColor = ConsoleColor.Cyan;
		Console.Write("  i ");
		Console.ResetColor();
		Console.WriteLine(value);
	}

	private static void WriteSuccess(string value)
	{
		Console.ForegroundColor = ConsoleColor.Green;
		Console.Write("  ✓ ");
		Console.ResetColor();
		Console.WriteLine(value);
	}

	private static void WriteWarning(string value)
	{
		Console.ForegroundColor = ConsoleColor.Yellow;
		Console.Write("  ! ");
		Console.ResetColor();
		Console.WriteLine(value);
	}

	private static void WriteError(string value)
	{
		Console.ForegroundColor = ConsoleColor.Red;
		Console.Write("  ✕ ");
		Console.ResetColor();
		Console.WriteLine(value);
	}

	private static void WriteDim(string value)
	{
		Console.ForegroundColor = ConsoleColor.DarkGray;
		Console.WriteLine(value);
		Console.ResetColor();
	}

	internal static AgentConfig LoadConfig(string[] args)
	{
		string text = null;
		string text2 = null;
		for (int i = 0; i < args.Length; i++)
		{
			if (args[i].Equals("--token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
			{
				text = args[++i];
			}
			else if (args[i].Equals("--server", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
			{
				text2 = args[++i];
			}
		}
		if (string.IsNullOrWhiteSpace(text))
		{
			Match match = Regex.Match(Path.GetFileName(Environment.ProcessPath ?? AppContext.BaseDirectory), "--(?<token>[A-Za-z0-9_-]{20,80})(?: \\(\\d+\\))?\\.exe$", RegexOptions.IgnoreCase);
			if (match.Success)
			{
				text = match.Groups["token"].Value;
				if (text2 == null)
				{
					text2 = "https://noryx-anticheat.shardweb.app";
				}
			}
		}
		string path = Path.Combine(AppContext.BaseDirectory, "noryx-analysis.json");
		if (File.Exists(path))
		{
			AgentConfig agentConfig = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), JsonOptions);
			if (text == null)
			{
				text = agentConfig?.Token;
			}
			if (text2 == null)
			{
				text2 = agentConfig?.ServerUrl;
			}
		}
		if (string.IsNullOrWhiteSpace(text))
		{
			throw new InvalidOperationException("Token da análise ausente. Baixe novamente o Noryx pelo link da análise.");
		}
		if (text2 == null)
		{
			text2 = "https://noryx-anticheat.shardweb.app";
		}
		return new AgentConfig
		{
			Token = text.Trim(),
			ServerUrl = text2.Trim()
		};
	}

	private static async Task<RulesResponse> LoadRulesAsync(HttpClient http, string token)
	{
		using HttpResponseMessage response = await http.GetAsync("api/agent/" + Uri.EscapeDataString(token) + "/rules");
		response.EnsureSuccessStatusCode();
		return (await response.Content.ReadFromJsonAsync<RulesResponse>(JsonOptions)) ?? new RulesResponse();
	}

	private static async Task PostJsonAsync(HttpClient http, string route, object body)
	{
		using HttpResponseMessage httpResponseMessage = await http.PostAsJsonAsync(route, body, JsonOptions);
		httpResponseMessage.EnsureSuccessStatusCode();
	}

	private static List<T> SafeCollect<T>(string moduleName, Func<List<T>> collector, List<string> errors)
	{
		_activeModuleWeight = ((!(moduleName == "Arquivos")) ? 1 : 25);
		ReportModuleProgress(0.0, $"Coleta local: etapa {_completedModules + 1} de {54}");
		ReportStatus("Iniciando módulo: " + moduleName);
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			List<T> list = collector();
			WorkerModule(moduleName, list, errors);
			ReportStatus($"✓ {moduleName}: {list.Count} ({stopwatch.Elapsed.TotalSeconds:0}s)");
			return list;
		}
		catch (Exception ex)
		{
			errors.Add(moduleName + ": " + ex.Message);
			WorkerModule(moduleName, new List<T>(), errors);
			ReportStatus($"! {moduleName}: indisponível ({stopwatch.Elapsed.TotalSeconds:0}s)");
			return new List<T>();
		}
		finally
		{
			ModuleSeconds[moduleName] = stopwatch.Elapsed.TotalSeconds;
			WorkerValue("moduleSeconds", ModuleSeconds);
			_completedModules++;
			_completedUnits += _activeModuleWeight;
			ReportProgress(LocalProgress(), $"Coleta local: {_completedModules} de {54} etapas concluídas");
		}
	}

	private static List<UsbDeviceRecord> CollectCurrentUsbDevices()
	{
		List<UsbDeviceRecord> list = new List<UsbDeviceRecord>();
		using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Model,DeviceID,PNPDeviceID,Manufacturer,Status FROM Win32_DiskDrive WHERE InterfaceType='USB'");
		foreach (ManagementObject item in managementObjectSearcher.Get())
		{
			string pnpDeviceId = Convert.ToString(item["PNPDeviceID"]) ?? "";
			string deviceId = Convert.ToString(item["DeviceID"]) ?? "";
			list.Add(new UsbDeviceRecord
			{
				Name = (Convert.ToString(item["Model"]) ?? "Dispositivo de armazenamento USB"),
				DeviceId = deviceId,
				PnpDeviceId = pnpDeviceId,
				Manufacturer = (Convert.ToString(item["Manufacturer"]) ?? ""),
				Status = (Convert.ToString(item["Status"]) ?? ""),
				Present = true
			});
		}
		return (from x in list.GroupBy<UsbDeviceRecord, string>((UsbDeviceRecord x) => x.PnpDeviceId + "|" + x.DeviceId, StringComparer.OrdinalIgnoreCase)
			select x.First()).ToList();
	}

	private static List<UsbFileRecord> CollectConnectedUsbFiles()
	{
		List<UsbFileRecord> list = new List<UsbFileRecord>();
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			if (driveInfo.DriveType != DriveType.Removable || !driveInfo.IsReady)
			{
				continue;
			}
			string fullName = driveInfo.RootDirectory.FullName;
			System.IO.EnumerationOptions enumerationOptions = new System.IO.EnumerationOptions
			{
				RecurseSubdirectories = true,
				IgnoreInaccessible = true,
				ReturnSpecialDirectories = false,
				AttributesToSkip = FileAttributes.None,
				MaxRecursionDepth = 64
			};
			IEnumerable<string> enumerable;
			try
			{
				enumerable = Directory.EnumerateFiles(fullName, "*", enumerationOptions);
			}
			catch
			{
				continue;
			}
			foreach (string item in enumerable)
			{
				try
				{
					FileInfo fileInfo = new FileInfo(item);
					list.Add(new UsbFileRecord
					{
						Drive = fullName,
						VolumeLabel = (driveInfo.VolumeLabel ?? ""),
						Name = fileInfo.Name,
						Path = fileInfo.FullName,
						RelativePath = Path.GetRelativePath(fullName, fileInfo.FullName),
						Extension = (fileInfo.Extension ?? ""),
						Size = fileInfo.Length,
						CreatedUtc = fileInfo.CreationTimeUtc,
						LastWriteUtc = fileInfo.LastWriteTimeUtc
					});
				}
				catch
				{
				}
			}
		}
		return list.OrderBy<UsbFileRecord, string>((UsbFileRecord x) => x.Drive, StringComparer.OrdinalIgnoreCase).ThenBy<UsbFileRecord, string>((UsbFileRecord x) => x.RelativePath, StringComparer.OrdinalIgnoreCase).ToList();
	}

	private static List<UsbHistoryRecord> CollectUsbHistory(List<UsbDeviceRecord> current)
	{
		List<UsbHistoryRecord> list = new List<UsbHistoryRecord>();
		using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
		if (registryKey == null)
		{
			return list;
		}
		HashSet<string> source = CollectCurrentUsbStorageTokens();
		string[] subKeyNames = registryKey.GetSubKeyNames();
		foreach (string text in subKeyNames)
		{
			using RegistryKey registryKey2 = registryKey.OpenSubKey(text);
			if (registryKey2 == null)
			{
				continue;
			}
			string[] subKeyNames2 = registryKey2.GetSubKeyNames();
			foreach (string text2 in subKeyNames2)
			{
				using RegistryKey registryKey3 = registryKey2.OpenSubKey(text2);
				if (registryKey3 != null)
				{
					string friendlyName = Convert.ToString(registryKey3.GetValue("FriendlyName")) ?? "";
					string deviceDescription = Convert.ToString(registryKey3.GetValue("DeviceDesc")) ?? "";
					string manufacturer = Convert.ToString(registryKey3.GetValue("Mfg")) ?? "";
					string normalizedInstance = NormalizeUsbIdentity(text2);
					string normalizedWithoutSuffix = Regex.Replace(normalizedInstance, "\\d+$", "");
					bool present = source.Any((string token) => (!string.IsNullOrWhiteSpace(normalizedInstance) && token.Contains(normalizedInstance, StringComparison.OrdinalIgnoreCase)) || (normalizedWithoutSuffix.Length >= 6 && token.Contains(normalizedWithoutSuffix, StringComparison.OrdinalIgnoreCase)));
					list.Add(new UsbHistoryRecord
					{
						DeviceClass = text,
						InstanceId = text2,
						FriendlyName = friendlyName,
						DeviceDescription = deviceDescription,
						Manufacturer = manufacturer,
						Present = present
					});
				}
			}
		}
		return list;
	}

	private static HashSet<string> CollectCurrentUsbStorageTokens()
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT PNPDeviceID,DeviceID,Model,SerialNumber,InterfaceType FROM Win32_DiskDrive WHERE InterfaceType='USB'");
			foreach (ManagementObject item in managementObjectSearcher.Get())
			{
				string[] array = new string[4]
				{
					Convert.ToString(item["PNPDeviceID"]),
					Convert.ToString(item["DeviceID"]),
					Convert.ToString(item["Model"]),
					Convert.ToString(item["SerialNumber"])
				};
				for (int i = 0; i < array.Length; i++)
				{
					string text = NormalizeUsbIdentity(array[i]);
					if (text.Length >= 4)
					{
						hashSet.Add(text);
					}
				}
			}
		}
		catch
		{
		}
		return hashSet;
	}

	private static string NormalizeUsbIdentity(string? value)
	{
		return Regex.Replace((value ?? "").ToUpperInvariant(), "[^A-Z0-9]+", "");
	}

	private static List<SerialDeviceRecord> CollectSerialDevices()
	{
		string[] source = new string[17]
		{
			"arduino", "makcu", "moku", "ch340", "ch341", "ch343", "cp210", "ftdi", "usb serial", "usb-serial",
			"serial port", "vid_2341", "vid_2a03", "vid_1a86", "vid_10c4", "vid_0403", "vid_303a"
		};
		List<SerialDeviceRecord> list = new List<SerialDeviceRecord>();
		using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name,DeviceID,PNPDeviceID,Manufacturer,Status,PNPClass,Service FROM Win32_PnPEntity");
		foreach (ManagementObject item in managementObjectSearcher.Get())
		{
			string text = Convert.ToString(item["Name"]) ?? "";
			string text2 = Convert.ToString(item["DeviceID"]) ?? "";
			string text3 = Convert.ToString(item["PNPDeviceID"]) ?? "";
			string text4 = Convert.ToString(item["Manufacturer"]) ?? "";
			string text5 = Convert.ToString(item["PNPClass"]) ?? "";
			string text6 = Convert.ToString(item["Service"]) ?? "";
			string text7 = string.Join(" ", text, text2, text3, text4, text5, text6).ToLowerInvariant();
			bool flag = Regex.IsMatch(text, "\\(COM\\d+\\)", RegexOptions.IgnoreCase);
			bool flag2 = text5.Equals("Ports", StringComparison.OrdinalIgnoreCase);
			if (source.Any(text7.Contains) || flag || flag2)
			{
				list.Add(new SerialDeviceRecord
				{
					Name = text,
					DeviceId = text2,
					PnpDeviceId = text3,
					Manufacturer = text4,
					Status = (Convert.ToString(item["Status"]) ?? ""),
					PnpClass = text5,
					Service = text6
				});
			}
		}
		return (from x in list.GroupBy<SerialDeviceRecord, string>((SerialDeviceRecord x) => x.PnpDeviceId + "|" + x.DeviceId, StringComparer.OrdinalIgnoreCase)
			select x.First()).ToList();
	}

	private static List<PrefetchRecord> CollectPrefetch()
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
		List<PrefetchRecord> list = new List<PrefetchRecord>();
		if (!Directory.Exists(path))
		{
			return list;
		}
		foreach (string item in Directory.EnumerateFiles(path, "*.pf", SearchOption.TopDirectoryOnly))
		{
			try
			{
				FileInfo fileInfo = new FileInfo(item);
				list.Add(new PrefetchRecord
				{
					Name = fileInfo.Name,
					Path = fileInfo.FullName,
					LastWriteUtc = fileInfo.LastWriteTimeUtc,
					Size = fileInfo.Length
				});
			}
			catch
			{
			}
		}
		return list.OrderByDescending((PrefetchRecord x) => x.LastWriteUtc).Take(3000).ToList();
	}

	private static List<FileRecord> CollectCandidateFiles(List<PrefetchRecord> prefetch, List<DetectionRule> rules, List<RustThreatIndicator> catalog, List<string> knownNames, HashSet<string> evidencePaths, List<FileInventoryRecord> inventory, ScanDiagnosticsRecord diagnostics, List<string> errors, HashSet<string> inputScriptPaths, List<RustInputScriptRecord> inputScriptResults, ConcurrentBag<PeInspectionRecord> peResults, ConcurrentBag<AlternateDataStreamRecord> streamResults)
	{
		List<string> roots = new List<string>();
		HashSet<string> rootSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
		AddRoot(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
		AddRoot(Path.GetTempPath());
		string[] array = new string[6] { "LGHUB", "GHUB", "Logitech", "Razer", "SteelSeries", "AutoHotkey" };
		foreach (string path in array)
		{
			AddRoot(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), path));
			AddRoot(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), path));
		}
		AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
		AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
		AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo driveInfo in drives)
		{
			try
			{
				if ((driveInfo.DriveType == DriveType.Fixed || driveInfo.DriveType == DriveType.Removable) && driveInfo.IsReady)
				{
					AddRoot(driveInfo.RootDirectory.FullName);
				}
			}
			catch
			{
				lock (errors)
				{
					errors.Add("Não foi possível consultar a disponibilidade de um volume local.");
				}
			}
		}
		FileSearchCoverage coverage = new FileSearchCoverage();
		string[] extensions = new string[11]
		{
			".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".com", ".scr", ".zip", ".rar",
			".7z"
		};
		ConcurrentBag<FileRecord> files = new ConcurrentBag<FileRecord>();
		HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		HashSet<string> executionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		foreach (PrefetchRecord item in prefetch)
		{
			string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(item.Name);
			int num = fileNameWithoutExtension.LastIndexOf('-');
			if (num > 0)
			{
				executionNames.Add(fileNameWithoutExtension.Substring(0, num));
			}
		}
		string[] catalogNames = (from x in catalog.SelectMany((RustThreatIndicator x) => x.Aliases.Append(x.Name))
			where x.Length >= 4
			select x.ToLowerInvariant()).Distinct().ToArray();
		bool fullHashRules = rules.Any((DetectionRule x) => x.Type == "sha256" || x.Type == "signer_contains");
		HashSet<string> knownFileNames = new HashSet<string>(knownNames, StringComparer.OrdinalIgnoreCase);
		diagnostics.HashRulesRequireAll = fullHashRules;
		diagnostics.CollectionMode = "rust-broad-15m";
		diagnostics.CollectionBudgetSeconds = 900;
		diagnostics.Scope = "Busca ampla de executáveis/scripts em discos fixos e removíveis acessíveis, incluindo AppData. Prioriza rastros de execução e pastas do usuário. EXE, drivers e scripts são selecionados para leitura; DLLs/compactados de instalação sem indicadores podem ficar em metadados. Não segue links/reparse points nem lê documentos pessoais. Pendências, inacessíveis e limites são registrados.";
		string[] installationRoots = new string[3]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.Windows),
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
		};
		int discovered = 0;
		int completed = 0;
		int selected = 0;
		int phase = 0;
		int failed = 0;
		ConcurrentBag<string> pending = new ConcurrentBag<string>();
		List<FileRecord> batch = new List<FileRecord>();
		object batchLock = new object();
		ConcurrentDictionary<string, DateTime?> prefetchByName = new ConcurrentDictionary<string, DateTime?>(StringComparer.OrdinalIgnoreCase);
		Interlocked.Exchange(ref _fileBytesRead, 0L);
		Snapshot();
		using (new System.Threading.Timer(delegate
		{
			int num2 = Volatile.Read(in completed);
			int num3 = Volatile.Read(in selected);
			ReportModuleProgress((Volatile.Read(in phase) == 0) ? 0.1 : (0.2 + 0.8 * ((num3 == 0) ? 1.0 : ((double)num2 / (double)num3))), $"Busca ampla: {Volatile.Read(in discovered):N0} arquivos técnicos; {num2:N0}/{num3:N0} leituras concluídas");
		}, null, 0, 1000))
		{
			try
			{
				BoundedInspectionQueue.Run(Discover(), () => new FileInspectionWorkerClient(), delegate(FileInspectionWorkerClient worker, FileInventoryRecord entry)
				{
					FileRecord fileRecord = worker.Inspect(entry.Path);
					if (fileRecord.Sha256 == null)
					{
						lock (errors)
						{
							if (!errors.Contains("Hash de candidato selecionado incompleto."))
							{
								errors.Add("Hash de candidato selecionado incompleto.");
							}
						}
					}
					fileRecord.PrefetchEvidenceUtc = prefetchByName.GetOrAdd(fileRecord.Name, (string name) => FindPrefetchEvidence(name, prefetch));
					files.Add(fileRecord);
					lock (batchLock)
					{
						batch.Add(fileRecord);
						if (batch.Count >= 1)
						{
							WorkerAppend("files", batch.ToArray());
							batch.Clear();
						}
					}
					List<FileRecord> files2 = new List<FileRecord> { fileRecord };
					List<PeInspectionRecord> list = PeInspectionCollector.Collect(files2);
					foreach (PeInspectionRecord item2 in list)
					{
						peResults.Add(item2);
					}
					if (list.Count > 0)
					{
						WorkerAppend("peInspections", list);
					}
					List<AlternateDataStreamRecord> list2 = AlternateDataStreamCollector.Collect(files2);
					foreach (AlternateDataStreamRecord item3 in list2)
					{
						streamResults.Add(item3);
					}
					if (list2.Count > 0)
					{
						WorkerAppend("alternateDataStreams", list2);
					}
					Interlocked.Increment(ref completed);
					if (completed % 20 == 0)
					{
						Snapshot();
					}
				}, delegate(FileInventoryRecord entry, Exception error)
				{
					Interlocked.Increment(ref failed);
					Interlocked.Increment(ref completed);
					entry.AnalysisError = error.Message;
					pending.Add(entry.Path + " · " + error.Message);
					Snapshot();
				});
			}
			finally
			{
				lock (batchLock)
				{
					if (batch.Count > 0)
					{
						WorkerAppend("files", batch.ToArray());
					}
				}
				Snapshot();
			}
			if (coverage.Inaccessible > 0 || failed > 0)
			{
				errors.Add($"Busca ampla incompleta: {coverage.Inaccessible} entradas inacessíveis e {failed} candidatos não lidos.");
			}
			return files.ToList();
		}
		void AddRoot(string? value)
		{
			if (!string.IsNullOrWhiteSpace(value) && Directory.Exists(value) && rootSet.Add(value))
			{
				roots.Add(value);
			}
		}
		IEnumerable<FileInventoryRecord> Discover()
		{
			IEnumerable<string> enumerable = evidencePaths.Where((string path2) => !IsInstalled(path2)).Concat(evidencePaths.Where(IsInstalled)).Concat(roots.SelectMany((string root) => EvidenceFileWalker.Enumerate(root, coverage)));
			foreach (string item4 in enumerable)
			{
				string extension = Path.GetExtension(item4);
				if ((extension.Equals(".lua", StringComparison.OrdinalIgnoreCase) || extension.Equals(".ahk", StringComparison.OrdinalIgnoreCase)) && inputScriptPaths.Add(item4))
				{
					List<RustInputScriptRecord> list;
					lock (errors)
					{
						list = RustInputScriptCollector.Collect(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { item4 }, errors);
					}
					inputScriptResults.AddRange(list);
					if (list.Count > 0)
					{
						WorkerAppend("rustInputScripts", list);
					}
				}
				if (extensions.Contains<string>(extension, StringComparer.OrdinalIgnoreCase) && seen.Add(item4))
				{
					FileInventoryRecord fileInventoryRecord = null;
					try
					{
						FileInfo info = new FileInfo(item4);
						if (!info.Exists)
						{
							Interlocked.Increment(ref failed);
							continue;
						}
						bool flag = IsInstalled(info.FullName);
						new string[3] { ".zip", ".rar", ".7z" }.Contains<string>(extension, StringComparer.OrdinalIgnoreCase);
						bool flag2 = new string[7] { ".exe", ".com", ".scr", ".sys", ".bat", ".cmd", ".ps1" }.Contains<string>(extension, StringComparer.OrdinalIgnoreCase);
						string text = (fullHashRules ? "Regra global de hash/assinatura" : (knownFileNames.Contains(info.Name) ? "Catálogo conhecido" : ((evidencePaths.Contains(info.FullName) || executionNames.Contains(info.Name)) ? "Rastro de execução ou carregamento" : (rules.Any((DetectionRule rule) => rule.Type != "sha256" && RuleHintsFile(rule, info.Name, info.FullName)) ? "Regra de nome/caminho" : (catalogNames.Any((string name) => info.Name.Contains(name, StringComparison.OrdinalIgnoreCase)) ? "Indicador do catálogo" : (flag2 ? "Executável, driver ou script na busca ampla" : ((!flag) ? "Arquivo técnico fora das pastas de instalação" : (LooksRandomFileName(info.Name) ? "Nome incomum" : "Somente inventário; sem critério de leitura profunda"))))))));
						fileInventoryRecord = new FileInventoryRecord
						{
							Name = info.Name,
							Path = info.FullName,
							Size = info.Length,
							LastWriteUtc = SafeDate(info.LastWriteTimeUtc),
							DeepSelected = (text != "Somente inventário; sem critério de leitura profunda"),
							SelectionReason = text
						};
						inventory.Add(fileInventoryRecord);
						Interlocked.Increment(ref discovered);
						if (fileInventoryRecord.DeepSelected)
						{
							Interlocked.Increment(ref selected);
						}
					}
					catch
					{
						Interlocked.Increment(ref failed);
					}
					if (discovered % 100 == 0)
					{
						Snapshot();
					}
					if (fileInventoryRecord != null && fileInventoryRecord.DeepSelected)
					{
						yield return fileInventoryRecord;
					}
				}
			}
			Volatile.Write(ref phase, 1);
		}
		bool IsInstalled(string text)
		{
			return installationRoots.Any((string folder) => !string.IsNullOrEmpty(folder) && text.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
		}
		void Snapshot()
		{
			diagnostics.InventoryCount = Volatile.Read(in discovered);
			diagnostics.DeepSelectedCount = Volatile.Read(in selected);
			diagnostics.DeepCompletedCount = files.Count;
			diagnostics.MetadataOnlyCount = Math.Max(0, diagnostics.InventoryCount - diagnostics.DeepSelectedCount);
			diagnostics.DirectoriesVisited = coverage.DirectoriesVisited;
			diagnostics.InaccessibleEntries = coverage.Inaccessible;
			diagnostics.ReparsePointsSkipped = coverage.ReparsePointsSkipped;
			diagnostics.FailedCandidates = Volatile.Read(in failed);
			diagnostics.PendingFiles = pending.Take(20).ToList();
			WorkerValue("scanDiagnostics", diagnostics);
			lock (errors)
			{
				WorkerValue("errors", errors.ToArray());
			}
		}
	}

	private static bool RuleHintsFile(DetectionRule rule, string name, string fullPath)
	{
		string value = (rule.Pattern ?? "").Trim();
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}
		return rule.Type switch
		{
			"filename_contains" => name.Contains(value, StringComparison.OrdinalIgnoreCase), 
			"path_contains" => fullPath.Contains(value, StringComparison.OrdinalIgnoreCase), 
			"sha256" => true, 
			_ => false, 
		};
	}

	private static IEnumerable<string> EnumerateFilesLimited(string root, int depth, int maxFiles)
	{
		Queue<(string Path, int Depth)> queue = new Queue<(string, int)>();
		queue.Enqueue((root, 0));
		int yielded = 0;
		while (queue.Count > 0 && yielded < maxFiles)
		{
			var (current, currentDepth) = queue.Dequeue();
			IEnumerable<string> enumerable;
			try
			{
				enumerable = Directory.EnumerateFiles(current);
			}
			catch
			{
				continue;
			}
			foreach (string item in enumerable)
			{
				yield return item;
				yielded++;
				if (yielded >= maxFiles)
				{
					yield break;
				}
			}
			if (currentDepth >= depth)
			{
				continue;
			}
			IEnumerable<string> source;
			try
			{
				source = Directory.EnumerateDirectories(current);
			}
			catch
			{
				continue;
			}
			foreach (string item2 in source.Take(150))
			{
				queue.Enqueue((item2, currentDepth + 1));
			}
		}
	}

	private static DateTime? FindPrefetchEvidence(string fileName, List<PrefetchRecord> prefetch)
	{
		string executable = Path.GetFileNameWithoutExtension(fileName);
		return ((IEnumerable<PrefetchRecord>)(from x in prefetch
			where x.Name.StartsWith(fileName + "-", StringComparison.OrdinalIgnoreCase) || x.Name.StartsWith(executable + "-", StringComparison.OrdinalIgnoreCase)
			orderby x.LastWriteUtc descending
			select x)).Select((Func<PrefetchRecord, DateTime?>)((PrefetchRecord x) => x.LastWriteUtc)).FirstOrDefault();
	}

	private static List<ProcessRecord> CollectProcesses()
	{
		List<ProcessRecord> list = new List<ProcessRecord>();
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		Process[] processes = Process.GetProcesses();
		foreach (Process process in processes)
		{
			try
			{
				string text = process.MainModule?.FileName;
				string value = null;
				bool signed = false;
				string signerSubject = null;
				if (!string.IsNullOrWhiteSpace(text) && File.Exists(text))
				{
					if (!dictionary.TryGetValue(text, out value))
					{
						value = (dictionary[text] = ((new FileInfo(text).Length <= 262144000) ? TrySha256(text) : null));
					}
					(signed, signerSubject) = TrySigner(text);
				}
				list.Add(new ProcessRecord
				{
					Pid = process.Id,
					Name = process.ProcessName,
					Path = text,
					Sha256 = value,
					Signed = signed,
					SignerSubject = signerSubject,
					StartTimeUtc = TryGetStartTime(process)
				});
			}
			catch
			{
				list.Add(new ProcessRecord
				{
					Pid = process.Id,
					Name = process.ProcessName
				});
			}
			finally
			{
				process.Dispose();
			}
		}
		return list;
	}

	private static List<ServiceRecord> CollectServices()
	{
		List<ServiceRecord> list = new List<ServiceRecord>();
		using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service");
		foreach (ManagementObject item in managementObjectSearcher.Get())
		{
			list.Add(new ServiceRecord
			{
				Name = (Convert.ToString(item["Name"]) ?? ""),
				DisplayName = (Convert.ToString(item["DisplayName"]) ?? ""),
				State = (Convert.ToString(item["State"]) ?? ""),
				StartMode = (Convert.ToString(item["StartMode"]) ?? ""),
				PathName = (Convert.ToString(item["PathName"]) ?? "")
			});
		}
		return list;
	}

	private static List<DriverRecord> CollectDrivers()
	{
		List<DriverRecord> list = new List<DriverRecord>();
		using ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_SystemDriver");
		foreach (ManagementObject item in managementObjectSearcher.Get())
		{
			string text = Convert.ToString(item["PathName"]) ?? "";
			string text2 = ResolveDriverPath(text);
			string sha = null;
			bool signed = false;
			string signerSubject = null;
			if (!string.IsNullOrWhiteSpace(text2) && File.Exists(text2))
			{
				try
				{
					if (new FileInfo(text2).Length <= 67108864)
					{
						sha = TrySha256(text2);
					}
				}
				catch
				{
				}
				(signed, signerSubject) = TrySigner(text2);
			}
			list.Add(new DriverRecord
			{
				Name = (Convert.ToString(item["Name"]) ?? ""),
				DisplayName = (Convert.ToString(item["DisplayName"]) ?? ""),
				State = (Convert.ToString(item["State"]) ?? ""),
				StartMode = (Convert.ToString(item["StartMode"]) ?? ""),
				PathName = text,
				ResolvedPath = text2,
				Sha256 = sha,
				Signed = signed,
				SignerSubject = signerSubject
			});
		}
		return list;
	}

	private static string ResolveDriverPath(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return "";
		}
		string text = value.Trim().Trim('"');
		int num = text.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
		if (num >= 0)
		{
			text = text.Substring(0, num + 4);
		}
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		if (text.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
		{
			string text2 = text;
			int length = "\\SystemRoot\\".Length;
			text = Path.Combine(folderPath, text2.Substring(length, text2.Length - length));
		}
		else if (text.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
		{
			string text2 = text;
			text = text2.Substring(4, text2.Length - 4);
		}
		else if (text.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase))
		{
			text = Path.Combine(folderPath, text);
		}
		try
		{
			return Path.GetFullPath(Environment.ExpandEnvironmentVariables(text));
		}
		catch
		{
			return text;
		}
	}

	private static List<StartupRecord> CollectStartupEntries()
	{
		List<StartupRecord> list = new List<StartupRecord>();
		CollectRunKey(Registry.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run", list);
		CollectRunKey(Registry.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce", list);
		CollectRunKey(Registry.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run", list);
		CollectRunKey(Registry.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce", list);
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
		if (Directory.Exists(folderPath))
		{
			foreach (string item in Directory.EnumerateFiles(folderPath))
			{
				list.Add(new StartupRecord
				{
					Source = "Startup folder",
					Name = Path.GetFileName(item),
					Command = item
				});
			}
		}
		return list;
	}

	private static void CollectRunKey(RegistryKey hive, string subKey, string source, List<StartupRecord> result)
	{
		using RegistryKey registryKey = hive.OpenSubKey(subKey);
		if (registryKey != null)
		{
			string[] valueNames = registryKey.GetValueNames();
			foreach (string name in valueNames)
			{
				result.Add(new StartupRecord
				{
					Source = source,
					Name = name,
					Command = (Convert.ToString(registryKey.GetValue(name)) ?? "")
				});
			}
		}
	}

	private static string? TrySha256(string path)
	{
		try
		{
			FileInfo fileInfo = new FileInfo(path);
			string fullName = fileInfo.FullName;
			long length = fileInfo.Length;
			long ticks = fileInfo.LastWriteTimeUtc.Ticks;
			long ticks2 = fileInfo.CreationTimeUtc.Ticks;
			if (ScanHashes.TryGetValue(fullName, out (long, long, long, string) value) && value.Item1 == length && value.Item2 == ticks && value.Item3 == ticks2)
			{
				return value.Item4;
			}
			using FileStream fileStream = new FileStream(fullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 131072, FileOptions.SequentialScan);
			using IncrementalHash incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
			byte[] array = ArrayPool<byte>.Shared.Rent(131072);
			string text;
			try
			{
				int num;
				while ((num = fileStream.Read(array, 0, array.Length)) > 0)
				{
					incrementalHash.AppendData(array, 0, num);
					long obj = Interlocked.Add(ref _fileBytesRead, num);
					_fileWorkerHashProgress?.Invoke(obj);
				}
				text = Convert.ToHexString(incrementalHash.GetHashAndReset()).ToLowerInvariant();
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(array);
			}
			fileInfo.Refresh();
			if (!fileInfo.Exists || fileInfo.Length != length || fileInfo.LastWriteTimeUtc.Ticks != ticks || fileInfo.CreationTimeUtc.Ticks != ticks2)
			{
				ScanHashes.TryRemove(fullName, out (long, long, long, string) _);
				return null;
			}
			ScanHashes[fullName] = (length, ticks, ticks2, text);
			return text;
		}
		catch
		{
			return null;
		}
	}

	private static bool LooksRandomFileName(string fileName)
	{
		return ExecutableNameSignals.LooksRandomFileName(fileName);
	}

	private static List<string> TryListZipEntries(string path)
	{
		List<string> list = new List<string>();
		try
		{
			using ZipArchive zipArchive = ZipFile.OpenRead(path);
			foreach (ZipArchiveEntry item in zipArchive.Entries.Take(400))
			{
				string text = item.FullName?.Trim() ?? "";
				if (!string.IsNullOrWhiteSpace(text))
				{
					list.Add(text);
				}
			}
		}
		catch
		{
		}
		return list;
	}

	private static DateTime? TryPeCompileTimeUtc(string path)
	{
		try
		{
			using FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
			if (fileStream.Length < 256)
			{
				return null;
			}
			using BinaryReader binaryReader = new BinaryReader(fileStream);
			if (binaryReader.ReadUInt16() != 23117)
			{
				return null;
			}
			fileStream.Position = 60L;
			int num = binaryReader.ReadInt32();
			if (num <= 0 || num + 12 > fileStream.Length)
			{
				return null;
			}
			fileStream.Position = num;
			if (binaryReader.ReadUInt32() != 17744)
			{
				return null;
			}
			binaryReader.ReadUInt16();
			binaryReader.ReadUInt16();
			uint num2 = binaryReader.ReadUInt32();
			if (num2 == 0)
			{
				return null;
			}
			DateTime utcDateTime = DateTimeOffset.FromUnixTimeSeconds(num2).UtcDateTime;
			if (utcDateTime.Year < 1990 || utcDateTime > DateTime.UtcNow.AddYears(2))
			{
				return null;
			}
			return utcDateTime;
		}
		catch
		{
			return null;
		}
	}

	private static (bool Signed, string? Subject) TrySigner(string path)
	{
		var (item, text) = AuthenticodeVerifier.Verify(path);
		return (Signed: item, Subject: string.IsNullOrWhiteSpace(text) ? null : text);
	}

	private static DateTime? TryGetStartTime(Process process)
	{
		try
		{
			return process.StartTime.ToUniversalTime();
		}
		catch
		{
			return null;
		}
	}

	private static DateTime? SafeDate(DateTime value)
	{
		if (value.Year < 1980 || value.Year > 9998)
		{
			return null;
		}
		return value;
	}

	private static string GetDriveType(string filePath)
	{
		try
		{
			string pathRoot = Path.GetPathRoot(filePath);
			if (string.IsNullOrWhiteSpace(pathRoot))
			{
				return "Unknown";
			}
			return new DriveInfo(pathRoot).DriveType.ToString();
		}
		catch
		{
			return "Unknown";
		}
	}
}
