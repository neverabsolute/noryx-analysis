using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Noryx.Agent;

internal static class CollectionProcessRunner
{
	internal const string Prefix = "NORYX_COLLECTION:";

	internal static async Task<CollectionProcessOutcome> RunAsync(ProcessStartInfo start, string input, TimeSpan budget, Action<JsonElement> receive)
	{
		using CancellationTokenSource deadline = new CancellationTokenSource(budget);
		using Process child = Process.Start(start) ?? throw new IOException("Não foi possível iniciar a coleta isolada.");
		child.ErrorDataReceived += delegate
		{
		};
		child.BeginErrorReadLine();
		bool completed = false;
		CollectionProcessOutcome result;
		try
		{
			_ = 2;
			try
			{
				await child.StandardInput.WriteLineAsync(input);
				child.StandardInput.Close();
				while (true)
				{
					string text = await child.StandardOutput.ReadLineAsync().WaitAsync(deadline.Token);
					if (text == null)
					{
						break;
					}
					if (!text.StartsWith("NORYX_COLLECTION:", StringComparison.Ordinal))
					{
						continue;
					}
					using JsonDocument jsonDocument = JsonDocument.Parse(text.Substring("NORYX_COLLECTION:".Length));
					JsonElement rootElement = jsonDocument.RootElement;
					receive(rootElement);
					if (rootElement.GetProperty("kind").GetString() == "completed")
					{
						completed = true;
						break;
					}
				}
				if (!completed)
				{
					await child.WaitForExitAsync(deadline.Token);
				}
				result = new CollectionProcessOutcome(DeadlineReached: false, completed, child.HasExited ? child.ExitCode : 0);
			}
			catch (OperationCanceledException) when (deadline.IsCancellationRequested)
			{
				result = new CollectionProcessOutcome(DeadlineReached: true, Completed: false, -1);
			}
		}
		finally
		{
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
				await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3.0));
			}
			catch
			{
			}
		}
		return result;
	}
}
