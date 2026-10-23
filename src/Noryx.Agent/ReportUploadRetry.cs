using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Noryx.Agent;

internal static class ReportUploadRetry
{
	internal static bool Retryable(HttpStatusCode code)
	{
		if (code >= HttpStatusCode.InternalServerError || code == HttpStatusCode.RequestTimeout || code == HttpStatusCode.TooManyRequests)
		{
			return true;
		}
		return false;
	}

	internal static async Task SendAsync(HttpClient http, string route, byte[] json, Action<string> progress, TimeSpan? retryWindow = null, Func<TimeSpan, Task>? pause = null)
	{
		using MemoryStream memory = new MemoryStream();
		using (GZipStream gzip = new GZipStream(memory, CompressionLevel.Fastest, leaveOpen: true))
		{
			await gzip.WriteAsync(json);
		}
		byte[] compressed = memory.ToArray();
		using CancellationTokenSource window = new CancellationTokenSource(retryWindow ?? TimeSpan.FromSeconds(30.0));
		Stopwatch deadline = Stopwatch.StartNew();
		int attempt = 0;
		while (true)
		{
			attempt++;
			try
			{
				using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, route);
				request.Content = new ByteArrayContent(compressed);
				request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
				request.Content.Headers.ContentEncoding.Add("gzip");
				using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(window.Token);
				timeout.CancelAfter(TimeSpan.FromSeconds(30.0));
				using HttpResponseMessage httpResponseMessage = await http.SendAsync(request, timeout.Token);
				if (httpResponseMessage.IsSuccessStatusCode)
				{
					return;
				}
				if (!Retryable(httpResponseMessage.StatusCode))
				{
					throw new InvalidOperationException("Envio recusado (HTTP " + (int)httpResponseMessage.StatusCode + "). O relatório continua salvo; solicite revisão à equipe.");
				}
			}
			catch (HttpRequestException)
			{
			}
			catch (OperationCanceledException)
			{
			}
			if (window.IsCancellationRequested || deadline.Elapsed >= (retryWindow ?? TimeSpan.FromSeconds(30.0)))
			{
				break;
			}
			progress("Coleta concluída. Aguardando o painel e reenviando o relatório salvo · tentativa " + attempt + ". Não há nova varredura.");
			try
			{
				await (pause ?? new Func<TimeSpan, Task>(Task.Delay))(TimeSpan.FromSeconds(Math.Min(10, attempt * 3))).WaitAsync(window.Token);
			}
			catch (OperationCanceledException)
			{
				throw new IOException("Painel indisponível. Relatório salvo; use o mesmo código para reenviar sem nova coleta.");
			}
		}
		throw new IOException("Painel indisponível. Relatório salvo neste Windows. Abra o EXE e use o mesmo código para reenviar sem repetir a coleta.");
	}
}
