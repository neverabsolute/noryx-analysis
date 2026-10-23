using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Noryx.Agent;

internal sealed class RemoteSupportClient : IAsyncDisposable
{
	private sealed class AdminsResponse
	{
		public List<RemoteAdministrator> Admins { get; set; } = new List<RemoteAdministrator>();
	}

	private sealed class CreateSessionResponse
	{
		public string SessionId { get; set; } = "";

		public string AgentSecret { get; set; } = "";

		public string WebSocketUrl { get; set; } = "";

		public DateTimeOffset ExpiresAt { get; set; }
	}

	private sealed class SessionState
	{
		public string Status { get; set; } = "";
	}

	private sealed class InputEventsResponse
	{
		public List<InputEvent> Events { get; set; } = new List<InputEvent>();
	}

	private sealed class InputEvent
	{
		public long Sequence { get; set; }

		public JsonElement Event { get; set; }
	}

	private readonly AgentConfig _config;

	private readonly HttpClient _http;

	private readonly CancellationTokenSource _lifetime = new CancellationTokenSource();

	private ClientWebSocket? _socket;

	private string? _sessionId;

	private bool _controlEnabled;

	private volatile int _selectedMonitorIndex;

	public bool IsActive { get; private set; }

	public RemoteSupportClient(AgentConfig config)
	{
		_config = config;
		_http = new HttpClient
		{
			BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
			Timeout = TimeSpan.FromSeconds(30.0)
		};
	}

	public async Task<List<RemoteAdministrator>> GetAvailableAdminsAsync(CancellationToken cancellationToken = default(CancellationToken))
	{
		return (await _http.GetFromJsonAsync<AdminsResponse>("api/agent/" + Uri.EscapeDataString(_config.Token) + "/remote/admins", cancellationToken))?.Admins ?? new List<RemoteAdministrator>();
	}

	public async Task RunAsync(long adminId, string mode, Action<string> status, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (IsActive)
		{
			throw new InvalidOperationException("Já existe uma transmissão ativa.");
		}
		using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
		HttpResponseMessage obj = await _http.PostAsJsonAsync("api/agent/" + Uri.EscapeDataString(_config.Token) + "/remote/sessions", new { adminId, mode }, linked.Token);
		obj.EnsureSuccessStatusCode();
		CreateSessionResponse created = (await obj.Content.ReadFromJsonAsync<CreateSessionResponse>(linked.Token)) ?? throw new InvalidOperationException("Resposta inválida do servidor.");
		_sessionId = created.SessionId;
		_controlEnabled = mode == "control";
		status("Solicitação enviada. Aguardando o administrador aceitar...");
		while (!linked.IsCancellationRequested)
		{
			await Task.Delay(1200, linked.Token);
			SessionState sessionState = await _http.GetFromJsonAsync<SessionState>("api/agent/" + Uri.EscapeDataString(_config.Token) + "/remote/sessions/" + Uri.EscapeDataString(created.SessionId), linked.Token);
			if (sessionState?.Status == "accepted")
			{
				break;
			}
			string text = sessionState?.Status;
			if ((text == "rejected" || text == "ended") ? true : false)
			{
				throw new InvalidOperationException("O administrador recusou ou encerrou a solicitação.");
			}
			if (sessionState == null || DateTimeOffset.UtcNow >= created.ExpiresAt)
			{
				throw new TimeoutException("A solicitação expirou sem resposta.");
			}
		}
		IsActive = true;
		try
		{
			await PublishMonitorInfoAsync(created, linked.Token);
			int num = 0;
			try
			{
				_socket = new ClientWebSocket();
				await _socket.ConnectAsync(new Uri(created.WebSocketUrl), linked.Token);
				await SendTextAsync(JsonSerializer.Serialize(new
				{
					type = "authenticate",
					role = "agent",
					sessionId = created.SessionId,
					secret = created.AgentSecret
				}), linked.Token);
				status(_controlEnabled ? "TELA + CONTROLE ativos. Clique em PARAR a qualquer momento." : "TRANSMISSÃO DE TELA ativa. Clique em PARAR a qualquer momento.");
				Task task = ReceiveControlsAsync(linked.Token);
				Task task2 = CaptureLoopAsync(linked.Token);
				await (await Task.WhenAny(task, task2));
			}
			catch (Exception ex) when (((ex is WebSocketException || ex is HttpRequestException || ex is InvalidOperationException) ? true : false) && !linked.IsCancellationRequested)
			{
				num = 1;
			}
			if (num == 1)
			{
				_socket?.Dispose();
				_socket = null;
				status(_controlEnabled ? "TELA + CONTROLE ativos pelo modo HTTPS compatível." : "TRANSMISSÃO DE TELA ativa pelo modo HTTPS compatível.");
				Task task3 = PollHttpControlsAsync(created, linked.Token);
				Task task4 = CaptureHttpLoopAsync(created, linked.Token);
				await (await Task.WhenAny(task3, task4));
			}
		}
		catch (OperationCanceledException) when (linked.IsCancellationRequested)
		{
		}
		finally
		{
			IsActive = false;
			status("Transmissão encerrada.");
		}
	}

	public async Task StopAsync()
	{
		string id = _sessionId;
		_lifetime.Cancel();
		ClientWebSocket socket = _socket;
		if (socket != null && socket.State == WebSocketState.Open)
		{
			try
			{
				await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Encerrada pelo jogador", CancellationToken.None);
			}
			catch
			{
			}
		}
		if (!string.IsNullOrWhiteSpace(id))
		{
			try
			{
				await _http.PostAsync($"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(id)}/end", null);
			}
			catch
			{
			}
		}
		IsActive = false;
	}

	private async Task CaptureLoopAsync(CancellationToken cancellationToken)
	{
		while (!cancellationToken.IsCancellationRequested)
		{
			ClientWebSocket? socket = _socket;
			if (socket != null && socket.State == WebSocketState.Open)
			{
				byte[] array = CaptureJpeg();
				await _socket.SendAsync(array, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken);
				await Task.Delay(240, cancellationToken);
				continue;
			}
			break;
		}
	}

	private async Task CaptureHttpLoopAsync(CreateSessionResponse session, CancellationToken cancellationToken)
	{
		string path = $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(session.SessionId)}/frame";
		while (!cancellationToken.IsCancellationRequested)
		{
			byte[] content = CaptureJpeg();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, path);
			request.Headers.Add("X-Noryx-Session-Secret", session.AgentSecret);
			request.Content = new ByteArrayContent(content);
			request.Content.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");
			using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);
			response.EnsureSuccessStatusCode();
			await Task.Delay(280, cancellationToken);
		}
	}

	private async Task PollHttpControlsAsync(CreateSessionResponse session, CancellationToken cancellationToken)
	{
		long sequence = 0L;
		string basePath = $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(session.SessionId)}/input";
		while (!cancellationToken.IsCancellationRequested)
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"{basePath}?after={sequence}");
			request.Headers.Add("X-Noryx-Session-Secret", session.AgentSecret);
			using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);
			response.EnsureSuccessStatusCode();
			foreach (InputEvent item in (await response.Content.ReadFromJsonAsync<InputEventsResponse>(cancellationToken))?.Events ?? new List<InputEvent>())
			{
				sequence = Math.Max(sequence, item.Sequence);
				ApplyRemoteEvent(item.Event);
			}
			await Task.Delay(90, cancellationToken);
		}
	}

	private byte[] CaptureJpeg()
	{
		Screen[] allScreens = Screen.AllScreens;
		int num = Math.Clamp(_selectedMonitorIndex, 0, Math.Max(0, allScreens.Length - 1));
		Rectangle rectangle = ((allScreens.Length != 0) ? allScreens[num].Bounds : SystemInformation.VirtualScreen);
		int num2 = Math.Min(1280, rectangle.Width);
		int num3 = Math.Max(1, (int)Math.Round((double)rectangle.Height * ((double)num2 / (double)rectangle.Width)));
		using Bitmap bitmap = new Bitmap(num2, num3, PixelFormat.Format24bppRgb);
		using (Graphics graphics = Graphics.FromImage(bitmap))
		{
			nint dC = GetDC(IntPtr.Zero);
			nint hdc = graphics.GetHdc();
			try
			{
				SetStretchBltMode(hdc, 4);
				StretchBlt(hdc, 0, 0, num2, num3, dC, rectangle.Left, rectangle.Top, rectangle.Width, rectangle.Height, 1087111200u);
			}
			finally
			{
				graphics.ReleaseHdc(hdc);
				ReleaseDC(IntPtr.Zero, dC);
			}
		}
		using MemoryStream memoryStream = new MemoryStream();
		ImageCodecInfo encoder = ImageCodecInfo.GetImageEncoders().First((ImageCodecInfo x) => x.MimeType == "image/jpeg");
		using EncoderParameters encoderParameters = new EncoderParameters(1);
		encoderParameters.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 55L);
		bitmap.Save(memoryStream, encoder, encoderParameters);
		return memoryStream.ToArray();
	}

	private async Task ReceiveControlsAsync(CancellationToken cancellationToken)
	{
		if (_socket == null)
		{
			return;
		}
		byte[] buffer = new byte[16384];
		while (!cancellationToken.IsCancellationRequested && _socket.State == WebSocketState.Open)
		{
			WebSocketReceiveResult webSocketReceiveResult = await _socket.ReceiveAsync(buffer, cancellationToken);
			if (webSocketReceiveResult.MessageType == WebSocketMessageType.Close)
			{
				break;
			}
			if (webSocketReceiveResult.MessageType != WebSocketMessageType.Text)
			{
				continue;
			}
			try
			{
				using JsonDocument jsonDocument = JsonDocument.Parse(buffer.AsMemory(0, webSocketReceiveResult.Count));
				ApplyRemoteEvent(jsonDocument.RootElement);
			}
			catch
			{
			}
		}
	}

	private Task SendTextAsync(string text, CancellationToken cancellationToken)
	{
		return _socket.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
	}

	private void ApplyRemoteEvent(JsonElement message)
	{
		if ((message.TryGetProperty("type", out var value) ? (value.GetString() ?? "") : "") == "monitor" && message.TryGetProperty("index", out var value2))
		{
			Screen[] allScreens = Screen.AllScreens;
			_selectedMonitorIndex = Math.Clamp(value2.GetInt32(), 0, Math.Max(0, allScreens.Length - 1));
		}
		else if (_controlEnabled)
		{
			RemoteInput.Apply(message, _selectedMonitorIndex);
		}
	}

	private async Task PublishMonitorInfoAsync(CreateSessionResponse session, CancellationToken cancellationToken)
	{
		var monitors = Screen.AllScreens.Select((Screen screen, int index) => new
		{
			index = index,
			name = (string.IsNullOrWhiteSpace(screen.DeviceName) ? $"Monitor {index + 1}" : screen.DeviceName),
			width = screen.Bounds.Width,
			height = screen.Bounds.Height,
			primary = screen.Primary
		}).ToArray();
		bool elevated;
		try
		{
			using WindowsIdentity ntIdentity = WindowsIdentity.GetCurrent();
			elevated = new WindowsPrincipal(ntIdentity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			elevated = false;
		}
		using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"api/agent/{Uri.EscapeDataString(_config.Token)}/remote/sessions/{Uri.EscapeDataString(session.SessionId)}/monitors");
		request.Headers.Add("X-Noryx-Session-Secret", session.AgentSecret);
		request.Content = JsonContent.Create(new
		{
			monitors = monitors,
			selectedIndex = _selectedMonitorIndex,
			elevated = elevated
		});
		using HttpResponseMessage httpResponseMessage = await _http.SendAsync(request, cancellationToken);
		httpResponseMessage.EnsureSuccessStatusCode();
	}

	[DllImport("user32.dll")]
	private static extern nint GetDC(nint window);

	[DllImport("user32.dll")]
	private static extern int ReleaseDC(nint window, nint deviceContext);

	[DllImport("gdi32.dll")]
	private static extern int SetStretchBltMode(nint deviceContext, int mode);

	[DllImport("gdi32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool StretchBlt(nint destination, int xDestination, int yDestination, int destinationWidth, int destinationHeight, nint source, int xSource, int ySource, int sourceWidth, int sourceHeight, uint rasterOperation);

	public async ValueTask DisposeAsync()
	{
		await StopAsync();
		_socket?.Dispose();
		_http.Dispose();
		_lifetime.Dispose();
	}
}
