using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Noryx.Agent;

internal sealed class AgentMainForm : Form
{
	private static readonly Color Background = Color.FromArgb(8, 12, 20);

	private static readonly Color Surface = Color.FromArgb(15, 23, 36);

	private static readonly Color Accent = Color.FromArgb(55, 139, 255);

	private static readonly Color Primary = Color.FromArgb(238, 244, 253);

	private static readonly Color Muted = Color.FromArgb(145, 163, 188);

	private readonly Panel _stage = new Panel
	{
		Dock = DockStyle.Fill,
		BackColor = Background
	};

	private readonly System.Windows.Forms.Timer _clock = new System.Windows.Forms.Timer
	{
		Interval = 1000
	};

	private readonly System.Windows.Forms.Timer _invitations = new System.Windows.Forms.Timer
	{
		Interval = 5000
	};

	private readonly Stopwatch _elapsed = new Stopwatch();

	private readonly CancellationTokenSource _lifetime = new CancellationTokenSource();

	private readonly Panel _remoteBar = new Panel
	{
		Dock = DockStyle.Bottom,
		Height = 64,
		Visible = false,
		BackColor = Color.FromArgb(41, 27, 39)
	};

	private readonly Label _remoteLabel = new Label
	{
		ForeColor = Color.White,
		AutoSize = false
	};

	private TextBox[] _code = Array.Empty<TextBox>();

	private string[] _args;

	private Button? _validate;

	private Label? _message;

	private Label? _estimate;

	private NoryxProgressRing? _ring;

	private RemoteSupportClient? _remote;

	private bool _busy;

	private bool _running;

	private bool _accepted;

	private bool _polling;

	private bool _remoteBusy;

	private bool _declined;

	private bool _closing;

	private int _percent;

	internal AgentMainForm(string[] args)
	{
		_args = args;
		Text = "Noryx";
		base.AutoScaleMode = AutoScaleMode.Dpi;
		base.ClientSize = new Size(620, 680);
		base.StartPosition = FormStartPosition.CenterScreen;
		base.FormBorderStyle = FormBorderStyle.None;
		BackColor = Background;
		ForeColor = Primary;
		Font = new Font("Segoe UI", 10f);
		DoubleBuffered = true;
		base.KeyPreview = true;
		try
		{
			base.Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
		}
		catch
		{
		}
		Label value = new Label
		{
			Text = "NORYX",
			ForeColor = Accent,
			Font = new Font("Segoe UI", 16f, FontStyle.Bold),
			TextAlign = ContentAlignment.MiddleCenter,
			Dock = DockStyle.Top,
			Height = 86
		};
		Panel panel = new Panel
		{
			Dock = DockStyle.Bottom,
			Height = 48,
			BackColor = Background
		};
		LinkLabel linkLabel = new LinkLabel
		{
			Text = "Fechar",
			LinkColor = Muted,
			ActiveLinkColor = Primary,
			VisitedLinkColor = Muted,
			AutoSize = true,
			Location = new Point(286, 12)
		};
		linkLabel.LinkClicked += delegate
		{
			Close();
		};
		panel.Controls.Add(linkLabel);
		_remoteLabel.SetBounds(18, 12, 390, 42);
		_remoteLabel.Font = new Font("Segoe UI", 9f);
		Button button = MakeButton("Parar suporte", new Rectangle(440, 15, 160, 34), primary: false);
		button.Click += async delegate
		{
			await StopSupportAsync();
		};
		_remoteBar.Controls.Add(_remoteLabel);
		_remoteBar.Controls.Add(button);
		base.Controls.Add(_stage);
		base.Controls.Add(_remoteBar);
		base.Controls.Add(panel);
		base.Controls.Add(value);
		_clock.Tick += delegate
		{
			if (_running && _estimate != null)
			{
				_estimate.Text = VerificationPresentation.Remaining(_elapsed.Elapsed);
			}
		};
		_invitations.Tick += async delegate
		{
			await CheckInvitationAsync();
		};
		_invitations.Start();
		base.FormClosing += ClosingAsync;
		base.FormClosed += delegate
		{
			_lifetime.Cancel();
			_clock.Dispose();
			_invitations.Dispose();
			_lifetime.Dispose();
		};
		try
		{
			Program.LoadConfig(_args);
			ShowConsent();
		}
		catch
		{
			ShowCode();
		}
	}

	private void Ui(Action action)
	{
		if (base.IsDisposed || base.Disposing || !base.IsHandleCreated)
		{
			return;
		}
		try
		{
			if (base.InvokeRequired)
			{
				BeginInvoke(action);
			}
			else
			{
				action();
			}
		}
		catch (InvalidOperationException)
		{
		}
	}

	private void ClearStage()
	{
		_ring = null;
		_estimate = null;
		_message = null;
		Control[] array = _stage.Controls.Cast<Control>().ToArray();
		_stage.Controls.Clear();
		Control[] array2 = array;
		for (int i = 0; i < array2.Length; i++)
		{
			array2[i].Dispose();
		}
	}

	private Label TextBlock(string text, int top, int height, float size = 11f, Color? color = null, bool bold = false)
	{
		Label label = new Label
		{
			Text = text,
			Bounds = new Rectangle(65, top, 490, height),
			TextAlign = ContentAlignment.MiddleCenter,
			ForeColor = (color ?? Muted),
			Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular)
		};
		_stage.Controls.Add(label);
		return label;
	}

	private static Button MakeButton(string text, Rectangle bounds, bool primary = true)
	{
		Button button = new Button();
		button.Text = text;
		button.Bounds = bounds;
		button.BackColor = (primary ? Accent : Surface);
		button.ForeColor = Color.White;
		button.FlatStyle = FlatStyle.Flat;
		button.Cursor = Cursors.Hand;
		button.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
		button.UseVisualStyleBackColor = false;
		button.FlatAppearance.BorderSize = 0;
		return button;
	}

	private Button ActionButton(string text, int top, EventHandler handler)
	{
		Button button = MakeButton(text, new Rectangle(105, top, 410, 48));
		button.Click += handler;
		_stage.Controls.Add(button);
		return button;
	}

	private void ShowCode()
	{
		ClearStage();
		_accepted = false;
		TextBlock("Código de verificação", 60, 45, 24f, Primary, bold: true);
		TextBlock("Informe o código exibido no jogo.", 112, 30);
		_code = new TextBox[6];
		for (int i = 0; i < 6; i++)
		{
			int position = i;
			TextBox box = new TextBox
			{
				Bounds = new Rectangle(105 + i * 62 + ((i >= 3) ? 38 : 0), 188, 52, 58),
				MaxLength = 1,
				CharacterCasing = CharacterCasing.Upper,
				TextAlign = HorizontalAlignment.Center,
				Font = new Font("Segoe UI", 26f, FontStyle.Bold),
				BackColor = Surface,
				ForeColor = Primary,
				BorderStyle = BorderStyle.FixedSingle,
				AccessibleName = "Caractere " + (i + 1) + " do código"
			};
			box.KeyPress += delegate(object? _, KeyPressEventArgs e)
			{
				char c = char.ToUpperInvariant(e.KeyChar);
				bool flag = !char.IsControl(c);
				if (flag)
				{
					bool flag2;
					switch (c)
					{
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
					case 'A':
					case 'B':
					case 'C':
					case 'D':
					case 'E':
					case 'F':
					case 'G':
					case 'H':
					case 'I':
					case 'J':
					case 'K':
					case 'L':
					case 'M':
					case 'N':
					case 'O':
					case 'P':
					case 'Q':
					case 'R':
					case 'S':
					case 'T':
					case 'U':
					case 'V':
					case 'W':
					case 'X':
					case 'Y':
					case 'Z':
						flag2 = true;
						break;
					default:
						flag2 = false;
						break;
					}
					flag = !flag2;
				}
				if (flag)
				{
					e.Handled = true;
				}
			};
			box.TextChanged += delegate
			{
				if (box.TextLength == 1 && position < 5)
				{
					_code[position + 1]?.Focus();
				}
				if (_validate != null)
				{
					_validate.Enabled = VerificationPresentation.ValidCode(string.Concat(_code.Select((TextBox x) => x?.Text ?? "")));
				}
			};
			box.KeyDown += async delegate(object? _, KeyEventArgs e)
			{
				if (e.Control && e.KeyCode == Keys.V)
				{
					e.SuppressKeyPress = true;
					PasteCode();
				}
				else if (e.KeyCode == Keys.Back && box.TextLength == 0 && position > 0)
				{
					_code[position - 1].Focus();
					_code[position - 1].Clear();
					e.SuppressKeyPress = true;
				}
				else if (e.KeyCode == Keys.Left && position > 0)
				{
					_code[position - 1].Focus();
					e.SuppressKeyPress = true;
				}
				else if (e.KeyCode == Keys.Right && position < 5)
				{
					_code[position + 1].Focus();
					e.SuppressKeyPress = true;
				}
				else if (e.KeyCode == Keys.Return && (_validate?.Enabled ?? false))
				{
					e.SuppressKeyPress = true;
					await ValidateCodeAsync();
				}
			};
			ContextMenuStrip contextMenuStrip = new ContextMenuStrip();
			contextMenuStrip.Items.Add("Colar código", null, delegate
			{
				PasteCode();
			});
			box.ContextMenuStrip = contextMenuStrip;
			_code[i] = box;
			_stage.Controls.Add(box);
		}
		Label value = new Label
		{
			Text = "—",
			Bounds = new Rectangle(282, 195, 38, 40),
			TextAlign = ContentAlignment.MiddleCenter,
			ForeColor = Muted,
			Font = new Font("Segoe UI", 18f)
		};
		_stage.Controls.Add(value);
		_validate = ActionButton("Validar código", 285, async delegate
		{
			await ValidateCodeAsync();
		});
		_validate.Enabled = false;
		_message = TextBlock("", 350, 65, 10f);
		base.Shown += FocusCode;
		if (base.IsHandleCreated)
		{
			BeginInvoke(delegate
			{
				_code.FirstOrDefault()?.Focus();
			});
		}
	}

	private void FocusCode(object? sender, EventArgs e)
	{
		_code.FirstOrDefault()?.Focus();
		base.Shown -= FocusCode;
	}

	private void PasteCode()
	{
		try
		{
			string text = VerificationPresentation.NormalizeCode(Clipboard.GetText());
			if (VerificationPresentation.ValidCode(text))
			{
				for (int i = 0; i < 6; i++)
				{
					_code[i].Text = text[i].ToString();
				}
				_validate?.Focus();
			}
		}
		catch
		{
		}
	}

	private async Task ValidateCodeAsync()
	{
		if (_busy)
		{
			return;
		}
		string code = string.Concat(_code.Select((TextBox x) => x.Text));
		if (!VerificationPresentation.ValidCode(code))
		{
			return;
		}
		_busy = true;
		_validate.Enabled = false;
		if (_message != null)
		{
			_message.Text = "Validando código…";
		}
		try
		{
			string server = "https://noryx-anticheat.shardweb.app";
			string text = AgentRecoveryStore.PendingToken(server, code);
			if (text == null)
			{
				using HttpClient http = new HttpClient
				{
					BaseAddress = new Uri(server.TrimEnd('/') + "/"),
					Timeout = TimeSpan.FromSeconds(30.0)
				};
				using HttpResponseMessage response = await http.PostAsJsonAsync("api/noryx/client/claim", new
				{
					code = code,
					clientSecret = AgentRecoveryStore.ClaimSecret(server, code)
				}, _lifetime.Token);
				if (!response.IsSuccessStatusCode)
				{
					if (_message != null)
					{
						_message.Text = ((response.StatusCode >= HttpStatusCode.InternalServerError) ? "Serviço indisponível. Tente novamente." : "Código inválido, expirado ou já utilizado.");
					}
					return;
				}
				using JsonDocument jsonDocument = JsonDocument.Parse(await response.Content.ReadAsStringAsync(_lifetime.Token));
				text = jsonDocument.RootElement.GetProperty("token").GetString() ?? throw new IOException("invalid_session");
				AgentRecoveryStore.RememberToken(server, code, text);
			}
			if (!base.IsDisposed)
			{
				_args = new string[4] { "--token", text, "--server", server };
				ShowConsent();
			}
		}
		catch (OperationCanceledException)
		{
			if (!base.IsDisposed && _message != null)
			{
				_message.Text = "Conexão indisponível. Tente novamente.";
			}
		}
		catch
		{
			if (!base.IsDisposed && _message != null)
			{
				_message.Text = "Não foi possível validar o código. Tente novamente.";
			}
		}
		finally
		{
			_busy = false;
			if (!base.IsDisposed && _validate != null && !_validate.IsDisposed)
			{
				_validate.Enabled = true;
			}
		}
	}

	private void ShowConsent()
	{
		ClearStage();
		_validate = null;
		TextBlock("Autorizar verificação", 25, 45, 23f, Primary, bold: true);
		TextBlock("Confirme as permissões antes de continuar.", 77, 30);
		CheckBox pc = new CheckBox
		{
			Text = "Autorizo a análise de executáveis, processos e registros técnicos deste computador para a verificação.",
			Bounds = new Rectangle(85, 140, 450, 68),
			ForeColor = Primary,
			Font = new Font("Segoe UI", 10f),
			AutoSize = false,
			Cursor = Cursors.Hand
		};
		CheckBox discord = new CheckBox
		{
			Text = "Também autorizo a consulta das comunidades da conta Discord que eu conectar (opcional).",
			Bounds = new Rectangle(85, 217, 450, 64),
			ForeColor = Primary,
			Font = new Font("Segoe UI", 10f),
			AutoSize = false,
			Cursor = Cursors.Hand
		};
		_stage.Controls.Add(pc);
		_stage.Controls.Add(discord);
		TextBlock("Não coletamos senhas, mensagens ou documentos pessoais.\nO Discord confirma a autorização no navegador oficial.\nTela e controle remoto exigem um aceite separado.", 293, 65, 9f);
		LinkLabel linkLabel = new LinkLabel
		{
			Text = "Termos e privacidade",
			AutoSize = false,
			Bounds = new Rectangle(185, 365, 250, 28),
			TextAlign = ContentAlignment.MiddleCenter,
			LinkColor = Color.FromArgb(143, 188, 255),
			ActiveLinkColor = Primary,
			VisitedLinkColor = Color.FromArgb(143, 188, 255)
		};
		linkLabel.LinkClicked += delegate
		{
			ShowTerms();
		};
		_stage.Controls.Add(linkLabel);
		Button begin = MakeButton("Confirmar e iniciar", new Rectangle(105, 405, 410, 48));
		_stage.Controls.Add(begin);
		begin.Click += async delegate
		{
			if (_busy || !pc.Checked)
			{
				return;
			}
			_busy = true;
			beginButtonState(enabled: false);
			try
			{
				if (discord.Checked)
				{
					await OpenDiscordAsync();
				}
				if (!base.IsDisposed)
				{
					_accepted = true;
					await RunScanAsync();
				}
			}
			catch (OperationCanceledException)
			{
			}
			catch
			{
				if (!base.IsDisposed && _message != null)
				{
					_message.Text = "Não foi possível abrir o Discord. Tente novamente ou desmarque essa opção.";
				}
			}
			finally
			{
				_busy = false;
				if (!base.IsDisposed)
				{
					beginButtonState(enabled: true);
				}
			}
		};
		begin.Enabled = false;
		pc.CheckedChanged += delegate
		{
			begin.Enabled = pc.Checked && !_busy;
		};
		_message = TextBlock("Ao confirmar, você aceita os termos da verificação.", 465, 45, 9f);
		void beginButtonState(bool enabled)
		{
			if (!begin.IsDisposed)
			{
				begin.Enabled = enabled && pc.Checked;
			}
		}
	}

	private void ShowTerms()
	{
		AgentConfig config = Program.LoadConfig(_args);
		using Form form = new Form
		{
			Text = "Termos e privacidade",
			Size = new Size(430, 245),
			FormBorderStyle = FormBorderStyle.FixedDialog,
			MaximizeBox = false,
			MinimizeBox = false,
			StartPosition = FormStartPosition.CenterParent,
			BackColor = Background,
			ForeColor = Primary
		};
		Label value = new Label
		{
			Text = "Consulte o escopo completo e as condições antes de confirmar a verificação.",
			Bounds = new Rectangle(25, 25, 365, 50),
			ForeColor = Muted
		};
		Button button = MakeButton("Abrir termos", new Rectangle(25, 100, 170, 42));
		Button button2 = MakeButton("Abrir privacidade", new Rectangle(215, 100, 170, 42));
		button.Click += delegate
		{
			OpenLink(config.ServerUrl.TrimEnd('/') + "/terms");
		};
		button2.Click += delegate
		{
			OpenLink(config.ServerUrl.TrimEnd('/') + "/privacy");
		};
		form.Controls.Add(value);
		form.Controls.Add(button);
		form.Controls.Add(button2);
		form.ShowDialog(this);
	}

	private static void OpenLink(string url)
	{
		try
		{
			Process.Start(new ProcessStartInfo(url)
			{
				UseShellExecute = true
			});
		}
		catch
		{
		}
	}

	private async Task OpenDiscordAsync()
	{
		AgentConfig agentConfig = Program.LoadConfig(_args);
		using HttpClient http = new HttpClient
		{
			BaseAddress = new Uri(agentConfig.ServerUrl.TrimEnd('/') + "/"),
			Timeout = TimeSpan.FromSeconds(20.0)
		};
		using HttpResponseMessage response = await http.PostAsJsonAsync("api/agent/" + Uri.EscapeDataString(agentConfig.Token) + "/discord-link", new { }, _lifetime.Token);
		response.EnsureSuccessStatusCode();
		using JsonDocument jsonDocument = JsonDocument.Parse(await response.Content.ReadAsStringAsync(_lifetime.Token));
		Uri uri = new Uri(jsonDocument.RootElement.GetProperty("url").GetString() ?? "");
		if (uri.Scheme != "https" || uri.GetLeftPart(UriPartial.Authority) != http.BaseAddress.GetLeftPart(UriPartial.Authority))
		{
			throw new IOException("invalid_oauth_origin");
		}
		Process.Start(new ProcessStartInfo(uri.AbsoluteUri)
		{
			UseShellExecute = true
		});
	}

	private async Task RunScanAsync()
	{
		if (_running)
		{
			return;
		}
		_running = true;
		_percent = 0;
		_elapsed.Restart();
		ClearStage();
		TextBlock("Verificação em andamento", 40, 45, 23f, Primary, bold: true);
		_ring = new NoryxProgressRing
		{
			Bounds = new Rectangle(208, 115, 204, 204),
			Value = 0
		};
		_stage.Controls.Add(_ring);
		_estimate = TextBlock(VerificationPresentation.Remaining(TimeSpan.Zero), 350, 35);
		_clock.Start();
		AgentRunResult agentRunResult;
		try
		{
			agentRunResult = await Task.Run(() => Program.RunAnalysisAsync(_args, delegate
			{
			}, delegate(int value, string _)
			{
				Ui(delegate
				{
					_percent = Math.Clamp(value, _percent, 99);
					if (_ring != null)
					{
						_ring.Value = _percent;
					}
				});
			}));
		}
		catch
		{
			agentRunResult = new AgentRunResult
			{
				ExitCode = 1
			};
		}
		_running = false;
		_clock.Stop();
		_elapsed.Stop();
		if (!base.IsDisposed)
		{
			ShowReceipt(agentRunResult.ExitCode == 0);
		}
	}

	private void ShowReceipt(bool received)
	{
		ClearStage();
		TextBlock(received ? "✓" : "!", 90, 95, 48f, received ? Accent : Muted, bold: true);
		TextBlock(VerificationPresentation.Completion(received), 215, 85, 21f, Primary, bold: true);
		if (received)
		{
			return;
		}
		ActionButton("Tentar novamente", 345, async delegate
		{
			if (!_running)
			{
				await RunScanAsync();
			}
		});
	}

	private async Task CheckInvitationAsync()
	{
		if (!_accepted || _polling || _remoteBusy || base.IsDisposed)
		{
			return;
		}
		_polling = true;
		try
		{
			await using RemoteSupportClient client = new RemoteSupportClient(Program.LoadConfig(_args));
			List<RemoteAdministrator> list = await client.GetAvailableAdminsAsync(_lifetime.Token);
			if (base.IsDisposed)
			{
				return;
			}
			if (list.Count == 0)
			{
				_declined = false;
				return;
			}
			if (_declined)
			{
				return;
			}
			_declined = true;
			RemoteAdministrator remoteAdministrator = list[0];
			if (MessageBox.Show(this, remoteAdministrator.DisplayName + " solicitou compartilhar a tela e controlar o mouse e o teclado.\n\nVocê autoriza esta sessão? Pode pará-la a qualquer momento.", "Solicitação de suporte", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
			{
				return;
			}
			_remoteBusy = true;
			_remote = new RemoteSupportClient(Program.LoadConfig(_args));
			RemoteSupportClient current = _remote;
			_remoteBar.Visible = true;
			_remoteLabel.Text = "Conectando o suporte solicitado…";
			try
			{
				_ = 1;
				try
				{
					await current.RunAsync(remoteAdministrator.Id, "control", delegate
					{
						Ui(delegate
						{
							_remoteLabel.Text = (current.IsActive ? "Tela, mouse e teclado compartilhados.\nVocê pode parar a qualquer momento." : "Conectando o suporte solicitado…");
						});
					}, _lifetime.Token);
				}
				catch
				{
					if (!base.IsDisposed)
					{
						MessageBox.Show(this, "A sessão de suporte não foi concluída.", "Noryx", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
					}
				}
			}
			finally
			{
				if (_remote == current)
				{
					_remote = null;
				}
				await current.DisposeAsync();
				_remoteBusy = false;
				if (!base.IsDisposed)
				{
					_remoteBar.Visible = false;
				}
			}
		}
		catch
		{
		}
		finally
		{
			_polling = false;
		}
	}

	private async Task StopSupportAsync()
	{
		RemoteSupportClient remote = _remote;
		if (remote == null)
		{
			return;
		}
		_remoteLabel.Text = "Encerrando suporte…";
		try
		{
			await remote.StopAsync();
		}
		catch
		{
		}
	}

	private async void ClosingAsync(object? sender, FormClosingEventArgs e)
	{
		if (_closing)
		{
			return;
		}
		if ((_running || _remoteBusy) && MessageBox.Show(this, "A verificação ou o suporte ainda está em andamento. Deseja fechar?", "Noryx", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
		{
			e.Cancel = true;
			return;
		}
		e.Cancel = true;
		_closing = true;
		_lifetime.Cancel();
		_clock.Stop();
		_invitations.Stop();
		await StopSupportAsync();
		if (!base.IsDisposed)
		{
			BeginInvoke(base.Close);
		}
	}
}
