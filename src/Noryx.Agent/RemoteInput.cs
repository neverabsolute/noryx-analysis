using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Forms;

namespace Noryx.Agent;

internal static class RemoteInput
{
	private struct INPUT
	{
		public uint type;

		public InputUnion union;
	}

	[StructLayout(LayoutKind.Explicit)]
	private struct InputUnion
	{
		[FieldOffset(0)]
		public MOUSEINPUT mouse;

		[FieldOffset(0)]
		public KEYBDINPUT keyboard;
	}

	private struct MOUSEINPUT
	{
		public int dx;

		public int dy;

		public uint mouseData;

		public uint flags;

		public uint time;

		public nint extraInfo;
	}

	private struct KEYBDINPUT
	{
		public ushort virtualKey;

		public ushort scanCode;

		public uint flags;

		public uint time;

		public nint extraInfo;
	}

	private const uint InputMouse = 0u;

	private const uint InputKeyboard = 1u;

	private const uint MouseMove = 1u;

	private const uint MouseAbsolute = 32768u;

	private const uint MouseVirtualDesktop = 16384u;

	private const uint MouseLeftDown = 2u;

	private const uint MouseLeftUp = 4u;

	private const uint MouseRightDown = 8u;

	private const uint MouseRightUp = 16u;

	private const uint KeyUp = 2u;

	public static void Apply(JsonElement message, int monitorIndex = 0)
	{
		JsonElement value;
		string text = (message.TryGetProperty("type", out value) ? (value.GetString() ?? "") : "");
		JsonElement value3;
		if (text == "pointer")
		{
			double num = Math.Clamp(message.GetProperty("x").GetDouble(), 0.0, 1.0);
			double num2 = Math.Clamp(message.GetProperty("y").GetDouble(), 0.0, 1.0);
			Screen[] allScreens = Screen.AllScreens;
			Rectangle virtualScreen = SystemInformation.VirtualScreen;
			Rectangle rectangle = ((allScreens.Length != 0) ? allScreens[Math.Clamp(monitorIndex, 0, allScreens.Length - 1)].Bounds : virtualScreen);
			double num3 = ((double)(rectangle.Left - virtualScreen.Left) + num * (double)rectangle.Width) / Math.Max(1.0, virtualScreen.Width);
			SendMouse(y: (int)Math.Clamp(Math.Round(((double)(rectangle.Top - virtualScreen.Top) + num2 * (double)rectangle.Height) / Math.Max(1.0, virtualScreen.Height) * 65535.0), 0.0, 65535.0), x: (int)Math.Clamp(Math.Round(num3 * 65535.0), 0.0, 65535.0), flags: 49153u);
			JsonElement value2;
			uint num4 = (message.TryGetProperty("action", out value2) ? (value2.GetString() ?? "") : "") switch
			{
				"leftDown" => 2u, 
				"leftUp" => 4u, 
				"rightDown" => 8u, 
				"rightUp" => 16u, 
				_ => 0u, 
			};
			if (num4 != 0)
			{
				SendMouse(0, 0, num4);
			}
		}
		else if (text == "key" && message.TryGetProperty("keyCode", out value3))
		{
			int @int = value3.GetInt32();
			if (@int >= 8 && @int <= 255)
			{
				SendKey((ushort)@int, message.TryGetProperty("up", out var value4) && value4.GetBoolean());
			}
		}
	}

	private static void SendMouse(int x, int y, uint flags)
	{
		INPUT iNPUT = new INPUT
		{
			type = 0u,
			union = new InputUnion
			{
				mouse = new MOUSEINPUT
				{
					dx = x,
					dy = y,
					flags = flags
				}
			}
		};
		SendInput(1u, new INPUT[1] { iNPUT }, Marshal.SizeOf<INPUT>());
	}

	private static void SendKey(ushort key, bool up)
	{
		INPUT iNPUT = new INPUT
		{
			type = 1u,
			union = new InputUnion
			{
				keyboard = new KEYBDINPUT
				{
					virtualKey = key,
					flags = (up ? 2u : 0u)
				}
			}
		};
		SendInput(1u, new INPUT[1] { iNPUT }, Marshal.SizeOf<INPUT>());
	}

	[DllImport("user32.dll", SetLastError = true)]
	private static extern uint SendInput(uint count, INPUT[] inputs, int size);
}
