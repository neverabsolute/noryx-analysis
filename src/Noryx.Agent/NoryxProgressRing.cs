using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Noryx.Agent;

internal sealed class NoryxProgressRing : Control
{
	private int _value;

	internal int Value
	{
		get
		{
			return _value;
		}
		set
		{
			_value = Math.Clamp(value, 0, 100);
			Invalidate();
		}
	}

	internal NoryxProgressRing()
	{
		DoubleBuffered = true;
		BackColor = Color.FromArgb(8, 12, 20);
	}

	protected override void OnPaint(PaintEventArgs e)
	{
		base.OnPaint(e);
		e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
		RectangleF rect = new RectangleF(12f, 12f, base.Width - 24, base.Height - 24);
		using Pen pen = new Pen(Color.FromArgb(27, 42, 63), 8f);
		using Pen pen2 = new Pen(Color.FromArgb(55, 139, 255), 8f)
		{
			StartCap = LineCap.Round,
			EndCap = LineCap.Round
		};
		e.Graphics.DrawEllipse(pen, rect);
		if (Value > 0)
		{
			e.Graphics.DrawArc(pen2, rect, -90f, 360f * (float)Value / 100f);
		}
		using Font font = new Font("Segoe UI", 33f, FontStyle.Bold);
		using SolidBrush brush = new SolidBrush(Color.FromArgb(238, 244, 253));
		using StringFormat format = new StringFormat
		{
			Alignment = StringAlignment.Center,
			LineAlignment = StringAlignment.Center
		};
		e.Graphics.DrawString(Value + "%", font, brush, base.ClientRectangle, format);
	}
}
