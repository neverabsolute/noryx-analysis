using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Noryx.Agent;

internal static class LogClearEventParser
{
	internal static List<EventLogSignalRecord> Parse(string xml, string expectedChannel)
	{
		if (xml.Length > 262144)
		{
			throw new IOException("Resposta de log acima do tamanho esperado.");
		}
		string text = Regex.Replace(xml, "<\\?xml[^?]*\\?>", "");
		using XmlReader reader = XmlReader.Create(new StringReader("<Events>" + text + "</Events>"), new XmlReaderSettings
		{
			DtdProcessing = DtdProcessing.Prohibit,
			XmlResolver = null
		});
		XElement xElement = XElement.Load(reader);
		XNamespace xNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
		List<EventLogSignalRecord> list = new List<EventLogSignalRecord>();
		foreach (XElement item in xElement.Elements(xNamespace + "Event").Take(30))
		{
			XElement xElement2 = item.Element(xNamespace + "System");
			string text2 = xElement2?.Element(xNamespace + "Channel")?.Value ?? "";
			string text3 = xElement2?.Element(xNamespace + "Provider")?.Attribute("Name")?.Value ?? "";
			if (int.TryParse(xElement2?.Element(xNamespace + "EventID")?.Value, out var result) && text2.Equals(expectedChannel, StringComparison.OrdinalIgnoreCase) && text3.Equals("Microsoft-Windows-Eventlog", StringComparison.OrdinalIgnoreCase) && ((text2.Equals("System", StringComparison.OrdinalIgnoreCase) && result == 104) || (text2.Equals("Security", StringComparison.OrdinalIgnoreCase) && result == 1102)))
			{
				DateTimeOffset result2;
				DateTime? timestampUtc = (DateTimeOffset.TryParse(xElement2?.Element(xNamespace + "TimeCreated")?.Attribute("SystemTime")?.Value ?? "", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out result2) ? new DateTime?(result2.UtcDateTime) : ((DateTime?)null));
				list.Add(new EventLogSignalRecord
				{
					Channel = text2,
					Provider = text3,
					EventId = result,
					RecordId = (long.TryParse(xElement2?.Element(xNamespace + "EventRecordID")?.Value, out var result3) ? new long?(result3) : ((long?)null)),
					TimestampUtc = timestampUtc,
					Signal = "Limpeza de log registrada (Event ID " + result + ")",
					WindowHours = 360,
					Evidence = "Evento de limpeza confirmado no log do Windows. A finalidade da operação não é determinada pelo evento."
				});
			}
		}
		return list;
	}
}
