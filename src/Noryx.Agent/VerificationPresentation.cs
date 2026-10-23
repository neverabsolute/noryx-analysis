using System;
using System.Linq;

namespace Noryx.Agent;

internal static class VerificationPresentation
{
	internal const int CollectionBudgetSeconds = 900;

	internal static string NormalizeCode(string value)
	{
		return value.Trim().Replace("-", "").Replace(" ", "")
			.ToUpperInvariant();
	}

	internal static bool ValidCode(string value)
	{
		if (value.Length == 6)
		{
			return value.All(delegate(char c)
			{
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
					return true;
				default:
					return false;
				}
			});
		}
		return false;
	}

	internal static string Remaining(TimeSpan elapsed)
	{
		double num = 930.0 - elapsed.TotalSeconds;
		if (!(num <= 0.0))
		{
			return "Tempo estimado restante: ~" + TimeSpan.FromSeconds(num).ToString("mm\\:ss");
		}
		return "Finalizando…";
	}

	internal static string Completion(bool received)
	{
		if (!received)
		{
			return "Não foi possível concluir a verificação.";
		}
		return "Verificação enviada para análise.";
	}
}
