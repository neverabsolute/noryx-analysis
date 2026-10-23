using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Noryx.Agent;

internal static class TransportReport
{
	internal static byte[] Encode<T>(T report, int maximumBytes = 6291456)
	{
		JsonObject jsonObject = JsonSerializer.SerializeToNode(report, new JsonSerializerOptions(JsonSerializerDefaults.Web)).AsObject();
		JsonObject jsonObject2 = new JsonObject();
		foreach (KeyValuePair<string, JsonNode> item in jsonObject)
		{
			if (item.Value is JsonArray jsonArray)
			{
				jsonObject2[item.Key] = jsonArray.Count;
			}
		}
		jsonObject["transportOriginalCounts"] = jsonObject2;
		if (jsonObject["fileInventory"] is JsonArray jsonArray2)
		{
			jsonObject["fileInventory"] = new JsonArray();
			jsonObject["transportInventoryOmitted"] = jsonArray2.Count;
		}
		jsonObject["transportTruncated"] = false;
		byte[] array = JsonSerializer.SerializeToUtf8Bytes(jsonObject);
		bool flag = false;
		while (array.Length > maximumBytes)
		{
			if (!((from x in jsonObject
				where x.Value is JsonArray { Count: >0 } && x.Key != "errors"
				orderby x.Value.ToJsonString().Length descending
				select x).FirstOrDefault().Value is JsonArray jsonArray3))
			{
				throw new IOException("Relatório excede o tamanho seguro. Revisão necessária; não foi enviado como limpo.");
			}
			if (!flag)
			{
				if (!(jsonObject["errors"] is JsonArray))
				{
					jsonObject["errors"] = new JsonArray();
				}
				jsonObject["errors"].AsArray().Add("Relatório reduzido para o limite de transporte de memória. Cobertura parcial; revisão obrigatória.");
				flag = true;
				jsonObject["transportTruncated"] = true;
			}
			int num = jsonArray3.Count / 2;
			int num2 = jsonArray3.Count - 1;
			while (num2 >= num && num2 >= 0)
			{
				jsonArray3.RemoveAt(num2);
				if (jsonArray3.Count == 0)
				{
					break;
				}
				num2--;
			}
			array = JsonSerializer.SerializeToUtf8Bytes(jsonObject);
		}
		return array;
	}
}
