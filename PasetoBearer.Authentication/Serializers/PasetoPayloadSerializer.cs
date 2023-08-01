using Paseto.Serializers;
using System.Text.Json;

namespace PasetoBearer.Authentication.Serializers;

/// <summary>
/// PASETO token serializer using System.Text.Json
/// </summary>
internal class PasetoPayloadSerializer : IJsonSerializer
{
    public T Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json)!;
    }

    public string Serialize(object obj)
    {
        return JsonSerializer.Serialize(obj);
    }
}
