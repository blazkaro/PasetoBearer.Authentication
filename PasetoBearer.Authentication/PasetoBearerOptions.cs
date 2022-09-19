using Microsoft.AspNetCore.Authentication;
using Paseto;

namespace PasetoBearer.Authentication;

public class PasetoBearerOptions : AuthenticationSchemeOptions
{
    public PasetoTokenValidationParameters PasetoTokenValidationParameters { get; set; }
    public ProtocolVersion PasetoVersion { get; set; }
    public byte[] PublicKey { get; set; }
    public bool GetPublicKeyFromDiscoveryEndpoint { get; set; }
    public Uri DiscoveryEndpoint { get; set; }
    public string PublicKeyPropertyNameInDiscoveryDocument { get; set; }
}
