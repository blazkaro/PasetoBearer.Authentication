using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Paseto;
using Paseto.Builder;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;

namespace PasetoBearer.Authentication;

public class PasetoBearerHandler : AuthenticationHandler<PasetoBearerOptions>
{
    public PasetoBearerHandler(IOptionsMonitor<PasetoBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        byte[]? publicKey = null;
        if (Options.GetPublicKeyFromDiscoveryEndpoint)
        {
            using (var http = new HttpClient())
            {
                var response = await http.GetAsync(Options.DiscoveryEndpoint, Context.RequestAborted);
                var publicKeyB64Node = JsonNode.Parse(await response.Content.ReadAsStringAsync())[Options.PublicKeyPropertyNameInDiscoveryDocument];
                publicKey = Convert.FromBase64String(publicKeyB64Node.GetValue<string>());
            }
        }
        else
        {
            publicKey = Options.PublicKey;
        }

        var authorizationHeader = Request.Headers[HeaderNames.Authorization].ToString();
        if (string.IsNullOrEmpty(authorizationHeader))
            return AuthenticateResult.NoResult();

        var accessToken = authorizationHeader.Replace("Bearer ", "");
        if (string.IsNullOrEmpty(accessToken))
            return AuthenticateResult.NoResult();

        var pasetoValidator = new PasetoBuilder().Use(Options.PasetoVersion, Purpose.Public)
            .WithPublicKey(publicKey)
            .Decode(accessToken, Options.PasetoTokenValidationParameters);

        if (!pasetoValidator.IsValid)
            return AuthenticateResult.NoResult();

        List<Claim> claims = new();
        claims.AddRange(pasetoValidator.Paseto.Payload.Select(claim => new Claim(claim.Key, Convert.ToString(claim.Value))));

        return AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(claims, PasetoBearerDefaults.AuthenticationScheme)),
            PasetoBearerDefaults.AuthenticationScheme));
    }
}
