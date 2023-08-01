using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography;
using PasetoBearer.Authentication.Serializers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace PasetoBearer.Authentication;

public class PasetoBearerHandler : AuthenticationHandler<PasetoBearerOptions>
{
    private const string PASERK_CACHING_KEY = "paserk-key";

    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _memoryCache;

    public PasetoBearerHandler(IOptionsMonitor<PasetoBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock,
        IHttpClientFactory httpClientFactory,
        IMemoryCache memoryCache)
        : base(options, logger, encoder, clock)
    {
        _httpClient = httpClientFactory.CreateClient(PasetoBearerDefaults.HttpClientName);
        _memoryCache = memoryCache;
    }

    public PasetoBearerHandler(IOptionsMonitor<PasetoBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock,
        IHttpClientFactory httpClientFactory)
        : base(options, logger, encoder, clock)
    {
        _httpClient = httpClientFactory.CreateClient(PasetoBearerDefaults.HttpClientName);
    }

    public PasetoBearerHandler(IOptionsMonitor<PasetoBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorizationHeader = Request.Headers[HeaderNames.Authorization].ToString();
        if (string.IsNullOrEmpty(authorizationHeader))
            return AuthenticateResult.NoResult();

        var accessToken = authorizationHeader.Replace("Bearer ", "");
        if (string.IsNullOrEmpty(accessToken))
            return AuthenticateResult.NoResult();

        byte[]? publicKey = await GetPublicKeyAsync(Context.RequestAborted);
        if (await ValidateAsync(accessToken, publicKey) is var (isValid, failureMessage, token) && (!isValid || token is null))
            return await FailAsync(failureMessage);

        static string ConvertClaimValueToString(object claimValue)
        {
            if (claimValue is string s)
                return s;

            if (claimValue is DateTime dateTime)
                return dateTime.ToString();

            return JsonSerializer.Serialize(claimValue);
        }

        var claims = token.Payload.Select(claim => new Claim(claim.Key, ConvertClaimValueToString(claim.Value)));
        var claimsIdentity = new ClaimsIdentity(claims, PasetoBearerDefaults.AuthenticationScheme);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        var ticket = new AuthenticationTicket(claimsPrincipal, PasetoBearerDefaults.AuthenticationScheme);
        return AuthenticateResult.Success(ticket);
    }

    private async Task<byte[]> GetPublicKeyAsync(CancellationToken cancellationToken)
    {
        if (Options.GetPublicKeyFromDiscoveryEndpoint)
        {
            if (Options.PaserkCachingOptions.CacheRetrievedPaserk)
            {
                if (_memoryCache.TryGetValue(PASERK_CACHING_KEY, out byte[]? cachedKey) && cachedKey?.Length == Ed25519.PublicKeySizeInBytes)
                {
                    return cachedKey;
                }
                else
                {
                    var key = await RetrievePaserkFromEndpoint(cancellationToken);
                    lock (_memoryCache)
                    {
                        _memoryCache.Set(PASERK_CACHING_KEY,
                            key,
                            DateTime.UtcNow.AddSeconds(Options.PaserkCachingOptions.CacheExpiresIn.Seconds));
                    }

                    return key;
                }
            }
            else
            {
                return await RetrievePaserkFromEndpoint(cancellationToken);
            }
        }
        else
        {
            return Options.PublicKey;
        }
    }

    private async Task<byte[]> RetrievePaserkFromEndpoint(CancellationToken cancellationToken)
    {
        var response = await (await _httpClient.GetAsync(Options.PaserkEndpoint, cancellationToken))
            .EnsureSuccessStatusCode()
            .Content.ReadFromJsonAsync<JsonNode>(cancellationToken: cancellationToken);

        var paserk = await Options.RetrievePaserk(response!);
        return Paserk.Decode(paserk).Key.ToArray();
    }

    private async Task<(bool IsValid, string? FailureMessage, PasetoToken? Token)> ValidateAsync(string accessToken, byte[] publicKey)
    {
        var pasetoValidator = new PasetoBuilder()
            .WithJsonSerializer(new PasetoPayloadSerializer())
            .Use(Options.PasetoVersion, Purpose.Public)
            .WithPublicKey(publicKey)
            .Decode(accessToken, Options.PasetoTokenValidationParameters);

        if (!pasetoValidator.IsValid)
            return new(false, pasetoValidator.Exception.Message, null);

        var additionalValidationResult = await Options.AdditionalValidation(pasetoValidator.Paseto);
        if (!additionalValidationResult.IsValid)
            return new(false, additionalValidationResult.FailureMessage, null);

        return new(true, null, pasetoValidator.Paseto);
    }

    private async Task<AuthenticateResult> FailAsync(string? failureMessage)
    {
        var properties = new AuthenticationProperties();
        if (!string.IsNullOrEmpty(failureMessage))
            properties.Items.Add("failureMessage", failureMessage);

        await ChallengeAsync(properties);
        return AuthenticateResult.Fail(failureMessage);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await Context.Response.WriteAsJsonAsync(
            new
            {
                error = "invalid_token",
                error_description = properties.Items.TryGetValue("failureMessage", out string? failureMessage) ? failureMessage : null,
            },
            new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            }, Context.RequestAborted);
    }
}
