using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Paseto;
using Paseto.Cryptography;
using PasetoBearer.Authentication.Results;
using System.Text.Json.Nodes;

namespace PasetoBearer.Authentication;

/// <summary>
/// The PASETO-Bearer authentication options
/// </summary>
public class PasetoBearerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The PASETO validation parameters
    /// </summary>
    public PasetoTokenValidationParameters PasetoTokenValidationParameters { get; set; }

    /// <summary>
    /// The PASETO version to use. Default to V4
    /// </summary>
    public ProtocolVersion PasetoVersion { get; set; } = ProtocolVersion.V4;

    /// <summary>
    /// The public key to verify PASETO access tokens. Needed if public key is not retrieved from endpoint
    /// </summary>
    public byte[] PublicKey { get; set; }

    /// <summary>
    /// Whether the public key to verify the PASETO access token is retrieved from endpoint
    /// </summary>
    public bool GetPublicKeyFromDiscoveryEndpoint { get; set; }

    /// <summary>
    /// The endpoint which provides PASERK (we get public key from it)
    /// </summary>
    public Uri PaserkEndpoint { get; set; }

    /// <summary>
    /// Function to retrieve PASERK from <see cref="PaserkEndpoint"/> response. By default, it will look for "paserk" property in JSON object, and use its value.
    /// If you have different use case, implement your own logic
    /// </summary>
    public Func<JsonNode, Task<string>> RetrievePaserk { get; set; } = (paserksEndpointResponse) =>
    {
        string? paserk = null;
        if (paserksEndpointResponse is JsonObject paserksObject)
        {
            if (paserksObject.TryGetPropertyValue("paserk", out JsonNode? paserkNode) && paserkNode is not null)
            {
                paserk = paserkNode.GetValue<string>();
            }
        }

        if (string.IsNullOrEmpty(paserk))
            throw new NotSupportedException($"Unable to retrieve PASERK from given '{nameof(PaserkEndpoint)}'. " +
                $"Override '{nameof(PasetoBearerOptions.RetrievePaserk)}' with your custom logic.");

        return Task.FromResult(paserk);
    };

    /// <summary>
    /// The additional validation to do. You can just implement it.
    /// </summary>
    public Func<PasetoToken, Task<AdditionalValidationResult>> AdditionalValidation { get; set; }
        = (token) => Task.FromResult(AdditionalValidationResult.Success());

    /// <summary>
    /// The caching options for PASERK retrieved from <see cref="PaserkEndpoint"/>
    /// </summary>
    public PaserkCachingOptions PaserkCachingOptions { get; set; } = new();

    /// <inheritdoc/>
    public override void Validate(string scheme)
    {
        var failureMessages = new List<string>();

        if (PasetoTokenValidationParameters is null)
            failureMessages.Add($"You must specify '{nameof(PasetoTokenValidationParameters)}'");

        if (PublicKey?.Length != Ed25519.PublicKeySizeInBytes && !GetPublicKeyFromDiscoveryEndpoint)
            failureMessages.Add($"You must specify '{nameof(PublicKey)}' or the '{nameof(GetPublicKeyFromDiscoveryEndpoint)}' must be set to 'true'");

        if (GetPublicKeyFromDiscoveryEndpoint && PaserkEndpoint is null)
            failureMessages.Add($"If the '{nameof(GetPublicKeyFromDiscoveryEndpoint)}' is set to 'true', you must specify the '{nameof(PaserkEndpoint)}'");

        if (failureMessages.Any())
            throw new OptionsValidationException(nameof(PasetoBearerOptions), typeof(PasetoBearerOptions), failureMessages);
    }
}

/// <summary>
/// The PASERK caching options
/// </summary>
public class PaserkCachingOptions
{
    /// <summary>
    /// Whether PASERK should be cached
    /// </summary>
    public bool CacheRetrievedPaserk { get; set; } = true;

    /// <summary>
    /// How long the cached PASERK is valid (when the cache should expiry)
    /// </summary>
    public TimeSpan CacheExpiresIn { get; set; } = TimeSpan.FromHours(1);
}