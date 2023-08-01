using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace PasetoBearer.Authentication;

public static class DependencyInjection
{
    /// <summary>
    /// Register necessary services
    /// </summary>
    /// <param name="authenticationBuilder">The <see cref="AuthenticationBuilder"/></param>
    /// <param name="configureOptions">The PASETO-Bearer authentication options</param>
    /// <returns>The <see cref="AuthenticationBuilder"/></returns>
    public static AuthenticationBuilder AddPasetoBearer(this AuthenticationBuilder authenticationBuilder, Action<PasetoBearerOptions> configureOptions)
    {
        var options = new PasetoBearerOptions();
        configureOptions(options);

        options.Validate();

        authenticationBuilder.AddScheme<PasetoBearerOptions, PasetoBearerHandler>(PasetoBearerDefaults.AuthenticationScheme, configureOptions);

        if (options.GetPublicKeyFromDiscoveryEndpoint)
        {
            authenticationBuilder.Services.AddHttpClient(PasetoBearerDefaults.HttpClientName);

            if (options.PaserkCachingOptions.CacheRetrievedPaserk)
                authenticationBuilder.Services.AddMemoryCache();
        }

        return authenticationBuilder;
    }
}
