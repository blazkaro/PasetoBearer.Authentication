using Microsoft.AspNetCore.Authentication;

namespace PasetoBearer.Authentication;

public static class DependencyInjection
{
    public static AuthenticationBuilder AddPasetoBearer(this AuthenticationBuilder authenticationBuilder, Action<PasetoBearerOptions> configureOptions)
    {
        authenticationBuilder.AddScheme<PasetoBearerOptions, PasetoBearerHandler>(PasetoBearerDefaults.AuthenticationScheme, configureOptions);
        return authenticationBuilder;
    }
}
