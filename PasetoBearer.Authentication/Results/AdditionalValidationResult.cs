namespace PasetoBearer.Authentication.Results;

/// <summary>
/// Result of additional validation
/// </summary>
/// <param name="IsValid">Whether access token is valid</param>
/// <param name="FailureMessage">The description of the cause for invalidity</param>
public record AdditionalValidationResult(bool IsValid, string? FailureMessage = null)
{
    public static AdditionalValidationResult Fail(string? failureMessage = null)
    {
        return new(false, failureMessage);
    }

    public static AdditionalValidationResult Success() => new(true);
}
