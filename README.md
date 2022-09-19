# PasetoBearer.Authentication
A simple implementation for securing the API by PASETO public access tokens.

# Usage

```cs
services.AddAuthentication()
    .AddPasetoBearer(cfg =>
    {
    });

app.UseAuthentication();
app.UseAuthorization();
```


And then you can use PasetoBearer authorization in controller with ```[AuthorizeAttribute]``` like this:

```cs
[HttpGet]
[Authorize(AuthenticationSchemes = PasetoBearerDefaults.AuthenticationScheme)]
public IActionResult SomeMethod()
{
    return Ok();
}
```