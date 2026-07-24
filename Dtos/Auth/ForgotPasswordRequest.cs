using System.ComponentModel.DataAnnotations;

namespace OAuthGoogleAPI.Dtos.Auth;

public class ForgotPasswordRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = default!;
}
