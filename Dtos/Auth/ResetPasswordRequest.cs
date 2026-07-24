using System.ComponentModel.DataAnnotations;

namespace OAuthGoogleAPI.Dtos.Auth;

public class ResetPasswordRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = default!;

    [Required]
    public string Token { get; set; } = default!;

    [Required]
    public string NewPassword { get; set; } = default!;
}
