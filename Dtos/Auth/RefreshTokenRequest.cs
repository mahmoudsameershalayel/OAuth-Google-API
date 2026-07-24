using System.ComponentModel.DataAnnotations;

namespace OAuthGoogleAPI.Dtos.Auth;

public class RefreshTokenRequest
{
    [Required]
    public string RefreshToken { get; set; } = default!;
}
