namespace OAuthGoogleAPI.Dtos.Auth;

public class TokenResponse
{
    public string AccessToken { get; set; } = default!;
    public DateTime AccessTokenExpiresAtUtc { get; set; }
    public string RefreshToken { get; set; } = default!;
    public DateTime RefreshTokenExpiresAtUtc { get; set; }
}
