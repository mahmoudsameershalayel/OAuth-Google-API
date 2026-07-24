using Microsoft.AspNetCore.Identity;
using OAuthGoogleAPI.Dtos.Auth;

namespace OAuthGoogleAPI.Services;

public interface ITokenService
{
    Task<TokenResponse> IssueTokensAsync(IdentityUser user);

    Task<TokenResponse?> RefreshAsync(string refreshToken);

    Task<bool> RevokeAsync(string refreshToken, string userId);
}
