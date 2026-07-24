using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OAuthGoogleAPI.Data;
using OAuthGoogleAPI.Dtos.Auth;
using OAuthGoogleAPI.Entities;

namespace OAuthGoogleAPI.Services;

public class TokenService(ApplicationDbContext db, IConfiguration configuration) : ITokenService
{
    private readonly IConfiguration _configuration = configuration;
    private readonly ApplicationDbContext _db = db;

    public async Task<TokenResponse> IssueTokensAsync(IdentityUser user)
    {
        var jwtSection = _configuration.GetSection("Jwt");
        var accessTokenMinutes = jwtSection.GetValue("AccessTokenExpirationMinutes", 15);
        var refreshTokenDays = jwtSection.GetValue("RefreshTokenExpirationDays", 7);

        var jwtId = Guid.NewGuid().ToString();
        var accessTokenExpiresAtUtc = DateTime.UtcNow.AddMinutes(accessTokenMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, jwtId),
            new(ClaimTypes.NameIdentifier, user.Id),
        };
        if (!string.IsNullOrEmpty(user.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        }
        if (!string.IsNullOrEmpty(user.UserName))
        {
            claims.Add(new Claim(ClaimTypes.Name, user.UserName));
        }

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: accessTokenExpiresAtUtc,
            signingCredentials: credentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

        var (rawRefreshToken, refreshTokenExpiresAtUtc) = await CreateRefreshTokenAsync(user.Id, jwtId, refreshTokenDays);

        return new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenExpiresAtUtc = accessTokenExpiresAtUtc,
            RefreshToken = rawRefreshToken,
            RefreshTokenExpiresAtUtc = refreshTokenExpiresAtUtc,
        };
    }

    public async Task<TokenResponse?> RefreshAsync(string refreshToken)
    {
        var tokenHash = Hash(refreshToken);
        var existing = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
        if (existing is null || !existing.IsActive)
        {
            return null;
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == existing.UserId);
        if (user is null)
        {
            return null;
        }

        var jwtSection = _configuration.GetSection("Jwt");
        var refreshTokenDays = jwtSection.GetValue("RefreshTokenExpirationDays", 7);

        var newTokens = await IssueTokensAsync(user);

        existing.RevokedAtUtc = DateTime.UtcNow;
        existing.ReplacedByTokenHash = Hash(newTokens.RefreshToken);
        await _db.SaveChangesAsync();

        return newTokens;
    }

    public async Task<bool> RevokeAsync(string refreshToken, string userId)
    {
        var tokenHash = Hash(refreshToken);
        var existing = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
        if (existing is null || existing.UserId != userId)
        {
            return false;
        }

        if (existing.IsActive)
        {
            existing.RevokedAtUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }

        return true;
    }

    private async Task<(string rawToken, DateTime expiresAtUtc)> CreateRefreshTokenAsync(string userId, string jwtId, int refreshTokenDays)
    {
        var rawToken = GenerateRawToken();
        var expiresAtUtc = DateTime.UtcNow.AddDays(refreshTokenDays);

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = userId,
            TokenHash = Hash(rawToken),
            JwtId = jwtId,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = expiresAtUtc,
        });
        await _db.SaveChangesAsync();

        return (rawToken, expiresAtUtc);
    }

    private static string GenerateRawToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    private static string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }
}
