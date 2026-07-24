using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OAuthGoogleAPI.Dtos.Auth;
using OAuthGoogleAPI.Services;

namespace OAuthGoogleAPI.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager,
    ITokenService tokenService,
    IEmailSender emailSender,
    IConfiguration configuration,
    IWebHostEnvironment env) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IEmailSender _emailSender = emailSender;
    private readonly IConfiguration _configuration = configuration;
    private readonly IWebHostEnvironment _env = env;

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var existing = await _userManager.FindByEmailAsync(request.Email);
        if (existing is not null)
        {
            return BadRequest(new { error = "Email is already registered." });
        }

        var user = new IdentityUser { UserName = request.Email, Email = request.Email };
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={Uri.EscapeDataString(user.Id)}&token={Uri.EscapeDataString(token)}";
        await _emailSender.SendAsync(user.Email!, "Confirm your email", $"Confirm your account: {confirmUrl}");

        return Created(string.Empty, new
        {
            userId = user.Id,
            email = user.Email,
            confirmationToken = _env.IsDevelopment() ? token : null,
        });
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return BadRequest(new { error = "Invalid user." });
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { message = "Email confirmed." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid credentials." });
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (result.IsLockedOut)
        {
            return StatusCode(StatusCodes.Status423Locked, new { error = "Account locked out. Try again later." });
        }
        if (result.IsNotAllowed)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Email not confirmed." });
        }
        if (!result.Succeeded)
        {
            return Unauthorized(new { error = "Invalid credentials." });
        }

        var tokens = await _tokenService.IssueTokensAsync(user);
        return Ok(tokens);
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequest request)
    {
        var tokens = await _tokenService.RefreshAsync(request.RefreshToken);
        if (tokens is null)
        {
            return Unauthorized(new { error = "Invalid or expired refresh token." });
        }

        return Ok(tokens);
    }

    [Authorize]
    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken(RefreshTokenRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            return Unauthorized();
        }

        var revoked = await _tokenService.RevokeAsync(request.RefreshToken, userId);
        if (!revoked)
        {
            return NotFound(new { error = "Refresh token not found." });
        }

        return NoContent();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        string? token = null;
        if (user is not null && await _userManager.IsEmailConfirmedAsync(user))
        {
            token = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _emailSender.SendAsync(user.Email!, "Reset your password", $"Password reset token: {token}");
        }

        return Ok(new
        {
            message = "If that email is registered, a reset link has been sent.",
            resetToken = _env.IsDevelopment() ? token : null,
        });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return BadRequest(new { error = "Invalid request." });
        }

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { message = "Password has been reset." });
    }

    [HttpGet("google-login")]
    public IActionResult GoogleLogin()
    {
        var redirectUrl = Url.Action(nameof(GoogleCallback), "Auth", null, Request.Scheme);
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    [HttpGet("google-callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            return RedirectToFrontendWithError("external_login_failed");
        }

        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user is null)
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToFrontendWithError("no_email_from_google");
            }

            user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return RedirectToFrontendWithError("create_user_failed");
                }
            }

            var addLoginResult = await _userManager.AddLoginAsync(user, info);
            if (!addLoginResult.Succeeded)
            {
                return RedirectToFrontendWithError("link_login_failed");
            }
        }

        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        var tokens = await _tokenService.IssueTokensAsync(user);

        var redirectUrl = _configuration["Frontend:OAuthRedirectUrl"]!;
        var uri = QueryHelpers.AddQueryString(redirectUrl, new Dictionary<string, string?>
        {
            ["accessToken"] = tokens.AccessToken,
            ["refreshToken"] = tokens.RefreshToken,
        });
        return Redirect(uri);
    }

    private IActionResult RedirectToFrontendWithError(string error)
    {
        var redirectUrl = _configuration["Frontend:OAuthRedirectUrl"]!;
        var uri = QueryHelpers.AddQueryString(redirectUrl, "error", error);
        return Redirect(uri);
    }
}
