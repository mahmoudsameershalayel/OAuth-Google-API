using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OAuthGoogleAPI.Dtos.Users;

namespace OAuthGoogleAPI.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        return Ok(ToResponse(user));
    }

    [HttpPut("me")]
    public async Task<IActionResult> UpdateMe(UpdateProfileRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        if (request.UserName is not null && request.UserName != user.UserName)
        {
            var setUserNameResult = await _userManager.SetUserNameAsync(user, request.UserName);
            if (!setUserNameResult.Succeeded)
            {
                return BadRequest(new { errors = setUserNameResult.Errors.Select(e => e.Description) });
            }
        }

        if (request.PhoneNumber is not null && request.PhoneNumber != user.PhoneNumber)
        {
            var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, request.PhoneNumber);
            if (!setPhoneResult.Succeeded)
            {
                return BadRequest(new { errors = setPhoneResult.Errors.Select(e => e.Description) });
            }
        }

        return Ok(ToResponse(user));
    }

    [HttpPost("me/change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { message = "Password changed." });
    }

    private static UserResponse ToResponse(IdentityUser user) => new()
    {
        Id = user.Id,
        Email = user.Email,
        EmailConfirmed = user.EmailConfirmed,
        UserName = user.UserName,
        PhoneNumber = user.PhoneNumber,
    };
}
