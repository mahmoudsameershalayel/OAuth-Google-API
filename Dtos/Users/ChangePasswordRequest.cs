using System.ComponentModel.DataAnnotations;

namespace OAuthGoogleAPI.Dtos.Users;

public class ChangePasswordRequest
{
    [Required]
    public string CurrentPassword { get; set; } = default!;

    [Required]
    public string NewPassword { get; set; } = default!;
}
