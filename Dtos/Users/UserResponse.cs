namespace OAuthGoogleAPI.Dtos.Users;

public class UserResponse
{
    public string Id { get; set; } = default!;
    public string? Email { get; set; }
    public bool EmailConfirmed { get; set; }
    public string? UserName { get; set; }
    public string? PhoneNumber { get; set; }
}
