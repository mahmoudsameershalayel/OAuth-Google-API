namespace OAuthGoogleAPI.Services;

/// <summary>
/// Dev stand-in: the original MVC app also has no working IEmailSender, so its
/// RequireConfirmedAccount flow never actually delivers mail. This logs instead
/// of sending, so it's an obvious placeholder to replace (e.g. SendGrid) before
/// any real deployment.
/// </summary>
public class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : IEmailSender
{
    private readonly ILogger<LoggingEmailSender> _logger = logger;

    public Task SendAsync(string toEmail, string subject, string body)
    {
        _logger.LogInformation("Email to {ToEmail} | {Subject} | {Body}", toEmail, subject, body);
        return Task.CompletedTask;
    }
}
