using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueBlocker.Configuration;

namespace RogueBlocker.Services;

public class SecurityEventWatcher : IDisposable
{
    private readonly ILogger<SecurityEventWatcher> _logger;
    private readonly RogueBlockerOptions _options;
    private readonly FirewallManager _firewallManager;
    private EventLogWatcher? _watcher;
    private readonly HashSet<string> _allowedUsernamesLower;

    // 事件ID 4625: 登录失败
    private const int EventIdLogonFailed = 4625;

    public SecurityEventWatcher(
        ILogger<SecurityEventWatcher> logger,
        IOptions<RogueBlockerOptions> options,
        FirewallManager firewallManager)
    {
        _logger = logger;
        _options = options.Value;
        _firewallManager = firewallManager;
        _allowedUsernamesLower = _options.AllowedUsernames
            .Select(u => u.ToLowerInvariant())
            .ToHashSet();
    }

    public void Start()
    {
        try
        {
            // 查询安全日志中的登录失败事件
            var query = new EventLogQuery(
                "Security",
                PathType.LogName,
                $"*[System[EventID={EventIdLogonFailed}]]");

            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;

            _logger.LogInformation("安全事件监视器已启动，监听登录失败事件 (EventID: {EventId})", EventIdLogonFailed);
            _logger.LogInformation("允许的用户名: {Usernames}", string.Join(", ", _options.AllowedUsernames));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "启动安全事件监视器失败，请确保以管理员权限运行");
            throw;
        }
    }

    public void Stop()
    {
        if (_watcher != null)
        {
            _watcher.Enabled = false;
            _watcher.EventRecordWritten -= OnEventRecordWritten;
            _logger.LogInformation("安全事件监视器已停止");
        }
    }

    private async void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord == null)
                return;

            var eventRecord = e.EventRecord;
            var properties = GetEventProperties(eventRecord);

            if (properties == null)
                return;

            var targetUsername = properties.TargetUsername;
            var sourceIp = properties.SourceIp;

            if (string.IsNullOrWhiteSpace(sourceIp) || sourceIp == "-")
            {
                _logger.LogDebug("忽略无IP的登录失败事件，用户名: {Username}", targetUsername);
                return;
            }

            _logger.LogInformation(
                "检测到登录失败 - 用户名: {Username}, 来源IP: {Ip}, 工作站: {Workstation}",
                targetUsername, sourceIp, properties.WorkstationName);

            // 检查用户名是否在允许列表中
            if (!IsUsernameAllowed(targetUsername))
            {
                _logger.LogWarning(
                    "检测到非法用户名登录尝试: {Username} 来自 {Ip}",
                    targetUsername, sourceIp);

                await _firewallManager.BanIpAsync(sourceIp, $"使用非法用户名 '{targetUsername}' 尝试登录");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "处理安全事件失败");
        }
    }

    private bool IsUsernameAllowed(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        return _allowedUsernamesLower.Contains(username.ToLowerInvariant());
    }

    private LoginAttemptInfo? GetEventProperties(EventRecord eventRecord)
    {
        try
        {
            // Event 4625 属性索引:
            // 5: 目标用户名 (TargetUserName)
            // 6: 目标域 (TargetDomainName)
            // 11: 工作站名 (WorkstationName)
            // 19: 源网络地址 (IpAddress)

            var properties = ((EventLogRecord)eventRecord).Properties;

            if (properties.Count < 20)
                return null;

            return new LoginAttemptInfo
            {
                TargetUsername = properties[5]?.Value?.ToString(),
                TargetDomain = properties[6]?.Value?.ToString(),
                WorkstationName = properties[11]?.Value?.ToString(),
                SourceIp = properties[19]?.Value?.ToString()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "解析事件属性失败");
            return null;
        }
    }

    public void Dispose()
    {
        _watcher?.Dispose();
    }

    private class LoginAttemptInfo
    {
        public string? TargetUsername { get; init; }
        public string? TargetDomain { get; init; }
        public string? WorkstationName { get; init; }
        public string? SourceIp { get; init; }
    }
}
