using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueBlocker.Configuration;

namespace RogueBlocker.Services;

public class FirewallManager
{
    private readonly ILogger<FirewallManager> _logger;
    private readonly RogueBlockerOptions _options;
    private readonly HashSet<string> _bannedIps = [];

    public FirewallManager(ILogger<FirewallManager> logger, IOptions<RogueBlockerOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    public async Task InitializeAsync()
    {
        await LoadExistingBannedIpsAsync();
        _logger.LogInformation(
            "防火墙管理器初始化完成，已加载 {Count} 个已封禁IP",
            _bannedIps.Count
        );
    }

    public bool IsIpBanned(string ip) => _bannedIps.Contains(ip);

    public bool IsIpWhitelisted(string ip) =>
        _options.WhitelistedIps.Contains(ip, StringComparer.OrdinalIgnoreCase);

    public async Task<bool> BanIpAsync(string ip, string reason)
    {
        if (string.IsNullOrWhiteSpace(ip) || ip == "-" || IsIpWhitelisted(ip))
        {
            return false;
        }

        if (_bannedIps.Contains(ip))
        {
            _logger.LogDebug("IP {Ip} 已被封禁，跳过", ip);
            return false;
        }

        var ruleName = $"{_options.FirewallRulePrefix}{ip.Replace(":", "_").Replace(".", "_")}";

        var result = await RunNetshCommandAsync(
            $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip={ip}"
        );

        if (result)
        {
            _bannedIps.Add(ip);
            _logger.LogWarning("已封禁IP: {Ip}，原因: {Reason}", ip, reason);
        }
        else
        {
            _logger.LogError("封禁IP失败: {Ip}", ip);
        }

        return result;
    }

    public async Task<bool> UnbanIpAsync(string ip)
    {
        var ruleName = $"{_options.FirewallRulePrefix}{ip.Replace(":", "_").Replace(".", "_")}";

        var result = await RunNetshCommandAsync(
            $"advfirewall firewall delete rule name=\"{ruleName}\""
        );

        if (result)
        {
            _bannedIps.Remove(ip);
            _logger.LogInformation("已解封IP: {Ip}", ip);
        }

        return result;
    }

    private async Task LoadExistingBannedIpsAsync()
    {
        try
        {
            var output = await RunNetshCommandWithOutputAsync(
                $"advfirewall firewall show rule name=all dir=in"
            );

            if (string.IsNullOrEmpty(output))
                return;

            var lines = output.Split('\n');
            string? currentRuleName = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.StartsWith("规则名称:") || trimmed.StartsWith("Rule Name:"))
                {
                    currentRuleName = trimmed.Split(':', 2).LastOrDefault()?.Trim();
                }
                else if (
                    (trimmed.StartsWith("RemoteIP:") || trimmed.StartsWith("远程 IP:"))
                    && currentRuleName?.StartsWith(_options.FirewallRulePrefix) == true
                )
                {
                    var ip = trimmed.Split(':', 2).LastOrDefault()?.Trim();
                    if (!string.IsNullOrEmpty(ip) && ip != "Any")
                    {
                        _bannedIps.Add(ip);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "加载已封禁IP列表失败");
        }
    }

    private async Task<bool> RunNetshCommandAsync(string arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                },
            };

            process.Start();
            await process.WaitForExitAsync();

            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "执行netsh命令失败: {Arguments}", arguments);
            return false;
        }
    }

    private async Task<string> RunNetshCommandWithOutputAsync(string arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.Default, // 关键
                    StandardErrorEncoding = Encoding.Default, // 可选
                },
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            return output;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "执行netsh命令失败: {Arguments}", arguments);
            return string.Empty;
        }
    }
}
