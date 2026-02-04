using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace RogueBlocker.Services;

public class RogueBlockerService : BackgroundService
{
    private readonly ILogger<RogueBlockerService> _logger;
    private readonly SecurityEventWatcher _eventWatcher;
    private readonly FirewallManager _firewallManager;

    public RogueBlockerService(
        ILogger<RogueBlockerService> logger,
        SecurityEventWatcher eventWatcher,
        FirewallManager firewallManager)
    {
        _logger = logger;
        _eventWatcher = eventWatcher;
        _firewallManager = firewallManager;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("RogueBlocker 服务正在启动...");

        try
        {
            await _firewallManager.InitializeAsync();
            _eventWatcher.Start();

            _logger.LogInformation("RogueBlocker 服务已成功启动");

            // 保持服务运行
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("RogueBlocker 服务正在停止...");
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "RogueBlocker 服务发生致命错误");
            throw;
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _eventWatcher.Stop();
        _logger.LogInformation("RogueBlocker 服务已停止");
        return base.StopAsync(cancellationToken);
    }
}
