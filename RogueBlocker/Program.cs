using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RogueBlocker.Configuration;
using RogueBlocker.Services;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

// 配置日志目录
var logDirectory = Path.Combine(AppContext.BaseDirectory, "logs");
Console.WriteLine(logDirectory);

// 配置 Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.File(
        path: Path.Combine(logDirectory, "RogueBlocker-.log"),
        rollingInterval: RollingInterval.Day, // 按天滚动
        fileSizeLimitBytes: 1024 * 1024, // 1MB 大小限制
        rollOnFileSizeLimit: true, // 达到大小限制时滚动
        retainedFileCountLimit: 31, // 保留最近31个文件
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
    )
    .CreateLogger();
builder.Services.AddSerilog();

// 配置为 Windows 服务
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "RogueBlocker";
});

// 绑定配置
builder.Services.Configure<RogueBlockerOptions>(
    builder.Configuration.GetSection(RogueBlockerOptions.SectionName)
);

// 注册服务
builder.Services.AddSingleton<FirewallManager>();
builder.Services.AddSingleton<SecurityEventWatcher>();
builder.Services.AddHostedService<RogueBlockerService>();

var host = builder.Build();
host.Run();
