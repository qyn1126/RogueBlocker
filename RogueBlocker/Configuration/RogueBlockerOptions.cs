namespace RogueBlocker.Configuration;

public class RogueBlockerOptions
{
    public const string SectionName = "RogueBlocker";

    /// <summary>
    /// 允许登录的用户名列表（不区分大小写）
    /// </summary>
    public List<string> AllowedUsernames { get; set; } = [];

    /// <summary>
    /// 防火墙规则名称前缀
    /// </summary>
    public string FirewallRulePrefix { get; set; } = "RogueBlocker_Ban_";

    /// <summary>
    /// 是否启用日志记录封禁的IP
    /// </summary>
    public bool LogBannedIps { get; set; } = true;

    /// <summary>
    /// IP白名单（永不封禁）
    /// </summary>
    public List<string> WhitelistedIps { get; set; } = ["127.0.0.1", "::1"];
}
