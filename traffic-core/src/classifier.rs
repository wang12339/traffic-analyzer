//! Universal application classifier: SNI/DNS/UA + port → app name + category.
//! Single source of truth used by both ingest and API paths.

/// Classification result.
#[derive(Debug, Clone)]
pub struct Classification {
    pub app_id: u32,
    pub app_name: String,
    pub app_category: String,
    pub confidence: f32,
}

impl Classification {
    pub fn unknown() -> Self {
        Self {
            app_id: 0,
            app_name: "Unknown".into(),
            app_category: "Unknown".into(),
            confidence: 0.0,
        }
    }
    pub fn named(id: u32, name: &str, cat: &str, conf: f32) -> Self {
        Self {
            app_id: id,
            app_name: name.into(),
            app_category: cat.into(),
            confidence: conf,
        }
    }
}

static RULES: &[Rule] = &[
    // ── AI Services ──
    Rule(
        50,
        "ChatGPT",
        "AI",
        &["chatgpt.com", "openai.com", "oaistatic.com"],
    ),
    Rule(
        51,
        "Claude",
        "AI",
        &["anthropic.com", "claude.ai", "claudeusercontent.com"],
    ),
    Rule(52, "DeepSeek", "AI", &["deepseek.com"]),
    Rule(
        53,
        "Gemini",
        "AI",
        &["gemini.google.com", "bard.google.com"],
    ),
    Rule(54, "Kimi", "AI", &["kimi.moonshot.cn", "moonshot.cn"]),
    Rule(55, "Coze", "AI", &["coze.com"]),
    Rule(56, "通义千问", "AI", &["tongyi.aliyun.com", "qwen.ai"]),
    // ── Video Streaming ──
    Rule(
        1,
        "YouTube",
        "Video",
        &[
            "youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "withgoogle.com",
        ],
    ),
    Rule(
        2,
        "Netflix",
        "Video",
        &["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
    ),
    Rule(
        3,
        "抖音/TikTok",
        "Video",
        &[
            "douyin.com",
            "tiktok.com",
            "amemv.com",
            "douyinvod.com",
            "douyinpic.com",
            "byteoversea.com",
        ],
    ),
    Rule(4, "Bilibili", "Video", &["bilibili.com", "hdslb.com"]),
    Rule(5, "爱奇艺", "Video", &["iqiyi.com", "qiyi.com"]),
    Rule(6, "腾讯视频", "Video", &["v.qq.com", "qqvideo"]),
    Rule(7, "优酷", "Video", &["youku.com", "ykimg.com"]),
    Rule(8, "芒果TV", "Video", &["mgtv.com"]),
    Rule(9, "Twitch", "Video", &["twitch.tv", "twitchcdn.net"]),
    // ── Social / Messaging ──
    Rule(
        10,
        "微信",
        "Social",
        &["weixin.qq.com", "wechat.com", "weixinbridge.com"],
    ),
    Rule(11, "微博", "Social", &["weibo.com", "weibo.cn"]),
    Rule(12, "小红书", "Social", &["xiaohongshu.com", "xhscdn.com"]),
    Rule(13, "知乎", "Social", &["zhihu.com"]),
    Rule(
        14,
        "Instagram",
        "Social",
        &["instagram.com", "cdninstagram.com"],
    ),
    Rule(
        15,
        "Twitter/X",
        "Social",
        &["twitter.com", "x.com", "twimg.com"],
    ),
    Rule(16, "WhatsApp", "Social", &["whatsapp.com", "whatsapp.net"]),
    Rule(
        17,
        "Telegram",
        "Social",
        &["telegram.org", "t.me", "cdn-telegram.org"],
    ),
    Rule(
        18,
        "Discord",
        "Social",
        &["discord.com", "discordapp.com", "discord.gg"],
    ),
    Rule(19, "Slack", "Social", &["slack.com", "slack-msgs.com"]),
    Rule(
        20,
        "QQ",
        "Social",
        &["qq.com", "qzone.qq.com", "connect.qq.com"],
    ),
    // ── Music ──
    Rule(
        30,
        "QQ 音乐",
        "Music",
        &["y.qq.com", "qqmusic.qq.com", "qpic.cn", "gtimg.cn"],
    ),
    Rule(31, "网易云音乐", "Music", &["163.com", "music.163"]),
    Rule(32, "Spotify", "Music", &["spotify.com", "scdn.co"]),
    Rule(33, "酷狗音乐", "Music", &["kugou.com"]),
    Rule(34, "酷我音乐", "Music", &["kuwo.cn"]),
    // ── E-commerce ──
    Rule(40, "淘宝/天猫", "Shopping", &["taobao.com", "tmall.com"]),
    Rule(41, "京东", "Shopping", &["jd.com", "jdpay.com"]),
    Rule(
        42,
        "拼多多",
        "Shopping",
        &["pinduoduo.com", "yangkeduo.com"],
    ),
    Rule(43, "Amazon", "Shopping", &["amazon.com"]),
    Rule(44, "美团", "Shopping", &["meituan.com", "dianping.com"]),
    // ── Payment ──
    Rule(
        45,
        "支付宝",
        "Payment",
        &["alipay.com", "alipayobjects.com"],
    ),
    Rule(46, "PayPal", "Payment", &["paypal.com"]),
    // ── Productivity ──
    Rule(
        50,
        "钉钉",
        "Productivity",
        &["dingtalk.com", "ding.zj.gov.cn"],
    ),
    Rule(51, "飞书", "Productivity", &["feishu.cn", "larksuite.com"]),
    Rule(
        52,
        "Microsoft 365",
        "Productivity",
        &["office.com", "sharepoint.com", "outlook.com", "live.com"],
    ),
    Rule(53, "Notion", "Productivity", &["notion.com", "notion.so"]),
    // ── Navigation ──
    Rule(60, "高德地图", "Navigation", &["amap.com", "autonavi.com"]),
    Rule(61, "百度地图", "Navigation", &["map.baidu.com"]),
    Rule(
        62,
        "Google Maps",
        "Navigation",
        &["maps.google.com", "googleapis.com/maps"],
    ),
    // ── Browser ──
    Rule(70, "Microsoft Edge", "Browser", &["edge.microsoft.com"]),
    Rule(
        71,
        "Chrome",
        "Browser",
        &["chrome.google.com", "update.googleapis.com"],
    ),
    Rule(72, "Firefox", "Browser", &["firefox.com", "mozilla.org"]),
    // ── Search ──
    Rule(80, "Google", "Web", &["google.com", "gstatic.com"]),
    Rule(81, "Bing", "Web", &["bing.com"]),
    Rule(82, "百度", "Web", &["baidu.com", "bdstatic.com"]),
    Rule(83, "搜狗", "Web", &["sogou.com"]),
    // ── Developer ──
    Rule(
        90,
        "GitHub",
        "Developer",
        &["github.com", "githubusercontent.com", "github.io"],
    ),
    Rule(91, "GitLab", "Developer", &["gitlab.com"]),
    Rule(92, "Docker", "Developer", &["docker.com", "docker.io"]),
    // ── Cloud / CDN ──
    Rule(100, "阿里云", "Cloud", &["aliyuncs.com", "aliyun.com"]),
    Rule(101, "腾讯云", "Cloud", &["qcloud.com", "tencentcloud.com"]),
    Rule(102, "AWS", "Cloud", &["amazonaws.com", "cloudfront.net"]),
    Rule(
        103,
        "Google Cloud",
        "Cloud",
        &["googleapis.com", "gcr.io", "appspot.com"],
    ),
    Rule(
        104,
        "Azure",
        "Cloud",
        &["azure.com", "windows.net", "trafficmanager.net"],
    ),
    Rule(105, "Cloudflare", "CDN", &["cloudflare.com"]),
    Rule(106, "Akamai", "CDN", &["akamaized.net", "akamai.net"]),
    Rule(107, "字节跳动云", "Cloud", &["volces.com", "bytedance.com"]),
    Rule(108, "金山云", "Cloud", &["ksyun.com", "ksyuncdn.com"]),
    // ── System ──
    Rule(
        110,
        "Windows Update",
        "System",
        &[
            "windowsupdate.com",
            "update.microsoft.com",
            "wns.windows.com",
        ],
    ),
    Rule(
        111,
        "Apple 系统服务",
        "System",
        &[
            "apple.com",
            "icloud.com",
            "guzzoni.apple.com",
            "configuration.apple.com",
        ],
    ),
    Rule(
        112,
        "Apple Push",
        "System",
        &[
            "push.apple.com",
            "courier.push.apple.com",
            "iphone-ld.apple.com",
        ],
    ),
    Rule(
        113,
        "小米 IoT",
        "IoT",
        &["mi.com", "xiaomi.net", "miui.com", "micloud.xiaomi"],
    ),
    Rule(
        114,
        "华为 HMS",
        "System",
        &["huawei.com", "hicloud.com", "hmscloud.com"],
    ),
    // ── News ──
    Rule(120, "微软新闻", "News", &["msn.cn", "msn.com"]),
    Rule(121, "今日头条", "News", &["toutiao.com", "pstatp.com"]),
    // ── Finance ──
    Rule(
        130,
        "加密货币",
        "Finance",
        &["hotcoins", "binance", "coinbase", "okx.com"],
    ),
    // ── AI (new) ──
    Rule(57, "Cursor", "AI", &["cursor.sh"]),
    // ── ByteDance (抖音/头条/番茄) ──
    Rule(150, "字节跳动 CDN", "Video", &["byteimg.com", "fqnovelpic.com", "qznovelvod.com", "snssdk.com"]),
    Rule(151, "番茄小说", "Social", &["novelpic.com", "novelfeeds.com"]),
    // ── Device/System ──
    Rule(152, "Vivo 系统服务", "System", &["vivo.com.cn", "vivo.com"]),
    // ── Network ──
    Rule(154, "WPAD", "Network", &["wpad"]),
    // ── Analytics ──
    Rule(140, "Comscore", "Analytics", &["scorecardresearch.com"]),
    Rule(
        141,
        "Google Analytics",
        "Analytics",
        &["google-analytics.com", "googletagmanager.com"],
    ),
];

struct Rule(u32, &'static str, &'static str, &'static [&'static str]);

/// Classify based on SNI, DNS, and port.
/// Falls back to port-based service detection when L7 data is unavailable.
pub fn classify(sni: &str, dns: &str, port: u16) -> Classification {
    let combined = format!("{} {}", sni.to_lowercase(), dns.to_lowercase());

    for rule in RULES {
        if rule.3.iter().any(|p| combined.contains(p)) {
            return Classification::named(rule.0, rule.1, rule.2, 0.85);
        }
    }

    // Port-based fallback when SNI/DNS is unavailable
    if sni.is_empty() && dns.is_empty() {
        match port {
            53 => return Classification::named(160, "DNS", "Network", 0.6),
            67 | 68 => return Classification::named(161, "DHCP", "Network", 0.6),
            80 => return Classification::named(162, "HTTP", "Web", 0.6),
            443 => return Classification::named(163, "HTTPS", "Web", 0.6),
            22 => return Classification::named(164, "SSH", "Remote", 0.6),
            21 | 20 => return Classification::named(165, "FTP", "File", 0.6),
            69 => return Classification::named(191, "TFTP", "File", 0.6),
            25 => return Classification::named(166, "SMTP", "Email", 0.6),
            465 => return Classification::named(192, "SMTPS", "Email", 0.6),
            587 => return Classification::named(193, "SMTP-Submit", "Email", 0.6),
            110 => return Classification::named(167, "POP3", "Email", 0.6),
            995 => return Classification::named(194, "POP3S", "Email", 0.6),
            143 => return Classification::named(168, "IMAP", "Email", 0.6),
            993 => return Classification::named(195, "IMAPS", "Email", 0.6),
            389 => return Classification::named(196, "LDAP", "Enterprise", 0.6),
            636 => return Classification::named(197, "LDAPS", "Enterprise", 0.6),
            3389 => return Classification::named(169, "RDP", "Remote", 0.6),
            5900 | 5901 => return Classification::named(170, "VNC", "Remote", 0.6),
            3306 => return Classification::named(171, "MySQL", "Database", 0.6),
            5432 => return Classification::named(172, "PostgreSQL", "Database", 0.6),
            6379 => return Classification::named(173, "Redis", "Database", 0.6),
            27017 => return Classification::named(174, "MongoDB", "Database", 0.6),
            8080 => return Classification::named(175, "HTTP-Alt", "Web", 0.6),
            9090 => return Classification::named(198, "HTTP-Alt2", "Web", 0.6),
            8443 => return Classification::named(176, "HTTPS-Alt", "Web", 0.6),
            9443 => return Classification::named(199, "HTTPS-Alt2", "Web", 0.6),
            123 => return Classification::named(177, "NTP", "Network", 0.6),
            161 | 162 => return Classification::named(178, "SNMP", "Network", 0.6),
            1900 => return Classification::named(180, "UPnP/SSDP", "Network", 0.6),
            5353 => return Classification::named(179, "mDNS", "Network", 0.6),
            137 | 138 | 139 => return Classification::named(181, "NetBIOS", "Network", 0.6),
            445 => return Classification::named(182, "SMB", "File", 0.6),
            548 => return Classification::named(183, "AFP", "File", 0.6),
            2049 => return Classification::named(184, "NFS", "File", 0.6),
            1194 => return Classification::named(185, "OpenVPN", "VPN", 0.6),
            500 | 4500 => return Classification::named(186, "IPsec", "VPN", 0.6),
            1701 => return Classification::named(187, "L2TP", "VPN", 0.6),
            1080 => return Classification::named(188, "SOCKS", "Proxy", 0.6),
            3128 => return Classification::named(189, "Squid", "Proxy", 0.6),
            7890 => return Classification::named(190, "Clash", "Proxy", 0.6),
            3478 | 5349 => return Classification::named(200, "STUN/TURN", "VoIP", 0.6),
            1935 => return Classification::named(201, "RTMP", "Streaming", 0.6),
            554 => return Classification::named(202, "RTSP", "Streaming", 0.6),
            5222 => return Classification::named(203, "XMPP", "Messaging", 0.6),
            25565 => return Classification::named(204, "Minecraft", "Game", 0.6),
            3074 => return Classification::named(205, "Xbox Live", "Game", 0.6),
            27015 | 27016 => return Classification::named(206, "Steam", "Game", 0.6),
            _ => {}
        }
    }

    Classification::unknown()
}

/// Infer device manufacturer from SNI/DNS + MAC.
pub fn infer_device(sni: &str, dns: &str, mac: &str) -> String {
    let combined = format!("{} {}", sni.to_lowercase(), dns.to_lowercase());
    let mac_lower = mac.to_lowercase();
    let mac_pref = if mac.len() >= 8 { &mac_lower[..8] } else { "" };

    if mac_pref == "aa:80:a0" || mac_pref == "de:2c:28" {
        return "Xiaomi".into();
    }
    if mac_pref == "5e:8f:c9" || mac_pref == "6c:1f:f7" || mac_pref == "f0:18:98" {
        return "Apple".into();
    }
    if mac_pref == "ea:0c:af" {
        return "NRadio".into();
    }
    if mac_pref == "b4:6e:10" || mac_pref == "3a:a4:28" {
        return "Vivo".into();
    }
    if mac_pref == "e2:08:f4" || mac_pref == "5a:e2:02" {
        return "Clash/Stash".into();
    }

    if combined.contains("miui") || combined.contains("micloud") {
        return "Xiaomi".into();
    }
    if combined.contains("apple.com")
        || combined.contains("icloud.com")
        || combined.contains("push.apple.com")
    {
        return "Apple".into();
    }
    if combined.contains("huawei") || combined.contains("hicloud") {
        return "Huawei".into();
    }
    if combined.contains("windowsupdate") || combined.contains("wns.windows") {
        return "Microsoft Windows".into();
    }
    if combined.contains("samsung") {
        return "Samsung".into();
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_sni() {
        assert_eq!(classify("www.youtube.com", "", 443).app_name, "YouTube");
        assert_eq!(classify("chatgpt.com", "", 443).app_name, "ChatGPT");
        assert_eq!(classify("anthropic.com", "", 443).app_name, "Claude");
    }

    #[test]
    fn test_classify_dns() {
        let r = classify("", "weixin.qq.com", 443);
        assert_eq!(r.app_name, "微信");
    }

    #[test]
    fn test_classify_combined_prefers_first_match() {
        let r = classify("www.youtube.com", "weixin.qq.com", 443);
        assert_eq!(r.app_name, "YouTube");
    }

    #[test]
    fn test_classify_case_insensitive() {
        assert_eq!(classify("WWW.YOUTUBE.COM", "", 443).app_name, "YouTube");
        assert_eq!(classify("Api.GitHub.Com", "", 443).app_name, "GitHub");
    }

    #[test]
    fn test_classify_unknown() {
        let r = classify("", "nonexistent-domain-xyz.example", 443);
        assert_eq!(r.app_name, "Unknown");
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn test_infer_device_mac_prefix() {
        assert_eq!(infer_device("", "", "aa:80:a0:00:00:00"), "Xiaomi");
        assert_eq!(infer_device("", "", "de:2c:28:00:00:00"), "Xiaomi");
        assert_eq!(infer_device("", "", "f0:18:98:00:00:00"), "Apple");
        assert_eq!(infer_device("", "", "ff:ff:ff:00:00:00"), "");
    }

    #[test]
    fn test_infer_device_dns_patterns() {
        assert_eq!(infer_device("", "miui.com", ""), "Xiaomi");
        assert_eq!(infer_device("", "icloud.com", ""), "Apple");
        assert_eq!(infer_device("", "wns.windows.com", ""), "Microsoft Windows");
    }

    #[test]
    fn test_classify_by_port() {
        assert_eq!(classify("", "", 443).app_name, "HTTPS");
        assert_eq!(classify("", "", 80).app_name, "HTTP");
        assert_eq!(classify("", "", 53).app_name, "DNS");
        assert_eq!(classify("", "", 22).app_name, "SSH");
        assert_eq!(classify("", "", 3306).app_name, "MySQL");
        assert_eq!(classify("", "", 8080).app_name, "HTTP-Alt");
        assert_eq!(classify("", "", 9090).app_name, "HTTP-Alt2");
        assert_eq!(classify("", "", 1900).app_name, "UPnP/SSDP");
        assert_eq!(classify("", "", 445).app_name, "SMB");
        assert_eq!(classify("", "", 1194).app_name, "OpenVPN");
        assert_eq!(classify("", "", 7890).app_name, "Clash");
        assert_eq!(classify("", "", 9999).app_name, "Unknown");
    }

    #[test]
    fn test_sni_takes_priority_over_port() {
        // SNI should match before port fallback
        assert_eq!(classify("www.youtube.com", "", 443).app_name, "YouTube");
        assert_eq!(classify("", "weixin.qq.com", 443).app_name, "微信");
    }

    #[test]
    fn test_rule_coverage() {
        // Spot-check a few categories
        assert_eq!(classify("", "douyin.com", 443).app_name, "抖音/TikTok");
        assert_eq!(classify("", "github.com", 443).app_name, "GitHub");
        assert_eq!(classify("", "taobao.com", 443).app_name, "淘宝/天猫");
        assert_eq!(classify("", "amap.com", 443).app_name, "高德地图");
    }
}
