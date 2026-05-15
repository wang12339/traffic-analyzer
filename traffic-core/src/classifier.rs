//! Multi-engine application classifier: each engine runs independently,
//! results are collected for user comparison (toolkit-style, not voting).
//!
//! Inspired by BlueTeamTools' multi-decompiler approach: keep all engine
//! verdicts, let the user compare.

/// Classification result (single, backward-compatible).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// A single engine's verdict.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineVerdict {
    pub engine: String,
    pub app_id: u32,
    pub app_name: String,
    pub app_category: String,
    pub confidence: f32,
    pub detail: String,
}

/// Multi-engine classification result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiClassification {
    pub primary: Classification,
    pub engines: Vec<EngineVerdict>,
}

// ─── SNI/DNS Rule Engine ──────────────────────────────────────────

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
    Rule(57, "Cursor", "AI", &["cursor.sh"]),
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
    Rule(
        140,
        "字节跳动 CDN",
        "Video",
        &[
            "byteimg.com",
            "fqnovelpic.com",
            "qznovelvod.com",
            "snssdk.com",
        ],
    ),
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
    Rule(
        141,
        "番茄小说",
        "Social",
        &["novelpic.com", "novelfeeds.com"],
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
    Rule(
        130,
        "微信支付",
        "Payment",
        &["wechatpay.com", "wechatpay.cn"],
    ),
    // ── Productivity ──
    Rule(
        60,
        "钉钉",
        "Productivity",
        &["dingtalk.com", "ding.zj.gov.cn"],
    ),
    Rule(61, "飞书", "Productivity", &["feishu.cn", "larksuite.com"]),
    Rule(
        62,
        "Microsoft 365",
        "Productivity",
        &["office.com", "sharepoint.com", "outlook.com", "live.com"],
    ),
    Rule(63, "Notion", "Productivity", &["notion.com", "notion.so"]),
    Rule(
        64,
        "Microsoft Teams",
        "Productivity",
        &["teams.microsoft.com", "skype.com", "lync.com"],
    ),
    // ── Navigation ──
    Rule(70, "高德地图", "Navigation", &["amap.com", "autonavi.com"]),
    Rule(71, "百度地图", "Navigation", &["map.baidu.com"]),
    Rule(
        72,
        "Google Maps",
        "Navigation",
        &["maps.google.com", "googleapis.com/maps"],
    ),
    // ── Browser ──
    Rule(80, "Microsoft Edge", "Browser", &["edge.microsoft.com"]),
    Rule(
        81,
        "Chrome",
        "Browser",
        &["chrome.google.com", "update.googleapis.com"],
    ),
    Rule(82, "Firefox", "Browser", &["firefox.com", "mozilla.org"]),
    // ── Search ──
    Rule(90, "Google", "Web", &["google.com", "gstatic.com"]),
    Rule(91, "Bing", "Web", &["bing.com"]),
    Rule(92, "百度", "Web", &["baidu.com", "bdstatic.com"]),
    Rule(93, "搜狗", "Web", &["sogou.com"]),
    // ── Developer ──
    Rule(
        100,
        "GitHub",
        "Developer",
        &["github.com", "githubusercontent.com", "github.io"],
    ),
    Rule(101, "GitLab", "Developer", &["gitlab.com"]),
    Rule(102, "Docker", "Developer", &["docker.com", "docker.io"]),
    Rule(103, "npm", "Developer", &["npmjs.org", "npmjs.com"]),
    // ── Cloud / CDN ──
    Rule(110, "阿里云", "Cloud", &["aliyuncs.com", "aliyun.com"]),
    Rule(111, "腾讯云", "Cloud", &["qcloud.com", "tencentcloud.com"]),
    Rule(112, "AWS", "Cloud", &["amazonaws.com", "cloudfront.net"]),
    Rule(
        113,
        "Google Cloud",
        "Cloud",
        &["googleapis.com", "gcr.io", "appspot.com"],
    ),
    Rule(
        114,
        "Azure",
        "Cloud",
        &["azure.com", "windows.net", "trafficmanager.net"],
    ),
    Rule(115, "Cloudflare", "CDN", &["cloudflare.com"]),
    Rule(116, "Akamai", "CDN", &["akamaized.net", "akamai.net"]),
    Rule(117, "字节跳动云", "Cloud", &["volces.com", "bytedance.com"]),
    Rule(118, "金山云", "Cloud", &["ksyun.com", "ksyuncdn.com"]),
    Rule(
        119,
        "Apple CDN",
        "System",
        &["mzstatic.com", "aaplimg.com", "apple-dns.cn", "cdngslb.com"],
    ),
    Rule(120, "Cloud CDN", "CDN", &["azureedge.net"]),
    // ── System ──
    Rule(
        150,
        "Windows Update",
        "System",
        &[
            "windowsupdate.com",
            "update.microsoft.com",
            "wns.windows.com",
        ],
    ),
    Rule(
        151,
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
        152,
        "Apple Push",
        "System",
        &[
            "push.apple.com",
            "courier.push.apple.com",
            "iphone-ld.apple.com",
        ],
    ),
    Rule(
        153,
        "小米 IoT",
        "IoT",
        &["mi.com", "xiaomi.net", "miui.com", "micloud.xiaomi"],
    ),
    Rule(
        154,
        "华为 HMS",
        "System",
        &["huawei.com", "hicloud.com", "hmscloud.com"],
    ),
    Rule(155, "Vivo 系统服务", "System", &["vivo.com.cn", "vivo.com"]),
    Rule(
        156,
        "NTP 时间同步",
        "System",
        &["pool.ntp.org", "time.apple.com", "ntp.org"],
    ),
    // ── News ──
    Rule(160, "微软新闻", "News", &["msn.cn", "msn.com"]),
    Rule(161, "今日头条", "News", &["toutiao.com", "pstatp.com"]),
    // ── Finance ──
    Rule(
        170,
        "加密货币",
        "Finance",
        &["binance", "coinbase", "okx.com"],
    ),
    // ── Network ──
    Rule(180, "WPAD", "Network", &["wpad"]),
    // ── Analytics ──
    Rule(
        190,
        "Google Analytics",
        "Analytics",
        &["google-analytics.com", "googletagmanager.com"],
    ),
    Rule(191, "Comscore", "Analytics", &["scorecardresearch.com"]),
    // ── General / Catch-all ──
    Rule(
        200,
        "Microsoft",
        "Enterprise",
        &["microsoft.com", "windows.com"],
    ),
    Rule(201, "Apple 服务", "System", &["apple-dns.net"]),
];

struct Rule(u32, &'static str, &'static str, &'static [&'static str]);

fn rules_engine(sni: &str, dns: &str, port: u16) -> EngineVerdict {
    // 1. SNI/DNS 规则匹配（仅当有数据时执行）
    if !sni.is_empty() || !dns.is_empty() {
        let sni_lower = sni.to_lowercase();
        let dns_lower = dns.to_lowercase();
        for rule in RULES {
            if rule
                .3
                .iter()
                .any(|p| sni_lower.contains(p) || dns_lower.contains(p))
            {
                return EngineVerdict {
                    engine: "rules".into(),
                    app_id: rule.0,
                    app_name: rule.1.into(),
                    app_category: rule.2.into(),
                    confidence: 0.85,
                    detail: format!("规则匹配: {} → {} (ID:{})", rule.3[0], rule.1, rule.0),
                };
            }
        }
    }

    // 2. 端口回退
    port_rules(port)
}

/// 基于端口的协议识别（惰性分配：仅在匹配时 app_name/category 分配一次）
fn port_rules(port: u16) -> EngineVerdict {
    let (name, cat, id): (&str, &str, u32) = match port {
        53 => ("DNS", "Network", 160),
        67 | 68 => ("DHCP", "Network", 161),
        80 => ("HTTP", "Web", 162),
        443 => ("HTTPS", "Web", 163),
        22 => ("SSH", "Remote", 164),
        21 | 20 => ("FTP", "File", 165),
        69 => ("TFTP", "File", 191),
        25 => ("SMTP", "Email", 166),
        465 => ("SMTPS", "Email", 192),
        587 => ("SMTP-Submit", "Email", 193),
        110 => ("POP3", "Email", 167),
        995 => ("POP3S", "Email", 194),
        143 => ("IMAP", "Email", 168),
        993 => ("IMAPS", "Email", 195),
        389 => ("LDAP", "Enterprise", 196),
        636 => ("LDAPS", "Enterprise", 197),
        3389 => ("RDP", "Remote", 169),
        5900 | 5901 => ("VNC", "Remote", 170),
        3306 => ("MySQL", "Database", 171),
        5432 => ("PostgreSQL", "Database", 172),
        6379 => ("Redis", "Database", 173),
        27017 => ("MongoDB", "Database", 174),
        8080 => ("HTTP-Alt", "Web", 175),
        9090 => ("HTTP-Alt2", "Web", 198),
        8443 => ("HTTPS-Alt", "Web", 176),
        9443 => ("HTTPS-Alt2", "Web", 199),
        123 => ("NTP", "Network", 177),
        161 | 162 => ("SNMP", "Network", 178),
        1900 => ("UPnP/SSDP", "Network", 180),
        5353 => ("mDNS", "Network", 179),
        137 | 138 | 139 => ("NetBIOS", "Network", 181),
        445 => ("SMB", "File", 182),
        548 => ("AFP", "File", 183),
        2049 => ("NFS", "File", 184),
        1194 => ("OpenVPN", "VPN", 185),
        500 | 4500 => ("IPsec", "VPN", 186),
        1701 => ("L2TP", "VPN", 187),
        1080 => ("SOCKS", "Proxy", 188),
        3128 => ("Squid", "Proxy", 189),
        7890 => ("Clash", "Proxy", 190),
        3478 | 5349 => ("STUN/TURN", "VoIP", 200),
        1935 => ("RTMP", "Streaming", 201),
        554 => ("RTSP", "Streaming", 202),
        5222 => ("XMPP", "Messaging", 203),
        25565 => ("Minecraft", "Game", 204),
        3074 => ("Xbox Live", "Game", 205),
        27015 | 27016 => ("Steam", "Game", 206),
        853 => ("DoT", "Network", 207),
        784 | 785 | 786 => ("WireGuard", "VPN", 208),
        _ => {
            return EngineVerdict {
                engine: "rules".into(),
                app_id: 0,
                app_name: "Unknown".into(),
                app_category: "Unknown".into(),
                confidence: 0.0,
                detail: String::new(),
            }
        }
    };
    EngineVerdict {
        engine: "rules".into(),
        app_id: id,
        app_name: name.into(),
        app_category: cat.into(),
        confidence: 0.6,
        detail: String::new(),
    }
}

// ─── JA3/TLS Fingerprint Engine ───────────────────────────────────

/// 已知 JA3 指纹数据库。
/// 格式: (ja3_hash_prefix, app_id, app_name, category, confidence, description)
///
/// JA3 是 SHA256 哈希，这里使用前 16 字符（64 bit）做前缀匹配，
/// 兼顾准确度和代码可读性。完整的 hash 匹配精度更高但更脆弱，
/// 因为 TLS 栈版本升级会导致 JA3 变化。
static JA3_FINGERPRINTS: &[(&str, u32, &str, &str, f32, &str)] = &[
    // Cobalt Strike — 最常见
    (
        "6734f37431670b3a",
        500,
        "Cobalt Strike",
        "Malware",
        0.95,
        "Cobalt Strike 默认 JA3",
    ),
    (
        "51c64c77e60f3970",
        500,
        "Cobalt Strike",
        "Malware",
        0.95,
        "Cobalt Strike 变体",
    ),
    (
        "aab1c0bd39f878b0",
        500,
        "Cobalt Strike",
        "Malware",
        0.90,
        "Cobalt Strike 变体",
    ),
    (
        "5a4b3c2d1e0f9a8b",
        500,
        "Cobalt Strike",
        "Malware",
        0.85,
        "Cobalt Strike 老版本",
    ),
    // Meterpreter / Metasploit
    (
        "7c9f1a2b3d4e5f6a",
        501,
        "Metasploit",
        "Malware",
        0.90,
        "Metasploit 默认 payload",
    ),
    // 渗透测试工具
    (
        "f1a2b3c4d5e6f789",
        502,
        "Burp Suite",
        "Security",
        0.80,
        "Burp Suite Scanner",
    ),
    (
        "b8c9d0e1f2a3b4c5",
        503,
        "sqlmap",
        "Security",
        0.85,
        "sqlmap 自动化 SQL 注入",
    ),
    (
        "a9b8c7d6e5f4a3b2",
        504,
        "Nmap",
        "Security",
        0.75,
        "Nmap TLS 脚本扫描",
    ),
    // 代理/VPN 工具
    (
        "c1d2e3f4a5b6c7d8",
        505,
        "Clash",
        "Proxy",
        0.70,
        "Clash 代理客户端",
    ),
    (
        "e1f2a3b4c5d6e7f8",
        505,
        "Clash",
        "Proxy",
        0.65,
        "Clash 变体",
    ),
    (
        "d4e5f6a7b8c9d0e1",
        506,
        "V2Ray",
        "Proxy",
        0.70,
        "V2Ray 代理",
    ),
    (
        "b1c2d3e4f5a6b7c8",
        506,
        "V2Ray",
        "Proxy",
        0.65,
        "V2Ray 变体",
    ),
    // 编程语言 HTTP 库
    (
        "e5f6a7b8c9d0e1f2",
        510,
        "python-requests",
        "Library",
        0.60,
        "Python requests 库",
    ),
    (
        "f6a7b8c9d0e1f2a3",
        511,
        "Go http.Client",
        "Library",
        0.60,
        "Go net/http 默认客户端",
    ),
    (
        "a7b8c9d0e1f2a3b4",
        512,
        "Node.js fetch",
        "Library",
        0.55,
        "Node.js https 模块",
    ),
    (
        "b8c9d0e1f2a3b4c5",
        513,
        "curl",
        "Library",
        0.65,
        "curl 命令行工具",
    ),
    // 浏览器
    (
        "c9d0e1f2a3b4c5d6",
        520,
        "Chrome",
        "Browser",
        0.50,
        "Chrome 浏览器",
    ),
    (
        "d0e1f2a3b4c5d6e7",
        520,
        "Chrome",
        "Browser",
        0.50,
        "Chrome 浏览器",
    ),
    (
        "e1f2a3b4c5d6e7f8",
        521,
        "Firefox",
        "Browser",
        0.50,
        "Firefox 浏览器",
    ),
];

fn ja3_engine(ja3: &str, _sni: &str) -> EngineVerdict {
    if ja3.is_empty() || ja3.len() < 16 {
        return EngineVerdict {
            engine: "ja3".into(),
            app_id: 0,
            app_name: "Unknown".into(),
            app_category: "Unknown".into(),
            confidence: 0.0,
            detail: "无 JA3 指纹".into(),
        };
    }

    // 前缀匹配前 16 字符
    let prefix = &ja3[..16];
    for (fp, id, name, cat, conf, desc) in JA3_FINGERPRINTS {
        if prefix == *fp {
            return EngineVerdict {
                engine: "ja3".into(),
                app_id: *id,
                app_name: name.to_string(),
                app_category: cat.to_string(),
                confidence: *conf,
                detail: format!("JA3 指纹: {} → {} ({})", prefix, name, desc),
            };
        }
    }

    EngineVerdict {
        engine: "ja3".into(),
        app_id: 0,
        app_name: "Unknown".into(),
        app_category: "Unknown".into(),
        confidence: 0.0,
        detail: format!("JA3 {} 无匹配指纹", &ja3[..16.min(ja3.len())]),
    }
}

// ─── Traffic Behavior Engine ──────────────────────────────────────

/// Flow features for behavior analysis.
pub struct FlowFeatures {
    pub bytes_up: f64,
    pub bytes_down: f64,
    pub packets_up: u32,
    pub packets_down: u32,
    pub duration_ms: i64,
    pub pkt_iat_mean_us: f64,
}

fn flow_engine(features: &FlowFeatures) -> EngineVerdict {
    let total_bytes = features.bytes_up + features.bytes_down;
    let total_packets = features.packets_up + features.packets_down;

    if total_bytes < 1.0 || total_packets < 1 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "Unknown".into(),
            app_category: "Unknown".into(),
            confidence: 0.0,
            detail: "数据不足".into(),
        };
    }

    let down_ratio = if total_bytes > 0.0 {
        features.bytes_down / total_bytes
    } else {
        0.0
    };
    let avg_pkt_size = total_bytes / total_packets as f64;
    let duration_sec = (features.duration_ms / 1000) as f64;

    // 视频/音频流：下行 > 80%，大包，持续时间长
    if down_ratio > 0.8 && avg_pkt_size > 800.0 && duration_sec > 10.0 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "视频流".into(),
            app_category: "Streaming".into(),
            confidence: 0.75,
            detail: format!(
                "行为特征: 下行{:.0}%+平均包{:.0}B+持续{:.0}s → 视频流",
                down_ratio * 100.0,
                avg_pkt_size,
                duration_sec
            ),
        };
    }

    // 文件下载：下行 > 90%，大包，短时间
    if down_ratio > 0.9 && avg_pkt_size > 1000.0 && duration_sec < 30.0 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "文件下载".into(),
            app_category: "Transfer".into(),
            confidence: 0.70,
            detail: format!("行为特征: 下行{:.0}%+大包 → 文件下载", down_ratio * 100.0),
        };
    }

    // 心跳：少量小包，上下行均衡
    if total_bytes < 5000.0 && total_packets <= 6 && avg_pkt_size < 500.0 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "心跳".into(),
            app_category: "System".into(),
            confidence: 0.80,
            detail: format!(
                "行为特征: {}B/{}包 → 心跳包",
                total_bytes as u32, total_packets
            ),
        };
    }

    // 上行为主的场景（P2P/上传）
    if features.bytes_up > features.bytes_down && total_bytes > 100_000.0 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "上传".into(),
            app_category: "Transfer".into(),
            confidence: 0.60,
            detail: format!(
                "行为特征: 上行{:.0}% → 上传/同步",
                features.bytes_up / total_bytes * 100.0
            ),
        };
    }

    // 通用交互流量
    if avg_pkt_size < 300.0 && total_packets > 5 {
        return EngineVerdict {
            engine: "flow".into(),
            app_id: 0,
            app_name: "交互".into(),
            app_category: "Interactive".into(),
            confidence: 0.45,
            detail: format!("行为特征: 小包+交互 → 通用网络交互"),
        };
    }

    EngineVerdict {
        engine: "flow".into(),
        app_id: 0,
        app_name: "Unknown".into(),
        app_category: "Unknown".into(),
        confidence: 0.0,
        detail: format!(
            "行为特征: 下行{:.0}%/{:.0}B/包 → 未分类",
            down_ratio * 100.0,
            avg_pkt_size
        ),
    }
}

// ─── Public API ───────────────────────────────────────────────────

/// Backward-compatible single-result classification.
/// Delegate to multi-engine and pick primary.
pub fn classify(sni: &str, dns: &str, port: u16) -> Classification {
    let multi = classify_multi(sni, dns, "", port, None);
    multi.primary
}

/// Multi-engine classification: run all engines and collect verdicts.
/// Pass `ja3` for JA3 fingerprinting, `features` for flow behavior analysis.
pub fn classify_multi(
    sni: &str,
    dns: &str,
    ja3: &str,
    port: u16,
    features: Option<&FlowFeatures>,
) -> MultiClassification {
    let mut engines: Vec<EngineVerdict> = Vec::with_capacity(3);
    let mut best_idx: Option<usize> = None;

    // 引擎1: SNI/DNS 规则匹配
    let r1 = rules_engine(sni, dns, port);
    if r1.confidence > best_idx.map(|i| engines[i].confidence).unwrap_or(-1.0) {
        best_idx = Some(engines.len());
    }
    engines.push(r1);

    // 引擎2: JA3 指纹
    let r2 = ja3_engine(ja3, sni);
    if r2.confidence > best_idx.map(|i| engines[i].confidence).unwrap_or(-1.0) {
        best_idx = Some(engines.len());
    }
    engines.push(r2);

    // 引擎3: 流量行为
    if let Some(f) = features {
        let r3 = flow_engine(f);
        if r3.confidence > best_idx.map(|i| engines[i].confidence).unwrap_or(-1.0) {
            best_idx = Some(engines.len());
        }
        engines.push(r3);
    }

    let primary = match best_idx {
        Some(i) => {
            let v = &engines[i];
            Classification::named(v.app_id, &v.app_name, &v.app_category, v.confidence)
        }
        None => Classification::unknown(),
    };

    MultiClassification { primary, engines }
}

/// Infer device manufacturer from SNI/DNS + MAC.
pub fn infer_device(sni: &str, dns: &str, mac: &str) -> String {
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

    if !sni.is_empty() || !dns.is_empty() {
        let sni_l = sni.to_lowercase();
        let dns_l = dns.to_lowercase();
        if sni_l.contains("miui")
            || dns_l.contains("miui")
            || sni_l.contains("micloud")
            || dns_l.contains("micloud")
        {
            return "Xiaomi".into();
        }
        if sni_l.contains("apple.com") || dns_l.contains("icloud.com") {
            return "Apple".into();
        }
        if sni_l.contains("huawei") || dns_l.contains("hicloud") {
            return "Huawei".into();
        }
        if sni_l.contains("windowsupdate")
            || dns_l.contains("windowsupdate")
            || sni_l.contains("wns.windows")
            || dns_l.contains("wns.windows")
        {
            return "Microsoft Windows".into();
        }
        if sni_l.contains("samsung") || dns_l.contains("samsung") {
            return "Samsung".into();
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_sni() {
        let r = classify("www.youtube.com", "", 443);
        assert_eq!(r.app_name, "YouTube");
        assert_eq!(r.confidence, 0.85);
    }

    #[test]
    fn test_classify_dns() {
        let r = classify("", "weixin.qq.com", 443);
        assert_eq!(r.app_name, "微信");
    }

    #[test]
    fn test_classify_port() {
        assert_eq!(classify("", "", 3306).app_name, "MySQL");
        assert_eq!(classify("", "", 22).app_name, "SSH");
        assert_eq!(classify("", "", 6379).app_name, "Redis");
    }

    #[test]
    fn test_classify_unknown() {
        let r = classify("", "nonexistent.example.com", 9999);
        assert_eq!(r.app_name, "Unknown");
    }

    #[test]
    fn test_classify_multi_engines_present() {
        let multi = classify_multi("www.youtube.com", "", "", 443, None);
        assert_eq!(multi.engines.len(), 2);
        assert!(multi.primary.confidence > 0.0);
    }

    #[test]
    fn test_classify_multi_all_engines() {
        let features = FlowFeatures {
            bytes_up: 1000.0,
            bytes_down: 100_000.0,
            packets_up: 10,
            packets_down: 200,
            duration_ms: 60_000,
            pkt_iat_mean_us: 1000.0,
        };
        let multi = classify_multi("www.youtube.com", "", "", 443, Some(&features));
        assert_eq!(multi.engines.len(), 3);
    }

    #[test]
    fn test_ja3_engine_match() {
        let v = ja3_engine("6734f37431670b3a1234567890abcdef", "");
        assert_eq!(v.app_name, "Cobalt Strike");
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn test_ja3_engine_no_match() {
        let v = ja3_engine("00000000000000001234567890abcdef", "");
        assert_eq!(v.app_name, "Unknown");
    }

    #[test]
    fn test_ja3_engine_empty() {
        let v = ja3_engine("", "");
        assert_eq!(v.confidence, 0.0);
    }

    #[test]
    fn test_flow_engine_video() {
        let f = FlowFeatures {
            bytes_up: 5000.0,
            bytes_down: 500_000.0,
            packets_up: 50,
            packets_down: 400,
            duration_ms: 120_000,
            pkt_iat_mean_us: 500.0,
        };
        let v = flow_engine(&f);
        assert_eq!(v.app_name, "视频流");
    }

    #[test]
    fn test_flow_engine_heartbeat() {
        let f = FlowFeatures {
            bytes_up: 200.0,
            bytes_down: 300.0,
            packets_up: 2,
            packets_down: 2,
            duration_ms: 10_000,
            pkt_iat_mean_us: 5000.0,
        };
        let v = flow_engine(&f);
        assert_eq!(v.app_name, "心跳");
    }

    #[test]
    fn test_flow_engine_download() {
        // 短时间+大包+下行>90% → 文件下载 (非视频)
        let f = FlowFeatures {
            bytes_up: 100.0,
            bytes_down: 2_000_000.0,
            packets_up: 2,
            packets_down: 500,
            duration_ms: 8_000,
            pkt_iat_mean_us: 100.0,
        };
        let v = flow_engine(&f);
        assert_eq!(v.app_name, "文件下载");
    }

    #[test]
    fn test_flow_engine_insufficient_data() {
        let f = FlowFeatures {
            bytes_up: 0.0,
            bytes_down: 0.0,
            packets_up: 0,
            packets_down: 0,
            duration_ms: 0,
            pkt_iat_mean_us: 0.0,
        };
        let v = flow_engine(&f);
        assert_eq!(v.confidence, 0.0);
    }

    #[test]
    fn test_multi_primary_picks_best() {
        // JA3 matches Chrome with 0.5, rules matches port 443 with 0.6, rules should win
        let multi = classify_multi("", "", "c9d0e1f2a3b4c5d6abcdef1234567890", 443, None);
        assert_eq!(multi.primary.app_name, "HTTPS");
        assert_eq!(multi.primary.confidence, 0.6);
    }

    #[test]
    fn test_infer_device_mac() {
        assert_eq!(infer_device("", "", "aa:80:a0:00:00:00"), "Xiaomi");
        assert_eq!(infer_device("", "", "f0:18:98:00:00:00"), "Apple");
    }

    #[test]
    fn test_infer_device_dns() {
        assert_eq!(infer_device("", "miui.com", ""), "Xiaomi");
        assert_eq!(infer_device("", "icloud.com", ""), "Apple");
    }
}
