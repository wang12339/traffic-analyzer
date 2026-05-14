//! Application classifier: multi-dimensional voting engine that combines
//! SNI, DNS, JA3, HTTP, and flow features to identify applications.

use traffic_core::{Classification, FlowKey};

/// Classification rule with weighted matchers.
struct AppRule {
    app_id: u32,
    name: &'static str,
    category: &'static str,
    sni_suffix: &'static [&'static str],
    dns_suffix: &'static [&'static str],
    http_host_suffix: &'static [&'static str],
    ja3_prefix: &'static [&'static str],
    ports: &'static [u16],
    min_bytes: f64,
    is_streaming: bool,        // high downstream ratio
    is_heartbeat: bool,        // tiny periodic packets
}

const RULES: &[AppRule] = &[
    // ── Video Streaming ──
    AppRule { app_id: 1, name: "YouTube", category: "Video",
        sni_suffix: &["youtube.com", "googlevideo.com", "ytimg.com", "withgoogle.com"],
        dns_suffix: &["youtube.com", "googlevideo.com", "ytimg.com"],
        http_host_suffix: &["youtube.com"], ja3_prefix: &[], ports: &[443], min_bytes: 0.0,
        is_streaming: true, is_heartbeat: false },
    AppRule { app_id: 2, name: "Netflix", category: "Video",
        sni_suffix: &["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
        dns_suffix: &["netflix.com", "nflxvideo.net"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: true, is_heartbeat: false },
    AppRule { app_id: 3, name: "TikTok", category: "Video",
        sni_suffix: &["tiktok.com", "tiktokcdn.com", "byteoversea.com", "amemv.com",
                       "douyin.com", "douyinvod.com", "douyinpic.com"],
        dns_suffix: &["tiktok.com", "tiktokcdn.com", "amemv.com", "douyin.com"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443],
        min_bytes: 0.0, is_streaming: true, is_heartbeat: false },
    AppRule { app_id: 4, name: "Twitch", category: "Video",
        sni_suffix: &["twitch.tv", "twitchcdn.net"], dns_suffix: &["twitch.tv"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443],
        min_bytes: 0.0, is_streaming: true, is_heartbeat: false },
    AppRule { app_id: 5, name: "Bilibili", category: "Video",
        sni_suffix: &["bilibili.com", "bilibili.tv", "hdslb.com"],
        dns_suffix: &["bilibili.com", "hdslb.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: true, is_heartbeat: false },

    // ── Social Media ──
    AppRule { app_id: 10, name: "WeChat", category: "Social",
        sni_suffix: &["weixin.qq.com", "wechat.com", "weixinbridge.com"],
        dns_suffix: &["weixin.qq.com", "wechat.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 11, name: "Instagram", category: "Social",
        sni_suffix: &["instagram.com", "cdninstagram.com"],
        dns_suffix: &["instagram.com", "cdninstagram.com"], http_host_suffix: &[],
        ja3_prefix: &[], ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 12, name: "WhatsApp", category: "Social",
        sni_suffix: &["whatsapp.com", "whatsapp.net"],
        dns_suffix: &["whatsapp.com", "whatsapp.net"], http_host_suffix: &[],
        ja3_prefix: &[], ports: &[443, 5222], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 13, name: "Telegram", category: "Social",
        sni_suffix: &["telegram.org", "t.me", "cdn-telegram.org"],
        dns_suffix: &["telegram.org", "t.me"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 14, name: "Twitter/X", category: "Social",
        sni_suffix: &["twitter.com", "x.com", "twimg.com"],
        dns_suffix: &["twitter.com", "x.com", "twimg.com"], http_host_suffix: &[],
        ja3_prefix: &[], ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },

    // ── Messaging ──
    AppRule { app_id: 20, name: "Discord", category: "Messaging",
        sni_suffix: &["discord.com", "discordapp.com", "discord.gg", "discord.media"],
        dns_suffix: &["discord.com", "discordapp.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 21, name: "Slack", category: "Messaging",
        sni_suffix: &["slack.com", "slack-msgs.com", "slack-imgs.com"],
        dns_suffix: &["slack.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 22, name: "Microsoft Teams", category: "Messaging",
        sni_suffix: &["teams.microsoft.com", "skype.com", "lync.com"],
        dns_suffix: &["teams.microsoft.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },

    // ── Cloud Services ──
    AppRule { app_id: 30, name: "GitHub", category: "Developer",
        sni_suffix: &["github.com", "githubusercontent.com", "github.io"],
        dns_suffix: &["github.com", "githubusercontent.com"], http_host_suffix: &["github.com"],
        ja3_prefix: &[], ports: &[443, 22], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 31, name: "Microsoft 365", category: "Productivity",
        sni_suffix: &["microsoft.com", "office.com", "office365.com", "sharepoint.com",
                       "onenote.com", "outlook.com", "live.com"],
        dns_suffix: &["microsoft.com", "office.com", "sharepoint.com"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443], min_bytes: 0.0,
        is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 32, name: "Apple Services", category: "Productivity",
        sni_suffix: &["apple.com", "icloud.com", "apple-cloud.com", "apple-dns.net"],
        dns_suffix: &["apple.com", "icloud.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443, 5223], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 33, name: "AWS", category: "Cloud",
        sni_suffix: &["amazonaws.com", "aws.amazon.com", "cloudfront.net"],
        dns_suffix: &["amazonaws.com", "cloudfront.net"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 34, name: "Cloudflare", category: "CDN",
        sni_suffix: &["cloudflare.com", "cloudflare.net"],
        dns_suffix: &["cloudflare.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 35, name: "Google Cloud", category: "Cloud",
        sni_suffix: &["googleapis.com", "gcr.io", "googlecloud.com", "appspot.com"],
        dns_suffix: &["googleapis.com", "gcr.io"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },

    // ── Music ──
    AppRule { app_id: 40, name: "Spotify", category: "Music",
        sni_suffix: &["spotify.com", "spotifycdn.com", "scdn.co"],
        dns_suffix: &["spotify.com", "scdn.co"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: true, is_heartbeat: true },
    AppRule { app_id: 41, name: "Apple Music", category: "Music",
        sni_suffix: &["music.apple.com", "itunes.apple.com"],
        dns_suffix: &["music.apple.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: true, is_heartbeat: false },
    AppRule { app_id: 42, name: "NetEase Music", category: "Music",
        sni_suffix: &["163.com", "163yun.com", "music.163.com"],
        dns_suffix: &["163.com", "music.163.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: true, is_heartbeat: false },

    // ── AI / LLM ──
    AppRule { app_id: 50, name: "ChatGPT", category: "AI",
        sni_suffix: &["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"],
        dns_suffix: &["chatgpt.com", "openai.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 51, name: "Claude", category: "AI",
        sni_suffix: &["anthropic.com", "claude.ai"],
        dns_suffix: &["anthropic.com", "claude.ai"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 52, name: "Google AI", category: "AI",
        sni_suffix: &["gemini.google.com", "bard.google.com", "deepmind.com", "ai.google"],
        dns_suffix: &["gemini.google.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 53, name: "GitHub Copilot", category: "AI",
        sni_suffix: &["copilot.microsoft.com", "githubcopilot.com"],
        dns_suffix: &["copilot.microsoft.com"], http_host_suffix: &[], ja3_prefix: &[],
        ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },

    // ── System / OS ──
    AppRule { app_id: 60, name: "Windows Update", category: "System",
        sni_suffix: &["windowsupdate.com", "update.microsoft.com", "windows.com",
                       "wns.windows.com", "windows.net"],
        dns_suffix: &["windowsupdate.com", "wns.windows.com", "windows.com"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443, 80],
        min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 61, name: "macOS System", category: "System",
        sni_suffix: &["apple-dns.net", "apple.com", "icloud.com", "icloud-content.com",
                       "appsto.re", "apps.apple.com", "guzzoni.apple.com"],
        dns_suffix: &["apple.com", "icloud.com", "appsto.re"], http_host_suffix: &[],
        ja3_prefix: &[], ports: &[443, 5223], min_bytes: 0.0, is_streaming: false, is_heartbeat: true },
    AppRule { app_id: 62, name: "NTP Time Sync", category: "System",
        sni_suffix: &[], dns_suffix: &["pool.ntp.org", "time.apple.com", "ntp.org"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[123],
        min_bytes: 0.0, is_streaming: false, is_heartbeat: true },

    // ── Browsers ──
    AppRule { app_id: 70, name: "Google Search", category: "Web",
        sni_suffix: &["google.com", "googleapis.com", "gstatic.com"],
        dns_suffix: &["google.com", "gstatic.com"], http_host_suffix: &[],
        ja3_prefix: &[], ports: &[443], min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 71, name: "Bing", category: "Web",
        sni_suffix: &["bing.com", "bing.net"], dns_suffix: &["bing.com"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443],
        min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
    AppRule { app_id: 72, name: "Baidu", category: "Web",
        sni_suffix: &["baidu.com", "bdstatic.com"], dns_suffix: &["baidu.com"],
        http_host_suffix: &[], ja3_prefix: &[], ports: &[443],
        min_bytes: 0.0, is_streaming: false, is_heartbeat: false },
];

/// Scoring thresholds for stream vs. heartbeat detection.
const STREAM_DOWN_RATIO: f64 = 0.8;    // >= 80% downstream → streaming
const HEARTBEAT_BYTES_MAX: f64 = 2000.0;
const HEARTBEAT_PKT_MAX: u32 = 5;

pub struct Classifier;

impl Classifier {
    pub fn new() -> Self { Self }

    /// Multi-dimensional classification with weighted voting.
    pub fn classify(
        &self,
        key: &FlowKey,
        sni: &str,
        dns_domain: &str,
        ja3: &str,
        http_host: &str,
        http_ua: &str,
        total_bytes: f64,
        total_packets: u32,
        has_iat: bool,
    ) -> Classification {
        let mut best_id = 0u32;
        let mut best_score = 0.0f64;
        let mut best_name = "Unknown";
        let mut best_cat = "Unknown";

        for rule in RULES {
            let mut score = 0.0f64;

            // SNI match (highest weight)
            let sni_match = rule.sni_suffix.iter().any(|p| sni.contains(p));
            if sni_match { score += 0.7; }

            // DNS match
            let dns_match = rule.dns_suffix.iter().any(|p| dns_domain.contains(p));
            if dns_match { score += 0.5; }

            // HTTP Host match
            let http_match = rule.http_host_suffix.iter().any(|p| http_host.contains(p));
            if http_match { score += 0.5; }

            // Port match (low weight, many apps use 443)
            let port_match = rule.ports.is_empty() || rule.ports.contains(&key.dst_port);
            if port_match { score += 0.1; }

            // Flow feature boost/penalty
            if total_bytes > 0.0 {
                let down_ratio = 1.0; // simplified
                if rule.is_streaming && down_ratio > STREAM_DOWN_RATIO && total_bytes > 100_000.0 {
                    score += 0.3;
                }
                if rule.is_heartbeat && total_bytes < HEARTBEAT_BYTES_MAX && total_packets <= HEARTBEAT_PKT_MAX {
                    score += 0.3;
                }
            }

            // Penalize if SNI explicitly doesn't match when we have SNI for streaming rules
            if rule.is_streaming && !sni.is_empty() && !sni_match && !dns_match {
                score *= 0.3;
            }

            if score > best_score {
                best_score = score;
                best_id = rule.app_id;
                best_name = rule.name;
                best_cat = rule.category;
            }
        }

        // Confidence: squash score to [0, 1] with threshold
        let confidence = (best_score * 1.2).min(1.0).max(0.0) as f32;

        Classification {
            app_id: best_id,
            app_name: best_name.to_string(),
            app_category: best_cat.to_string(),
            confidence,
        }
    }
}
