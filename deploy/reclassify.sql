-- Batch reclassification of existing flows
-- Run: clickhouse client --database=traffic < reclassify.sql

-- Video
ALTER TABLE flows UPDATE app_name='YouTube', app_category='Video', app_id=1 WHERE sni LIKE '%youtube.com%' OR sni LIKE '%googlevideo.com%' OR sni LIKE '%ytimg.com%' OR dns_domain LIKE '%youtube.com%';
ALTER TABLE flows UPDATE app_name='抖音/TikTok', app_category='Video', app_id=3 WHERE sni LIKE '%douyin%' OR sni LIKE '%amemv.com%' OR dns_domain LIKE '%douyin.com%';
ALTER TABLE flows UPDATE app_name='Bilibili', app_category='Video', app_id=5 WHERE sni LIKE '%bilibili.com%' OR sni LIKE '%hdslb.com%' OR dns_domain LIKE '%bilibili.com%';
ALTER TABLE flows UPDATE app_name='腾讯视频', app_category='Video', app_id=7 WHERE sni LIKE '%.v.qq.com%' OR dns_domain LIKE '%qqvideo%';

-- Social
ALTER TABLE flows UPDATE app_name='微信', app_category='Social', app_id=10 WHERE sni LIKE '%weixin.qq.com%' OR sni LIKE '%weixinbridge.com%' OR dns_domain LIKE '%weixin.qq.com%';
ALTER TABLE flows UPDATE app_name='微博', app_category='Social', app_id=15 WHERE sni LIKE '%weibo.com%' OR dns_domain LIKE '%weibo.com%';
ALTER TABLE flows UPDATE app_name='小红书', app_category='Social', app_id=17 WHERE sni LIKE '%xiaohongshu.com%' OR dns_domain LIKE '%xiaohongshu.com%';

-- AI
ALTER TABLE flows UPDATE app_name='Claude', app_category='AI', app_id=51 WHERE sni LIKE '%anthropic.com%' OR sni LIKE '%claude.ai%' OR dns_domain LIKE '%anthropic.com%';
ALTER TABLE flows UPDATE app_name='DeepSeek', app_category='AI', app_id=52 WHERE sni LIKE '%deepseek.com%' OR dns_domain LIKE '%deepseek%';

-- Music
ALTER TABLE flows UPDATE app_name='QQ 音乐', app_category='Music', app_id=45 WHERE sni LIKE '%y.qq.com%' OR sni LIKE '%qqmusic.qq.com%' OR dns_domain LIKE '%y.qq.com%' OR dns_domain LIKE '%qqmusic.qq.com%' OR sni LIKE '%qpic.cn%' OR dns_domain LIKE '%qpic.cn%';
ALTER TABLE flows UPDATE app_name='网易云音乐', app_category='Music', app_id=42 WHERE sni LIKE '%163.com%' OR dns_domain LIKE '%163.com%' OR dns_domain LIKE '%music.163%';

-- Maps
ALTER TABLE flows UPDATE app_name='高德地图', app_category='Navigation', app_id=90 WHERE sni LIKE '%amap.com%' OR sni LIKE '%autonavi.com%' OR dns_domain LIKE '%amap.com%';

-- System
ALTER TABLE flows UPDATE app_name='Apple 系统服务', app_category='System', app_id=61 WHERE sni LIKE '%apple.com%' OR dns_domain LIKE '%apple.com%' OR dns_domain LIKE '%icloud.com%';
ALTER TABLE flows UPDATE app_name='Windows Update', app_category='System', app_id=60 WHERE sni LIKE '%windowsupdate.com%' OR sni LIKE '%wns.windows.com%' OR dns_domain LIKE '%windowsupdate.com%' OR dns_domain LIKE '%wns.windows.com%';
ALTER TABLE flows UPDATE app_name='Apple Push', app_category='System', app_id=63 WHERE sni LIKE '%push.apple.com%' OR dns_domain LIKE '%push.apple.com%' OR dns_domain LIKE '%courier.push.apple.com%';
ALTER TABLE flows UPDATE app_name='NTP 时间同步', app_category='System', app_id=62 WHERE dns_domain LIKE '%pool.ntp.org%' OR dns_domain LIKE '%time.apple.com%';
ALTER TABLE flows UPDATE app_name='SSDP 发现', app_category='System', app_id=64 WHERE dst_port=1900;
ALTER TABLE flows UPDATE app_name='mDNS', app_category='System', app_id=65 WHERE dst_port=5353 AND dns_domain LIKE '%_dns-sd%';

-- Cloud / CDN
ALTER TABLE flows UPDATE app_name='阿里云', app_category='Cloud', app_id=37 WHERE sni LIKE '%aliyuncs.com%' OR dns_domain LIKE '%aliyuncs.com%';
ALTER TABLE flows UPDATE app_name='Microsoft 365', app_category='Productivity', app_id=31 WHERE sni LIKE '%office.com%' OR sni LIKE '%sharepoint.com%' OR sni LIKE '%outlook.com%';

-- Search
ALTER TABLE flows UPDATE app_name='Bing', app_category='Web', app_id=71 WHERE sni LIKE '%bing.com%' OR dns_domain LIKE '%bing.com%';
ALTER TABLE flows UPDATE app_name='百度', app_category='Web', app_id=72 WHERE sni LIKE '%baidu.com%' OR dns_domain LIKE '%baidu.com%';

-- E-commerce
ALTER TABLE flows UPDATE app_name='淘宝/天猫', app_category='Shopping', app_id=80 WHERE sni LIKE '%taobao.com%' OR sni LIKE '%tmall.com%' OR dns_domain LIKE '%taobao.com%';

-- Productivity
ALTER TABLE flows UPDATE app_name='钉钉', app_category='Productivity', app_id=102 WHERE sni LIKE '%dingtalk.com%' OR sni LIKE '%ding.zj.gov.cn%' OR dns_domain LIKE '%dingtalk.com%';
ALTER TABLE flows UPDATE app_name='飞书', app_category='Productivity', app_id=101 WHERE sni LIKE '%feishu.cn%' OR dns_domain LIKE '%feishu.cn%';

-- Payment
ALTER TABLE flows UPDATE app_name='支付宝', app_category='Payment', app_id=84 WHERE sni LIKE '%alipay.com%' OR dns_domain LIKE '%alipay.com%';

-- Developer
ALTER TABLE flows UPDATE app_name='GitHub', app_category='Developer', app_id=30 WHERE sni LIKE '%github.com%' OR sni LIKE '%githubusercontent.com%' OR dns_domain LIKE '%github.com%';
