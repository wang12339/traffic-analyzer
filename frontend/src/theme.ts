import type { ThemeConfig } from 'antd';

export const cyberpunkDark: ThemeConfig = {
  algorithm: undefined,
  token: {
    colorBgBase: '#0a0e27',
    colorBgContainer: '#131842',
    colorBgElevated: '#1a1f4e',
    colorBgLayout: '#070a1e',
    colorPrimary: '#6366f1',
    colorPrimaryHover: '#818cf8',
    colorPrimaryActive: '#4f46e5',
    colorSuccess: '#22c55e',
    colorWarning: '#f59e0b',
    colorError: '#ef4444',
    colorInfo: '#60a5fa',
    colorTextBase: '#e0e8ff',
    colorTextSecondary: '#8892c0',
    colorBorder: '#1e3a8a',
    colorBorderSecondary: '#162a5e',
    borderRadius: 10,
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    fontSize: 13,
    controlHeight: 36,
    colorBgMask: 'rgba(0, 0, 0, 0.6)',
  },
  components: {
    Layout: {
      bodyBg: '#070a1e',
      headerBg: '#0a0e27',
      siderBg: '#0a0e27',
      triggerBg: '#131842',
      triggerHeight: 48,
    },
    Menu: {
      darkItemBg: 'transparent',
      darkItemColor: '#8892c0',
      darkItemSelectedBg: 'rgba(99, 102, 241, 0.15)',
      darkItemSelectedColor: '#818cf8',
      darkItemHoverBg: 'rgba(99, 102, 241, 0.08)',
      itemBorderRadius: 8,
      darkSubMenuItemBg: 'transparent',
    },
    Card: {
      colorBgContainer: '#131842',
      paddingLG: 16,
    },
    Table: {
      colorBgContainer: '#131842',
      headerBg: '#0f1440',
      headerColor: '#818cf8',
      rowHoverBg: 'rgba(99, 102, 241, 0.06)',
      borderColor: '#1a2450',
    },
    Select: {
      colorBgContainer: '#131842',
      colorBorder: '#1e3a8a',
      optionSelectedBg: 'rgba(99, 102, 241, 0.15)',
    },
    Button: {
      colorBgContainer: '#131842',
      colorBorder: '#1e3a8a',
      primaryShadow: '0 0 12px rgba(99, 102, 241, 0.3)',
    },
    Tag: {
      colorBgContainer: 'rgba(99, 102, 241, 0.12)',
    },
    Tabs: {
      colorBgContainer: '#131842',
      inkBarColor: '#6366f1',
      itemSelectedColor: '#818cf8',
    },
    Switch: {
      colorPrimary: '#6366f1',
    },
    Drawer: {
      colorBgElevated: '#131842',
    },
    Modal: {
      colorBgElevated: '#131842',
    },
    Tooltip: {
      colorBgSpotlight: '#1a1f4e',
    },
  },
};
