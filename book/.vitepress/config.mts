import { defineConfig } from 'vitepress'
import latestVersion from './version-plugin.js';

// https://vitepress.dev/reference/site-config
export default defineConfig({
  lang: 'en-US',
  title: "Firedancer",
  description: "Firedancer",

  base: '/',
  lastUpdated: true,

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/fire.svg' }],
    ['meta', { name: 'theme-color', content: '#1ce7c2' }],
    ['meta', { name: 'og:type', content: 'website' }],
    ['meta', { name: 'og:locale', content: 'en' }],
    ['meta', { name: 'og:site_name', content: 'Firedancer' }],
  ],

  vite: {
    plugins: [latestVersion()]
  },

  themeConfig: {
    logo: { src: '/fire.svg', width: 24, height: 24 },

    nav: [
      { text: 'Guide', link: '/guide/firedancer' },
      { text: 'API', link: '/api/cli' }
    ],

    sidebar: {
      '/guide/': { base: '/guide/', items: [
        {
          text: 'Introduction',
          collapsed: false,
          items: [
            { text: 'Firedancer', link: 'firedancer' },
            { text: 'Getting Started', link: 'getting-started' },
            { text: 'Configuring', link: 'configuring' },
            { text: 'Initializing', link: 'initializing' },
          ]
        },
        {
          text: 'Performance',
          collapsed: false,
          items: [
            { text: 'Tuning', link: 'tuning' },
          ]
        },
        {
          text: 'Operating',
          collapsed: false,
          items: [
            { text: 'Monitoring', link: 'monitoring' },
            { text: 'Troubleshooting', link: 'troubleshooting' },
            { text: 'Frequently Asked Questions', link: 'faq' },
          ]
        },
        {
          text: 'Internals',
          collapsed: false,
          items: [
            { text: 'Net Tile', link: 'internals/net_tile' },
            { text: 'Netlink', link: 'internals/netlink' },
          ]
        }
      ] },

      '/api': { base: '/api/', items: [
        {
          text: 'API',
          items: [
            { text: 'Commands Line Interface', link: 'cli' },
            { text: 'Metrics', link: 'metrics' },
            { text: 'WebSocket', link: 'websocket' },
          ]
        }
      ] },
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/firedancer-io/firedancer' }
    ],

    editLink: {
      pattern: 'https://github.com/firedancer-io/firedancer/edit/main/book/:path',
      text: 'Edit this page on GitHub'
    },

    search: {
      provider: 'local'
    }
  }
})
