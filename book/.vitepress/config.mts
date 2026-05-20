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
            { text: 'Glossary', link: 'glossary' },
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
            { text: 'Networking', link: 'networking' },
            { text: 'Troubleshooting', link: 'troubleshooting' },
            { text: 'Frequently Asked Questions', link: 'faq' },
          ]
        },
        {
          text: 'Protocol',
          collapsed: false,
          items: [
            { text: 'Transaction Ingress', link: 'protocol/transaction_ingress' },
            { text: 'Bundle Client', link: 'protocol/bundle_client' },
            { text: 'Cryptography', link: 'protocol/cryptography' },
          ]
        },
        {
          text: 'Internals',
          collapsed: false,
          items: [
            { text: 'Agave Snapshots', link: 'internals/agave_snapshots' },
            { text: 'Fork Management', link: 'internals/fork_management' },
            { text: 'Net Tile', link: 'internals/net_tile' },
            { text: 'Netlink', link: 'internals/netlink' },
            { text: 'Supply Chain', link: 'internals/supply_chain' },
          ]
        }
      ] },

      '/api': { base: '/api/', items: [
        {
          text: 'API',
          items: [
            { text: 'Frankendancer Command Line Interface', link: 'cli' },
            { text: 'Firedancer Command Line Interface', link: 'firedancer-cli' },
            { text: 'Metrics', link: 'metrics' },
            { text: 'WebSocket', link: 'websocket' },
            { text: 'TPU-QUIC', link: 'tpu-quic' },
            { text: 'TPU-UDP', link: 'tpu-udp' },
          ]
        }
      ] },
    },

    outline: {
      level: [2, 3]
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
