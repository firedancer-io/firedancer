import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  lang: 'en-US',
  title: "Firedancer",
  description: "Firedancer",

  base: '/firedancer/',
  lastUpdated: true,

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/fire.svg' }],
    ['meta', { name: 'theme-color', content: '#1ce7c2' }],
    ['meta', { name: 'og:type', content: 'website' }],
    ['meta', { name: 'og:locale', content: 'en' }],
    ['meta', { name: 'og:site_name', content: 'Firedancer' }],
  ],

  themeConfig: {
    logo: { src: '/fire.svg', width: 24, height: 24 },

    nav: [
      { text: 'Guide', link: '/guide/firedancer' },
      { text: 'Commands', link: '/commands' }
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
