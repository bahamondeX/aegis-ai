export default defineNuxtConfig({
  ssr: false,
  compatibilityDate: '2026-11-23',
  devtools: { enabled: false },
  modules: ['@nuxt/ui', '@nuxt/eslint'],
  css: [
    '@fontsource-variable/inter',
    '@fontsource/ibm-plex-mono/400.css',
    '@fontsource/ibm-plex-mono/500.css',
    '~/assets/dashboard.css',
  ],
  app: {
    head: {
      title: 'AEGIS · Threat Intelligence',
      meta: [{ name: 'description', content: 'Evidence-backed vulnerability intelligence workspace' }],
    },
  },
  typescript: {
    strict: true,
    tsConfig: { compilerOptions: { noUncheckedIndexedAccess: true } },
  },
  runtimeConfig: {
    aegisApiBase: '',
    localApiBase: 'http://127.0.0.1:8000',
    aegisBridgeSigningKey: '',
    obAuth: {
      domain: 'https://auth.oscarbahamonde.com',
      clientId: '',
      clientSecret: '',
      appOrigin: '',
      sessionKey: '',
      logoutUri: '',
    },
    public: {
      localTokenAuth: process.env.NODE_ENV === 'development' && process.env.NUXT_PUBLIC_LOCAL_TOKEN_AUTH === 'true',
      historyAnalysisV2: process.env.NUXT_PUBLIC_HISTORY_ANALYSIS_V2 === 'true',
      epssHistoryV2: process.env.NUXT_PUBLIC_EPSS_HISTORY_V2 === 'true',
      profilesV2: process.env.NUXT_PUBLIC_PROFILES_V2 === 'true',
      catalogV2: process.env.NUXT_PUBLIC_CATALOG_V2 === 'true',
      networkContextV2: process.env.NUXT_PUBLIC_NETWORK_CONTEXT_V2 === 'true',
    },
  },
  nitro: { vercel: { functions: { maxDuration: 90 } } },
  routeRules: {
    '/demo/exposure': { prerender: true },
    '/auth/**': { headers: { 'Cache-Control': 'no-store' } },
    '/admin': { redirect: '/' },
    '/api/**': { headers: { 'Cache-Control': 'no-store' } },
    '/**': { headers: {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    } },
  },
})
