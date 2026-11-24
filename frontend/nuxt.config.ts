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
    aegisApiBase: 'http://127.0.0.1:8000',
    aegisRuntimeUrl: '',
    public: {
      cognitoIssuer: '',
      cognitoClientId: '',
      cognitoDomain: '',
    },
  },
  nitro: { prerender: { routes: ['/', '/auth/callback'] } },
  routeRules: {
    '/api/**': { headers: { 'Cache-Control': 'no-store' } },
    '/**': { headers: {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    } },
  },
})
