import withNuxt from './.nuxt/eslint.config.mjs'

export default withNuxt({
  ignores: ['investigations/events.d.ts', '.test-dist/**', 'playwright-report/**', 'test-results/**'],
})
