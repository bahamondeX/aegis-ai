export default defineEventHandler(async event => ({ session: await obAuth(event).getSession(event) }))
