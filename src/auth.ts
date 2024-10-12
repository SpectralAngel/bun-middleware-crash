import type { NextAuthConfig } from 'next-auth'
import NextAuth from 'next-auth'
import { JWT } from 'next-auth/jwt'
import Keycloak from 'next-auth/providers/keycloak'

async function refreshAccessToken(token: JWT) {
  const resp = await fetch(
    `${process.env.AUTH_KEYCLOAK_ISSUER}/protocol/openid-connect/token`,
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.AUTH_KEYCLOAK_ID,
        client_secret: process.env.AUTH_KEYCLOAK_SECRET,
        grant_type: 'refresh_token',
        refresh_token: token.refresh_token as string,
      }),
      method: 'POST',
    }
  )

  const refreshToken = await resp.json()
  if (!resp.ok) throw refreshToken

  return {
    ...token,
    access_token: refreshToken.access_token,
    id_token: refreshToken.id_token,
    expires_at: Math.floor(Date.now() / 1000) + refreshToken.expires_in,
    refresh_token: refreshToken.refresh_token,
  }
}

export const config = {
  providers: [Keycloak],
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user

      const unprotectedPaths = ['/login']

      const isProtected = !unprotectedPaths.some((path) =>
        nextUrl.pathname.startsWith(path)
      )

      if (isProtected && !isLoggedIn) {
        const redirectUrl = new URL('api/auth/signin', nextUrl.origin)
        redirectUrl.searchParams.append('callbackUrl', nextUrl.href)
        return Response.redirect(redirectUrl)
      }
      return true
    },
    session({ session, token }) {
      session.access_token = token.access_token
      session.id_token = token.id_token
      session.error = token.error
      // session.roles = token.decoded?.realm_access.roles;
      return session
    },
    jwt({ token, account }) {
      const now = Math.floor(Date.now() / 1000)
      if (account) {
        token.access_token = account.access_token ? account.access_token : ''
        token.id_token = account.id_token
        token.expires_at = account.expires_at ? account.expires_at : 0
        token.refresh_token = account.refresh_token ? account.refresh_token : ''
      } else if (now < token.expires_at!) {
        return token
      }
      try {
        return refreshAccessToken(token)
      } catch (error) {
        console.error('Error refreshing access token', error)
        return { ...token, error: 'RefreshAccessTokenError' }
      }
    },
  },
  events: {
    async signOut(message) {
      if ('token' in message) {
        console.log('Federated Logout')
        const token = message.token as JWT
        const sessionParams = new URLSearchParams({
          id_token_hint: token.id_token!,
          post_logout_redirect_uri: process.env.AUTH_CALLBACK_URL,
        })
        const url = `${process.env.AUTH_KEYCLOAK_ISSUER}/protocol/openid-connect/logout?${sessionParams}`
        try {
          await fetch(url, { method: 'GET' })
        } catch (error) {
          console.error(error)
          new Response('Error', { status: 500 })
        }
      }
    },
  },
} satisfies NextAuthConfig

declare module 'next-auth' {
  interface Session {
    access_token?: string
    id_token?: string
    error?: 'RefreshAccessTokenError'
  }
}
declare module 'next-auth/jwt' {
  interface JWT {
    access_token: string
    expires_at: number
    refresh_token: string
    id_token?: string
    error?: 'RefreshAccessTokenError'
  }
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth(config)
