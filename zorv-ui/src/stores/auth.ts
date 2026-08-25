// Pinia auth store: manages the login session token
import { defineStore } from 'pinia'
import http, { getToken, setToken, clearToken } from '@/api'
import type { ApiError, ApiOk } from '@/types'

interface LoginResult {
  ok: boolean
  token?: string
  error?: string
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: getToken(),
    username: localStorage.getItem('zorv_username') ?? '',
  }),
  getters: {
    isAuthed: (s) => !!s.token,
  },
  actions: {
    /** 登录：成功后将 token 写入 pinia + localStorage */
    async login(username: string, password: string, captcha_code: string): Promise<LoginResult> {
      try {
        const { data } = await http.post<ApiOk & { token?: string }>('/login', {
          username,
          password,
          captcha_code,
        })
        if (data.ok && data.token) {
          this.token = data.token
          this.username = username
          localStorage.setItem('zorv_username', username)
          setToken(data.token)
          return { ok: true, token: data.token }
        }
        const err = data as unknown as ApiError
        return { ok: false, error: err.error || 'Login failed' }
      } catch (e) {
        return { ok: false, error: 'Request failed, please retry' }
      }
    },
    /** Logout: invalidate the session server-side and clear the local token */
    async logout(): Promise<void> {
      try {
        await http.post('/logout')
      } catch {
        // Ignore network errors; local logout still happens
      }
      this.token = ''
      this.username = ''
      clearToken()
      localStorage.removeItem('zorv_username')
    },
    /** Local clear (e.g. after a 401) */
    clear(): void {
      this.token = ''
      this.username = ''
      clearToken()
      localStorage.removeItem('zorv_username')
    },
  },
})
