import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi, type LoginRequest, type LoginResponse } from '@/api/auth'

interface UserInfo {
  id: string
  username: string
  role: string
  must_change_password: boolean
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>(localStorage.getItem('argus_token') || '')
  const user = ref<UserInfo | null>(
    JSON.parse(localStorage.getItem('argus_user') || 'null'),
  )

  const isLoggedIn = computed(() => !!token.value)
  const mustChangePassword = computed(() => user.value?.must_change_password ?? false)

  async function login(data: LoginRequest): Promise<LoginResponse> {
    const res = await authApi.login(data)
    token.value = res.token
    user.value = res.user
    localStorage.setItem('argus_token', res.token)
    localStorage.setItem('argus_user', JSON.stringify(res.user))
    return res
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('argus_token')
    localStorage.removeItem('argus_user')
    authApi.logout().catch(() => {})
  }

  return {
    token,
    user,
    isLoggedIn,
    mustChangePassword,
    login,
    logout,
  }
})
