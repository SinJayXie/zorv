<script setup lang="ts">
// LoginView: Username + Password + Captcha (captcha id is sent via cookie)
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

const username = ref('')
const password = ref('')
const captcha = ref('')
const msg = ref('')
const loading = ref(false)

const captchaUrl = ref('')
function refreshCaptcha() {
  captchaUrl.value = `/api/captcha?t=${Date.now()}`
  captcha.value = ''
}
refreshCaptcha()

async function onSubmit() {
  msg.value = ''
  loading.value = true
  try {
    const res = await auth.login(username.value.trim(), password.value, captcha.value.trim())
    if (res.ok) {
      router.push('/')
    } else {
      msg.value = 'Login failed: ' + (res.error || 'Login credentials are incorrect')
      refreshCaptcha()
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen bg-[#F2F2F7] flex items-center justify-center p-4 text-[#1C1C1E]">
    <div class="w-full max-w-sm">
      <div class="bg-white rounded-2xl p-5 sm:p-6">
        <div class="mb-5">
          <h1 class="text-xl font-bold text-center">Zorv Console</h1>
          <p class="text-sm text-[#8E8E93] text-center mt-1">Tunnel · Server Console</p>
        </div>
        <form class="space-y-4" @submit.prevent="onSubmit">
          <div>
            <label class="block text-sm font-medium mb-1.5">Username</label>
            <div class="relative">
              <svg class="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#8E8E93]" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="8" r="4" />
                <path d="M4 21c0-4 3.6-7 8-7s8 3 8 7" />
              </svg>
              <input
                v-model="username"
                type="text"
                autocomplete="username"
                placeholder="Username"
                class="w-full bg-[#F2F2F7] border border-[#E5E5EA] rounded-xl pl-10 pr-3 py-3 text-[15px] placeholder:text-[#8E8E93] focus:outline-none focus:ring-2 focus:ring-[#007AFF] focus:border-[#007AFF] transition"
              />
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium mb-1.5">Password</label>
            <div class="relative">
              <svg class="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#8E8E93]" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <rect x="4" y="11" width="16" height="10" rx="2" />
                <path d="M8 11V7a4 4 0 0 1 8 0v4" />
              </svg>
              <input
                v-model="password"
                type="password"
                autocomplete="current-password"
                placeholder="Password"
                class="w-full bg-[#F2F2F7] border border-[#E5E5EA] rounded-xl pl-10 pr-3 py-3 text-[15px] placeholder:text-[#8E8E93] focus:outline-none focus:ring-2 focus:ring-[#007AFF] focus:border-[#007AFF] transition"
              />
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium mb-1.5">Captcha</label>
            <div class="flex gap-3 items-center">
              <div class="relative flex-1">
                <svg class="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#8E8E93]" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6z" />
                  <path d="M9.5 12l1.8 1.8 3.2-3.6" />
                </svg>
                <input
                  v-model="captcha"
                  type="text"
                  maxlength="4"
                  autocomplete="off"
                  placeholder="Captcha Code"
                  class="w-full uppercase bg-[#F2F2F7] border border-[#E5E5EA] rounded-xl pl-10 pr-3 py-3 text-[15px] placeholder:text-[#8E8E93] focus:outline-none focus:ring-2 focus:ring-[#007AFF] focus:border-[#007AFF] transition"
                />
              </div>
              <img
                :src="captchaUrl"
                alt="Captcha Image"
                title="Refresh captcha"
                class="h-11.5 w-32 shrink-0 rounded-xl border border-[#E5E5EA] cursor-pointer bg-[#F2F2F7]"
                @click="refreshCaptcha"
              />
            </div>
          </div>

          <p class="text-sm text-[#FF3B30] min-h-5">{{ msg }}</p>

          <button
            type="submit"
            :disabled="loading"
            class="w-full bg-[#007AFF] text-white py-3 rounded-xl font-semibold text-[15px] hover:bg-[#0A84FF] active:bg-[#0066D6] transition disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {{ loading ? 'Logging in...' : 'Login' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>
