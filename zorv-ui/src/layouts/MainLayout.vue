<script setup lang="ts">
// Main layout: top navigation + content area (shared by all protected pages)
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

async function onLogout() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <div class="bg-slate-100 min-h-screen text-slate-800">
    <nav class="bg-slate-800 text-white shadow">
      <div class="max-w-5xl mx-auto px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm sm:text-base">
        <span class="font-bold text-lg tracking-wide mr-auto">Zorv Console</span>
        <router-link to="/" class="text-white border-b-2 border-white pb-0.5">Overview</router-link>
        <router-link to="/clients" class="text-slate-300 hover:text-white">Online Clients</router-link>
        <router-link to="/settings" class="text-slate-300 hover:text-white">Settings</router-link>
        <router-link to="/traffic" class="text-slate-300 hover:text-white">Traffic Monitoring</router-link>
        <a href="#" class="text-slate-300 hover:text-white" @click.prevent="onLogout">Logout</a>
      </div>
    </nav>

    <main class="max-w-5xl mx-auto px-4 py-6 sm:py-8">
      <router-view />
    </main>
  </div>
</template>
