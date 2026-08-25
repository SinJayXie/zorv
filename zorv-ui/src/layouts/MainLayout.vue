<script setup lang="ts">
// Main layout: fixed left sidebar (desktop) / slide-out drawer (mobile) +
// top header with product name & user profile + max-width content area.
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const buildVersion = import.meta.env.VITE_BUILD_VERSION

const sidebarOpen = ref(false)

const navItems = [
  { path: '/', label: 'Overview', exact: true, icon: 'overview' },
  { path: '/clients', label: 'Online Clients', exact: false, icon: 'clients' },
  { path: '/settings', label: 'Settings', exact: false, icon: 'settings' },
  { path: '/traffic', label: 'Traffic Monitoring', exact: false, icon: 'traffic' },
  { path: '/audit', label: 'Audit', exact: false, icon: 'audit' },
]

function isActive(item: { path: string; exact: boolean }): boolean {
  return item.exact ? route.path === item.path : route.path.startsWith(item.path)
}

// Close the mobile drawer whenever navigation happens
watch(
  () => route.path,
  () => {
    sidebarOpen.value = false
  },
)

async function onLogout() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <div class="min-h-screen bg-[#f7f8fa] text-slate-800">
    <!-- Top header -->
    <header class="fixed top-0 left-0 right-0 z-40 h-14 bg-slate-800 text-white shadow flex items-center gap-3 px-4">
      <!-- Mobile hamburger -->
      <button
        class="md:hidden flex items-center justify-center w-11 h-11 -ml-2 rounded-lg hover:bg-slate-700 transition-colors"
        aria-label="Toggle navigation menu"
        @click="sidebarOpen = true"
      >
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      <span class="font-bold text-lg tracking-wide truncate">
        Zorv Console <span class="text-sm text-slate-400">{{ buildVersion }}</span>
      </span>

      <!-- User profile -->
      <div class="ml-auto hidden md:flex items-center gap-2.5">
        <span class="w-8 h-8 rounded-full bg-slate-600 flex items-center justify-center text-sm font-semibold uppercase select-none">
          {{ (auth.username || 'A').charAt(0) }}
        </span>
        <span class="text-sm text-slate-200">{{ auth.username || 'Admin' }}</span>
      </div>
    </header>

    <!-- Mobile drawer overlay -->
    <div v-if="sidebarOpen" class="fixed inset-0 z-30 bg-black/40 md:hidden" @click="sidebarOpen = false" />

    <!-- Sidebar -->
    <aside
      class="fixed top-14 bottom-0 left-0 z-40 w-56 bg-slate-900 text-slate-300 flex flex-col transition-transform duration-200 md:translate-x-0"
      :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full'"
    >
      <nav class="flex-1 overflow-y-auto p-3 space-y-1">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors border-l-2"
          :class="isActive(item)
            ? 'bg-slate-700/60 text-white border-sky-400'
            : 'text-slate-400 hover:text-white hover:bg-slate-700/40 border-transparent'"
        >
          <!-- Nav icons -->
          <svg v-if="item.icon === 'overview'" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="7" height="9" rx="1.5" />
            <rect x="14" y="3" width="7" height="5" rx="1.5" />
            <rect x="14" y="12" width="7" height="9" rx="1.5" />
            <rect x="3" y="16" width="7" height="5" rx="1.5" />
          </svg>
          <svg v-else-if="item.icon === 'clients'" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="9" cy="8" r="3.5" />
            <path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6" />
            <path d="M16 4.5a3.5 3.5 0 0 1 0 7M17.5 14.2c2 .9 4 2.8 4 5.8" />
          </svg>
          <svg v-else-if="item.icon === 'settings'" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.09a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z" />
          </svg>
          <svg v-else-if="item.icon === 'traffic'" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 3v18h18" />
            <path d="M7 14l3-4 3 3 4-6" />
          </svg>
          <svg v-else width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <path d="M14 2v6h6M8 13h8M8 17h8M8 9h2" />
          </svg>
          {{ item.label }}
        </router-link>
      </nav>

      <!-- Logout -->
      <div class="p-3 border-t border-slate-800">
        <button
          class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
          @click="onLogout"
        >
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <path d="M16 17l5-5-5-5M21 12H9" />
          </svg>
          Logout
        </button>
      </div>
    </aside>

    <!-- Main content -->
    <main class="pt-14 md:pl-56">
      <div class="max-w-[1400px] mx-auto px-4 sm:px-6 py-5 sm:py-6">
        <router-view />
      </div>
    </main>
  </div>
</template>
