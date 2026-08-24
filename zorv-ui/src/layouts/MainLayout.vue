<script setup lang="ts">
// Main layout: sticky top navigation (hamburger menu on mobile, horizontal on
// desktop) with route-aware active highlighting + content area.
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const buildVersion = import.meta.env.VITE_BUILD_VERSION



const menuOpen = ref(false)

const navItems = [
  { path: '/', label: 'Overview', exact: true },
  { path: '/clients', label: 'Online Clients', exact: false },
  { path: '/settings', label: 'Settings', exact: false },
  { path: '/traffic', label: 'Traffic Monitoring', exact: false },
  { path: '/audit', label: 'Audit', exact: false },
]

function isActive(item: { path: string; exact: boolean }): boolean {
  return item.exact ? route.path === item.path : route.path.startsWith(item.path)
}

function closeMenu() {
  menuOpen.value = false
}

async function onLogout() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <div class="bg-slate-100 min-h-screen text-slate-800">
    <!-- Sticky top bar so navigation stays visible while scrolling -->
    <nav class="sticky top-0 z-40 bg-slate-800 text-white shadow">
      <div class="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between gap-4 text-sm sm:text-base">
        <span class="font-bold text-lg tracking-wide mr-auto">Zorv Console <span class="text-sm">{{ buildVersion
            }}</span></span>

        <!-- Desktop navigation -->
        <div class="hidden sm:flex items-center gap-4">
          <router-link v-for="item in navItems" :key="item.path" :to="item.path" class="transition-colors" :class="isActive(item)
              ? 'text-white border-b-2 border-white pb-0.5'
              : 'text-slate-300 hover:text-white'
            ">
            {{ item.label }}
          </router-link>
          <a href="#" class="text-slate-300 hover:text-white" @click.prevent="onLogout">Logout</a>
        </div>

        <!-- Mobile hamburger toggle -->
        <button
          class="sm:hidden flex items-center justify-center w-9 h-9 rounded-lg hover:bg-slate-700 transition-colors"
          aria-label="Toggle navigation menu" @click="menuOpen = !menuOpen">
          <svg v-if="!menuOpen" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width="2" stroke-linecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          <svg v-else width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round">
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
      </div>

      <!-- Mobile dropdown panel -->
      <div v-if="menuOpen"
        class="sm:hidden absolute top-full left-0 right-0 bg-slate-800 shadow-lg border-t border-slate-700 px-4 py-2">
        <router-link v-for="item in navItems" :key="item.path" :to="item.path"
          class="block py-2.5 px-2 rounded-lg transition-colors"
          :class="isActive(item) ? 'bg-slate-700/60 text-white' : 'text-slate-300 hover:bg-slate-700/40 hover:text-white'"
          @click="closeMenu">
          {{ item.label }}
        </router-link>
        <a href="#"
          class="block py-2.5 px-2 rounded-lg text-slate-300 hover:bg-slate-700/40 hover:text-white transition-colors"
          @click.prevent="onLogout">
          Logout
        </a>
      </div>
    </nav>

    <main class="max-w-5xl mx-auto px-4 py-6 sm:py-8">
      <router-view />
    </main>
  </div>
</template>
