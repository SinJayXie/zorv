<script setup lang="ts">
// Overview page: dashboard-style stat cards + copyable address cards
import { onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import CopyButton from '@/components/CopyButton.vue'
import type { Status } from '@/types'

const stat = ref<Status | null>(null)
const loadFailed = ref(false)

async function load() {
  try {
    const { data } = await http.get<Status>('/status')
    stat.value = data
    loadFailed.value = false
  } catch {
    loadFailed.value = true
  }
}

let timer: number | undefined
onMounted(() => {
  load()
  timer = window.setInterval(load, 5000)
})
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3 mb-5 sm:mb-6">
      <div>
        <h1 class="text-xl sm:text-2xl font-semibold text-[#1d2129]">Overview</h1>
        <p class="text-sm text-[#86909c] mt-0.5">Tunnel server status at a glance</p>
      </div>
      <button
        class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-slate-800 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 min-[1200px]:grid-cols-4 gap-4">
      <!-- Stat cards -->
      <div class="bg-white rounded-xl p-5 shadow-sm border border-slate-100">
        <p class="text-sm text-[#6e7681]">Online Clients</p>
        <div class="flex items-baseline gap-2 mt-2">
          <p class="text-3xl sm:text-4xl font-bold text-[#1d2129]">{{ stat?.clients ?? '–' }}</p>
          <span
            class="inline-flex items-center gap-1.5 text-xs font-medium rounded-full px-2 py-0.5"
            :class="(stat?.clients ?? 0) > 0 ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-400'"
          >
            <span class="w-1.5 h-1.5 rounded-full" :class="(stat?.clients ?? 0) > 0 ? 'bg-emerald-500' : 'bg-slate-300'" />
            {{ (stat?.clients ?? 0) > 0 ? 'Online' : 'Idle' }}
          </span>
        </div>
        <p class="text-xs text-[#86909c] mt-2">Count of currently connected online clients</p>
      </div>

      <div class="bg-white rounded-xl p-5 shadow-sm border border-slate-100">
        <p class="text-sm text-[#6e7681]">Proxies</p>
        <p class="text-3xl sm:text-4xl font-bold text-[#1d2129] mt-2">{{ stat?.proxies ?? '–' }}</p>
        <p class="text-xs text-[#86909c] mt-2">Total number of configured proxy rules</p>
      </div>

      <!-- Address cards -->
      <div class="bg-white rounded-xl p-5 shadow-sm border border-slate-100">
        <p class="text-sm text-[#6e7681]" title="The public address of the reverse tunnel server">Tunnel Address</p>
        <div class="flex items-center gap-2 mt-2 min-w-0">
          <p class="flex-1 min-w-0 truncate text-lg font-mono font-semibold text-[#1d2129]" title="The public address of the reverse tunnel server">
            {{ stat?.tunnel_addr ?? '–' }}
          </p>
          <CopyButton v-if="stat?.tunnel_addr" :text="stat.tunnel_addr" />
        </div>
        <p class="text-xs text-[#86909c] mt-2">Clients connect here to establish tunnels</p>
      </div>

      <div class="bg-white rounded-xl p-5 shadow-sm border border-slate-100">
        <p class="text-sm text-[#6e7681]" title="The address of this admin web console">Admin Console Listen</p>
        <div class="flex items-center gap-2 mt-2 min-w-0">
          <p class="flex-1 min-w-0 truncate text-lg font-mono font-semibold text-[#1d2129]" title="The address of this admin web console">
            {{ stat?.admin_listen ?? '–' }}
          </p>
          <CopyButton v-if="stat?.admin_listen" :text="stat.admin_listen" />
        </div>
        <p class="text-xs text-[#86909c] mt-2">The address of this admin web console</p>
      </div>
    </div>

    <p v-if="loadFailed" class="text-sm text-red-500 mt-4">
      Status load failed, please check if the service is running and the management port is reachable.
    </p>
  </div>
</template>
