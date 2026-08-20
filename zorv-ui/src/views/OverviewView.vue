<script setup lang="ts">
// Overview page: online clients / proxy rules / tunnel address status cards
import { onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
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
    <h1 class="text-xl sm:text-2xl font-semibold mb-4 sm:mb-6">Overview</h1>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
      <div class="bg-white rounded-xl p-5 shadow-sm">
        <p class="text-sm text-slate-500">Online Clients</p>
        <p class="text-3xl font-bold mt-1">{{ stat?.clients ?? '–' }}</p>
      </div>
      <div class="bg-white rounded-xl p-5 shadow-sm">
        <p class="text-sm text-slate-500">Proxies</p>
        <p class="text-3xl font-bold mt-1">{{ stat?.proxies ?? '–' }}</p>
      </div>
      <div class="bg-white rounded-xl p-5 shadow-sm col-span-2">
        <p class="text-sm text-slate-500">Tunnel Address</p>
        <p class="text-lg font-mono mt-1 break-all">{{ stat?.tunnel_addr ?? '–' }}</p>
      </div>
      <div class="bg-white rounded-xl p-5 shadow-sm col-span-2">
        <p class="text-sm text-slate-500">Admin Console Listen</p>
        <p class="text-lg font-mono mt-1 break-all">{{ stat?.admin_listen ?? '–' }}</p>
      </div>
    </div>
    <p v-if="loadFailed" class="text-xs text-slate-400 mt-4">
      Status load failed, please check if the service is running and the management port is reachable.
    </p>
  </div>
</template>
