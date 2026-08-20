<script setup lang="ts">
// Online clients page: session info + one-click kick
import { onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import type { ClientInfo } from '@/types'

const clients = ref<ClientInfo[] | null>(null)
const error = ref('')

function fmtAgo(ms?: number): string {
  if (!ms) return '-'
  const ago = Date.now() - ms
  return Math.max(0, Math.round(ago / 1000)) + 's ago'
}

async function load() {
  try {
    const { data } = await http.get<ClientInfo[]>('/clients')
    clients.value = data
    error.value = ''
  } catch {
    error.value = 'Loading failed'
  }
}

async function kick(clientId: string) {
  if (!confirm(`Kick client ${clientId} ?`)) return
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/kick', { client_id: clientId })
    if (!data.ok) alert('Kick failed: ' + (data.error || 'unknown error'))
    load()
  } catch {
    alert('Kick failed')
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
    <div class="flex items-center justify-between mb-4 sm:mb-6">
      <h1 class="text-xl sm:text-2xl font-semibold">Online Clients</h1>
      <button class="text-sm bg-slate-800 text-white px-4 py-2 rounded-lg hover:bg-slate-700" @click="load">Refresh</button>
    </div>

    <div class="bg-white rounded-xl shadow-sm overflow-hidden">
      <table class="client-table w-full text-sm">
        <thead class="bg-slate-50 text-slate-500 text-left">
          <tr>
            <th class="px-4 py-3 font-medium">Client ID</th>
            <th class="px-4 py-3 font-medium">Session ID</th>
            <th class="px-4 py-3 font-medium">Active Streams</th>
            <th class="px-4 py-3 font-medium">Last Activity</th>
            <th class="px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!clients || !clients.length">
            <td colspan="5" class="px-4 py-8 text-center text-slate-400">
              {{ error || (!clients ? 'Loading…' : 'No online clients found') }}
            </td>
          </tr>
          <tr v-for="c in clients" v-else :key="c.session_id" class="border-t border-slate-100">
            <td data-label="Client ID" class="px-4 py-3 font-mono break-all">{{ c.client_id }}</td>
            <td data-label="Session ID" class="px-4 py-3 font-mono text-slate-500 break-all">{{ c.session_id }}</td>
            <td data-label="Active Streams" class="px-4 py-3">{{ c.active_streams }}</td>
            <td data-label="Last Activity" class="px-4 py-3 text-slate-500">{{ fmtAgo(c.last_activity_ms) }}</td>
            <td data-label="Actions" class="px-4 py-3">
              <button class="text-xs bg-red-50 text-red-600 border border-red-200 px-2 py-1 rounded hover:bg-red-100" @click="kick(c.client_id)">Kick</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped lang="scss">
// Mobile (<640px): the table becomes stacked cards, with field names shown inline via data-label
@media (max-width: 640px) {
  .client-table thead {
    display: none;
  }
  .client-table,
  .client-table tbody,
  .client-table tr,
  .client-table td {
    display: block;
    width: 100%;
  }
  .client-table tr {
    border-top: 1px solid #e2e8f0;
    padding: 0.5rem 0;
  }
  .client-table td {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.4rem 0.75rem;
    text-align: right;
  }
  .client-table td::before {
    content: attr(data-label);
    font-weight: 500;
    color: #94a3b8;
    text-align: left;
    flex-shrink: 0;
  }
}
</style>
