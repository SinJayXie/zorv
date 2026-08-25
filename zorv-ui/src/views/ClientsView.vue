<script setup lang="ts">
// Online clients page: session info, status dots, search + one-click kick
// (with confirmation modal and toast feedback)
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import CopyButton from '@/components/CopyButton.vue'
import { useToast } from '@/composables/useToast'
import type { ClientInfo } from '@/types'

const toast = useToast()

const clients = ref<ClientInfo[] | null>(null)
const error = ref('')
const search = ref('')

const filteredClients = computed(() => {
  const q = search.value.trim().toLowerCase()
  const list = clients.value || []
  if (!q) return list
  return list.filter((c) => c.client_id.toLowerCase().includes(q))
})

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

// Kick requires explicit confirmation
const kickTarget = ref<string | null>(null)
const kicking = ref(false)

function requestKick(clientId: string) {
  kickTarget.value = clientId
}

async function confirmKick() {
  if (!kickTarget.value) return
  kicking.value = true
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/kick', {
      client_id: kickTarget.value,
    })
    if (data.ok) {
      toast.success(`Client ${kickTarget.value} kicked`)
    } else {
      toast.error('Kick failed: ' + (data.error || 'unknown error'))
    }
    load()
  } catch {
    toast.error('Kick failed, please try again')
  } finally {
    kicking.value = false
    kickTarget.value = null
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
        <h1 class="text-xl sm:text-2xl font-semibold text-[#1d2129]">Online Clients</h1>
        <p class="text-sm text-[#86909c] mt-0.5">{{ clients?.length ?? '–' }} client{{ (clients?.length ?? 0) === 1 ? '' : 's' }} connected</p>
      </div>
      <button
        class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-slate-800 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <!-- Toolbar: search + refresh -->
    <div class="mb-4 flex flex-wrap items-center gap-3">
      <div class="relative flex-1 min-w-52 max-w-md">
        <svg class="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <circle cx="11" cy="11" r="7" />
          <path d="M21 21l-4.3-4.3" />
        </svg>
        <input
          v-model="search"
          type="text"
          placeholder="Search by Client ID…"
          class="w-full bg-white border border-slate-300 rounded-lg pl-10 pr-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500 transition"
        />
      </div>
      <span v-if="search.trim()" class="text-xs text-slate-500">{{ filteredClients.length }} match{{ filteredClients.length === 1 ? '' : 'es' }}</span>
    </div>

    <div class="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
      <div class="sm:max-h-[65vh] sm:overflow-y-auto">
        <table class="client-table sticky-header w-full text-sm">
          <thead class="bg-slate-50 text-slate-500 text-left">
            <tr>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Client ID</th>
              <th class="px-4 py-3 font-medium">Session ID</th>
              <th class="px-4 py-3 font-medium">Active Streams</th>
              <th class="px-4 py-3 font-medium">Last Activity</th>
              <th class="px-4 py-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!clients || !filteredClients.length">
              <td colspan="6" class="px-4 py-10 text-center table-empty">
                <div v-if="search.trim()" class="text-slate-400">No clients match "{{ search }}"</div>
                <div v-else-if="error" class="text-slate-400">{{ error }}</div>
                <div v-else-if="!clients" class="text-slate-400">Loading…</div>
                <div v-else class="text-slate-400">
                  <svg class="mx-auto mb-2 text-slate-300" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="9" cy="8" r="3.5" />
                    <path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6" />
                    <path d="M16 4.5a3.5 3.5 0 0 1 0 7M17.5 14.2c2 .9 4 2.8 4 5.8" />
                  </svg>
                  No online clients found
                </div>
              </td>
            </tr>
            <tr v-for="c in filteredClients" v-else :key="c.session_id" class="border-t border-slate-100 hover:bg-slate-50/60">
              <td data-label="Status" class="px-4 py-3">
                <span class="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600">
                  <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                  Online
                </span>
              </td>
              <td data-label="Client ID" class="px-4 py-3">
                <span class="font-mono break-all text-slate-800">{{ c.client_id }}</span>
              </td>
              <td data-label="Session ID" class="px-4 py-3">
                <span class="inline-flex items-center gap-1 max-w-full">
                  <span class="font-mono text-slate-500 break-all sm:max-w-[240px] sm:truncate" :title="c.session_id">{{ c.session_id }}</span>
                  <CopyButton :text="c.session_id" />
                </span>
              </td>
              <td data-label="Active Streams" class="px-4 py-3" :title="'Number of active proxy streams for ' + c.client_id">
                <span class="inline-flex items-center gap-1.5">
                  {{ c.active_streams }}
                  <span class="w-1.5 h-1.5 rounded-full" :class="c.active_streams > 0 ? 'bg-sky-500' : 'bg-slate-200'" :title="c.active_streams > 0 ? 'Streams active' : 'No active streams'"></span>
                </span>
              </td>
              <td data-label="Last Activity" class="px-4 py-3 text-slate-500 whitespace-nowrap">{{ fmtAgo(c.last_activity_ms) }}</td>
              <td data-label="Actions" class="px-4 py-3">
                <button
                  class="min-h-10 sm:min-h-8 inline-flex items-center gap-1.5 bg-white text-red-600 border border-red-300 rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-red-50 transition-colors"
                  @click="requestKick(c.client_id)"
                >
                  Kick
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <ConfirmDialog
      :open="!!kickTarget"
      title="Kick Client"
      :message="`Kick client ${kickTarget ?? ''}? This immediately disconnects the client and all of its active streams.`"
      confirm-text="Kick"
      cancel-text="Cancel"
      danger
      :loading="kicking"
      @confirm="confirmKick"
      @cancel="kickTarget = null"
    />
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
  .client-table td.table-empty {
    display: block;
    text-align: center;
    padding: 2.5rem 0.75rem;
  }
}
</style>
