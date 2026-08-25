<script setup lang="ts">
// Audit log page: server-side filtered + paginated table of admin & proxy
// connection events, with expandable detail rows
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import CopyButton from '@/components/CopyButton.vue'
import type { AuditEntry, AuditPage } from '@/types'

const items = ref<AuditEntry[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 50
const error = ref('')

const totalPages = ref(0)

// ---------- Filters (server-side) ----------
const ACTION_OPTIONS = [
  'login',
  'proxy_connect',
  'kick',
  'reload',
  'upsert_proxy',
  'delete_proxy',
  'update_token',
  'change_password',
]
const TIME_OPTIONS = [
  { label: 'All time', value: '' },
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 6 hours', value: '6h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
]

const actionFilter = ref('')
const ipFilter = ref('')
const timeFilter = ref('')

const hasFilters = computed(() => !!actionFilter.value || !!ipFilter.value.trim() || !!timeFilter.value)

function fromMs(value: string): number | undefined {
  if (!value) return undefined
  const hours = parseInt(value, 10)
  if (!hours) return undefined
  return Date.now() - hours * 3600 * 1000
}

function clearFilters() {
  actionFilter.value = ''
  ipFilter.value = ''
  timeFilter.value = ''
  page.value = 1
  load()
}

function onFilterChange() {
  page.value = 1
  load()
}

// ---------- Expandable detail ----------
const expanded = ref<Set<string>>(new Set())

function detailKey(e: AuditEntry, i: number): string {
  return e.ts_ms + '-' + i
}

function toggleDetail(e: AuditEntry, i: number) {
  const key = detailKey(e, i)
  const next = new Set(expanded.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  expanded.value = next
}

function fmtTime(ms: number): string {
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  )
}

async function load() {
  try {
    const params: Record<string, string | number> = { page: page.value, page_size: pageSize }
    if (actionFilter.value) params.action = actionFilter.value
    const ip = ipFilter.value.trim()
    if (ip) params.ip = ip
    const from = fromMs(timeFilter.value)
    if (from) params.from = from

    const { data } = await http.get<AuditPage>('/audit', { params })
    items.value = data.items
    total.value = data.total
    totalPages.value = Math.max(1, Math.ceil(data.total / pageSize))
    expanded.value = new Set()
    // Clamp the page if it exceeds the last page (e.g. after a refresh)
    if (page.value > totalPages.value) {
      page.value = totalPages.value
      await load()
      return
    }
    error.value = ''
  } catch {
    error.value = 'Loading failed'
  }
}

function prevPage() {
  if (page.value > 1) {
    page.value--
    load()
  }
}

function nextPage() {
  if (page.value < totalPages.value) {
    page.value++
    load()
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
        <h1 class="text-xl sm:text-2xl font-semibold text-[#1d2129]">Audit Log</h1>
        <p class="text-sm text-[#86909c] mt-0.5">Admin actions and tunnel connection events</p>
      </div>
      <button
        class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-slate-800 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <!-- Filter toolbar -->
    <div class="mb-4 flex flex-wrap items-center gap-3">
      <select
        v-model="timeFilter"
        class="bg-white border border-slate-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500"
        @change="onFilterChange"
      >
        <option v-for="t in TIME_OPTIONS" :key="t.value" :value="t.value">{{ t.label }}</option>
      </select>

      <select
        v-model="actionFilter"
        class="bg-white border border-slate-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500"
        @change="onFilterChange"
      >
        <option value="">All actions</option>
        <option v-for="a in ACTION_OPTIONS" :key="a" :value="a">{{ a }}</option>
      </select>

      <div class="relative flex-1 min-w-52 max-w-xs">
        <svg class="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <circle cx="11" cy="11" r="7" />
          <path d="M21 21l-4.3-4.3" />
        </svg>
        <input
          v-model="ipFilter"
          type="text"
          placeholder="Search by source IP…"
          class="w-full bg-white border border-slate-300 rounded-lg pl-10 pr-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500 transition"
          @keyup.enter="onFilterChange"
          @change="onFilterChange"
        />
      </div>

      <button
        v-if="hasFilters"
        class="min-h-11 sm:min-h-10 inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-800 px-2 py-1 rounded-lg transition-colors"
        @click="clearFilters"
      >
        Clear filters
      </button>
    </div>

    <div class="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
      <div class="sm:max-h-[65vh] sm:overflow-y-auto">
        <table class="audit-table sticky-header w-full text-sm">
          <thead class="bg-slate-50 text-slate-500 text-left">
            <tr>
              <th class="px-4 py-3 font-medium">Time</th>
              <th class="px-4 py-3 font-medium">Action</th>
              <th class="px-4 py-3 font-medium">Detail</th>
              <th class="px-4 py-3 font-medium">Source IP</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!items.length">
              <td colspan="4" class="px-4 py-10 text-center table-empty">
                <div v-if="error" class="text-slate-400">{{ error }}</div>
                <div v-else-if="hasFilters" class="text-slate-400">No audit entries match the current filters</div>
                <div v-else class="text-slate-400">
                  <svg class="mx-auto mb-2 text-slate-300" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <path d="M14 2v6h6M8 13h8M8 17h8M8 9h2" />
                  </svg>
                  No audit entries yet
                </div>
              </td>
            </tr>
            <tr v-for="(e, i) in items" :key="detailKey(e, i)" class="border-t border-slate-100 hover:bg-slate-50/60">
              <td data-label="Time" class="px-4 py-3 font-mono text-slate-500 whitespace-nowrap">{{ fmtTime(e.ts_ms) }}</td>
              <td data-label="Action" class="px-4 py-3">
                <span class="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full font-mono whitespace-nowrap">{{ e.action }}</span>
              </td>
              <td data-label="Detail" class="px-4 py-3">
                <button class="flex items-start gap-1.5 w-full min-w-0 text-left group" :title="expanded.has(detailKey(e, i)) ? 'Collapse' : 'Click to view full detail'" @click="toggleDetail(e, i)">
                  <span
                    class="font-mono text-slate-700 text-xs min-w-0 flex-1 break-all"
                    :class="expanded.has(detailKey(e, i)) ? 'whitespace-normal' : 'sm:truncate'"
                  >{{ e.detail }}</span>
                  <svg
                    class="shrink-0 mt-0.5 text-slate-400 group-hover:text-slate-600 transition-transform duration-200"
                    :class="expanded.has(detailKey(e, i)) ? 'rotate-180' : ''"
                    width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                  >
                    <path d="M6 9l6 6 6-6" />
                  </svg>
                </button>
              </td>
              <td data-label="Source IP" class="px-4 py-3">
                <span class="inline-flex items-center gap-1 whitespace-nowrap">
                  <span class="font-mono text-slate-500">{{ e.ip }}</span>
                  <CopyButton :text="e.ip" />
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Pagination (bottom-right) -->
    <div v-if="total > 0" class="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-500">
      <span>Total {{ total }} entries · page {{ page }} / {{ totalPages }}</span>
      <div class="flex items-center gap-2">
        <button
          class="min-h-11 sm:min-h-9 bg-white border border-slate-300 px-3.5 py-1.5 rounded-lg font-medium hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          :disabled="page <= 1"
          @click="prevPage"
        >
          Previous
        </button>
        <button
          class="min-h-11 sm:min-h-9 bg-white border border-slate-300 px-3.5 py-1.5 rounded-lg font-medium hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          :disabled="page >= totalPages"
          @click="nextPage"
        >
          Next
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
// Mobile (<640px): the table becomes stacked cards, with field names shown inline via data-label
@media (max-width: 640px) {
  .audit-table thead {
    display: none;
  }
  .audit-table,
  .audit-table tbody,
  .audit-table tr,
  .audit-table td {
    display: block;
    width: 100%;
  }
  .audit-table tr {
    border-top: 1px solid #e2e8f0;
    padding: 0.5rem 0;
  }
  .audit-table td {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.4rem 0.75rem;
    text-align: right;
  }
  .audit-table td::before {
    content: attr(data-label);
    font-weight: 500;
    color: #94a3b8;
    text-align: left;
    flex-shrink: 0;
  }
  .audit-table td.table-empty {
    display: block;
    text-align: center;
    padding: 2.5rem 0.75rem;
  }
  // Long detail lines wrap instead of overflowing on small screens
  .audit-table td[data-label='Detail'] {
    align-items: flex-start;
  }
  .audit-table td[data-label='Time'] {
    white-space: normal;
  }
}
</style>
