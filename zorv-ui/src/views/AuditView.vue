<script setup lang="ts">
// Audit log page: paged table of admin + proxy connection events
import { onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import type { AuditEntry, AuditPage } from '@/types'

const items = ref<AuditEntry[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 50
const error = ref('')

const totalPages = ref(0)

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
    const { data } = await http.get<AuditPage>('/audit', {
      params: { page: page.value, page_size: pageSize },
    })
    items.value = data.items
    total.value = data.total
    totalPages.value = Math.max(1, Math.ceil(data.total / pageSize))
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
    <div class="flex flex-wrap items-center justify-between gap-3 mb-4 sm:mb-6">
      <h1 class="text-xl sm:text-2xl font-semibold">Audit Log</h1>
      <button class="text-sm bg-slate-800 text-white px-4 py-2 rounded-lg hover:bg-slate-700" @click="load">Refresh</button>
    </div>

    <div class="bg-white rounded-xl shadow-sm overflow-hidden">
      <table class="audit-table w-full text-sm">
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
            <td colspan="4" class="px-4 py-8 text-center text-slate-400 table-empty">{{ error || 'No audit entries yet' }}</td>
          </tr>
          <tr v-for="(e, i) in items" :key="e.ts_ms + '-' + i" class="border-t border-slate-100">
            <td data-label="Time" class="px-4 py-3 font-mono text-slate-500 whitespace-nowrap">{{ fmtTime(e.ts_ms) }}</td>
            <td data-label="Action" class="px-4 py-3">
              <span class="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full font-mono">{{ e.action }}</span>
            </td>
            <td data-label="Detail" class="px-4 py-3 font-mono text-slate-700 break-all">{{ e.detail }}</td>
            <td data-label="Source IP" class="px-4 py-3 font-mono text-slate-500 whitespace-nowrap">{{ e.ip }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div v-if="total > 0" class="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-500">
      <span>Total {{ total }} entries · page {{ page }} / {{ totalPages }}</span>
      <div class="flex items-center gap-2">
        <button
          class="bg-white border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed"
          :disabled="page <= 1"
          @click="prevPage"
        >
          Previous
        </button>
        <button
          class="bg-white border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed"
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
    padding: 2rem 0.75rem;
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
