<script setup lang="ts">
// Traffic monitoring page: hand-drawn Canvas rate chart + per-client traffic cards
import { onBeforeUnmount, onMounted, ref } from 'vue'
import http from '@/api'
import type { HistorySample, TrafficCounter, TrafficEntry } from '@/types'

const list = ref<TrafficEntry[]>([])
const loaded = ref(false)
const error = ref('')

// Chart state: client_id -> time/rate series
interface Series {
  t: number[]
  rate: number[]
}
const chartSeries = ref<Record<string, Series>>({})
const chartHidden = ref<Record<string, boolean>>({})

const PALETTE = [
  '#0284c7', '#059669', '#7c3aed', '#dc2626', '#d97706',
  '#0891b2', '#db2777', '#65a30d',
]

function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + ' ' + units[i]
}

function fmtTime(ms: number): string {
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return p(d.getHours()) + ':' + p(d.getMinutes())
}

// Derive B/s rate series from consecutive history samples
function buildRateSeries(hist: HistorySample[]): Record<string, Series> {
  const series: Record<string, Series> = {}
  for (let i = 1; i < hist.length; i++) {
    const prev = hist[i - 1]
    const cur = hist[i]
    const dt = (cur.ts_ms - prev.ts_ms) / 1000
    if (dt <= 0) continue
    for (const cid of Object.keys(cur.totals)) {
      const t = cur.totals[cid]
      const p: TrafficCounter = (prev.totals && prev.totals[cid]) || { tcp_up: 0, tcp_down: 0, udp_up: 0, udp_down: 0 }
      const rate =
        (t.tcp_up - p.tcp_up +
          (t.tcp_down - p.tcp_down) +
          (t.udp_up - p.udp_up) +
          (t.udp_down - p.udp_down)) /
        dt
      if (!series[cid]) series[cid] = { t: [], rate: [] }
      series[cid].t.push(cur.ts_ms)
      series[cid].rate.push(rate)
    }
  }
  return series
}

const canvasRef = ref<HTMLCanvasElement | null>(null)

function drawChart() {
  const canvas = canvasRef.value
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  if (!ctx) return

  const dpr = window.devicePixelRatio || 1
  const w = canvas.clientWidth || 600
  const h = canvas.clientHeight || 224
  canvas.width = w * dpr
  canvas.height = h * dpr
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)

  const pad = { l: 64, r: 16, t: 12, b: 28 }
  const pw = w - pad.l - pad.r
  const ph = h - pad.t - pad.b

  const visible = Object.keys(chartSeries.value).filter((c) => !chartHidden.value[c])
  let tMin = Infinity
  let tMax = -Infinity
  let maxRate = 0
  for (const c of visible) {
    const s = chartSeries.value[c]
    if (!s.t.length) continue
    if (s.t[0] < tMin) tMin = s.t[0]
    if (s.t[s.t.length - 1] > tMax) tMax = s.t[s.t.length - 1]
    for (const r of s.rate) if (r > maxRate) maxRate = r
  }
  if (!isFinite(tMin) || tMax <= tMin || maxRate <= 0) {
    ctx.fillStyle = '#94a3b8'
    ctx.font = '14px sans-serif'
    ctx.textAlign = 'center'
    ctx.fillText('No data available, click refresh to load', w / 2, h / 2)
    return
  }
  maxRate *= 1.1

  // Horizontal grid + Y labels
  ctx.strokeStyle = '#e2e8f0'
  ctx.lineWidth = 1
  ctx.font = '11px monospace'
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ph - (i / 4) * ph
    ctx.beginPath()
    ctx.moveTo(pad.l, y)
    ctx.lineTo(w - pad.r, y)
    ctx.stroke()
    ctx.fillStyle = '#64748b'
    ctx.textAlign = 'right'
    ctx.fillText(fmtBytes((maxRate * i) / 4) + '/s', pad.l - 6, y + 4)
  }

  // Time axis labels
  ctx.textAlign = 'center'
  ctx.fillStyle = '#64748b'
  for (let i = 0; i <= 4; i++) {
    const t = tMin + ((tMax - tMin) * i) / 4
    const x = pad.l + (i / 4) * pw
    ctx.fillText(fmtTime(t), x, h - 8)
  }

  // Rate lines
  const xOf = (t: number) => pad.l + ((t - tMin) / (tMax - tMin)) * pw
  const yOf = (r: number) => pad.t + ph - (r / maxRate) * ph
  visible.forEach((c, idx) => {
    const s = chartSeries.value[c]
    const color = PALETTE[idx % PALETTE.length]
    ctx.strokeStyle = color
    ctx.lineWidth = 2
    ctx.beginPath()
    let started = false
    for (let i = 0; i < s.t.length; i++) {
      const x = xOf(s.t[i])
      const y = yOf(s.rate[i])
      if (!started) {
        ctx.moveTo(x, y)
        started = true
      } else ctx.lineTo(x, y)
    }
    ctx.stroke()
  })
}

function toggleLegend(cid: string) {
  chartHidden.value[cid] = !chartHidden.value[cid]
}

async function load() {
  try {
    const [hRes, tRes] = await Promise.all([
      http.get<HistorySample[]>('/traffic/history'),
      http.get<TrafficEntry[]>('/traffic'),
    ])
    const hist = hRes.data
    const traffic = tRes.data

    chartSeries.value = buildRateSeries(hist)
    for (const c of Object.keys(chartSeries.value)) {
      if (chartHidden.value[c] === undefined) chartHidden.value[c] = false
    }
    list.value = traffic
    error.value = ''
    loaded.value = true
    drawChart()
  } catch {
    error.value = 'Loading failed'
  }
}

function onResize() {
  drawChart()
}

let timer: number | undefined
onMounted(() => {
  load()
  timer = window.setInterval(load, 5000)
  window.addEventListener('resize', onResize)
})
onBeforeUnmount(() => {
  window.clearInterval(timer)
  window.removeEventListener('resize', onResize)
})
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3 mb-4 sm:mb-6">
      <h1 class="text-xl sm:text-2xl font-semibold">Traffic Monitoring</h1>
      <button class="text-sm bg-slate-800 text-white px-4 py-2 rounded-lg hover:bg-slate-700" @click="load">Refresh</button>
    </div>

    <div class="bg-white rounded-xl shadow-sm p-4 sm:p-5 mb-6">
      <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
        <h2 class="font-semibold">Traffic Monitoring Chart</h2>
        <span class="text-xs text-slate-400">Last 100 minutes · 30s sampling · Click legend to toggle display</span>
      </div>
      <canvas ref="canvasRef" class="w-full h-52 sm:h-56"></canvas>
      <div class="mt-3 flex flex-wrap gap-3">
        <button
          v-for="(cid, idx) in Object.keys(chartSeries)"
          :key="cid"
          class="flex items-center gap-1.5 text-sm text-slate-600 hover:text-slate-900"
          :class="chartHidden[cid] ? 'opacity-40 line-through' : ''"
          @click="toggleLegend(cid)"
        >
          <span class="inline-block w-3 h-3 rounded-full" :style="{ background: PALETTE[idx % PALETTE.length] }"></span>
          {{ cid }}
        </button>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div v-if="!loaded" class="bg-white rounded-xl shadow-sm px-6 py-12 text-center text-slate-400">Loading...</div>
      <div v-else-if="error" class="bg-white rounded-xl shadow-sm px-6 py-12 text-center text-red-400 md:col-span-2">{{ error }}</div>
      <div v-else-if="!list.length" class="bg-white rounded-xl shadow-sm px-6 py-12 text-center text-slate-400 md:col-span-2">
        No traffic data available, click refresh to load
      </div>
      <div v-for="t in list" :key="t.client_id" class="bg-white rounded-xl shadow-sm p-4 sm:p-5">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-4">
          <span class="font-mono font-semibold text-slate-700 break-all">{{ t.client_id }}</span>
          <span class="text-xs text-slate-500">
            <span class="inline-block w-2 h-2 rounded-full mr-1" :class="t.online ? 'bg-emerald-500' : 'bg-slate-300'"></span>
            {{ t.online ? 'Online' : 'Offline' }}
          </span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div class="text-center">
            <div class="text-xs text-slate-400 mb-1">TCP Upload</div>
            <div class="font-mono text-sm sm:text-base font-semibold text-sky-600">{{ fmtBytes(t.tcp_up) }}</div>
          </div>
          <div class="text-center">
            <div class="text-xs text-slate-400 mb-1">TCP Download</div>
            <div class="font-mono text-sm sm:text-base font-semibold text-sky-600">{{ fmtBytes(t.tcp_down) }}</div>
          </div>
          <div class="text-center">
            <div class="text-xs text-slate-400 mb-1">UDP Upload</div>
            <div class="font-mono text-sm sm:text-base font-semibold text-violet-600">{{ fmtBytes(t.udp_up) }}</div>
          </div>
          <div class="text-center">
            <div class="text-xs text-slate-400 mb-1">UDP Download</div>
            <div class="font-mono text-sm sm:text-base font-semibold text-violet-600">{{ fmtBytes(t.udp_down) }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
