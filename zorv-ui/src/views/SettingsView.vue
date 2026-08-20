<script setup lang="ts">
// Settings page: Token management / Change password / Config hot reload / Proxy rule CRUD
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import http from '@/api'
import type { ClientInfo, ProxyRule, Status } from '@/types'

const router = useRouter()

// ---------- Token management ----------
const curToken = ref('')
const tokenInput = ref('')
const tokenMsg = ref<{ text: string; ok: boolean } | null>(null)

async function loadToken() {
  try {
    const { data } = await http.get<Status>('/status')
    curToken.value = data.token
  } catch {
    /* ignore */
  }
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    tokenMsg.value = { text: 'Token copied to clipboard', ok: true }
  } catch {
    tokenMsg.value = { text: 'Copy failed, please try manually: ' + text, ok: false }
  }
}

async function updateToken(generate = false) {
  if (generate) tokenInput.value = ''
  try {
    const { data } = await http.put<{ ok: boolean; token?: string; error?: string }>('/token', {
      token: tokenInput.value.trim(),
    })
    if (data.ok && data.token) {
      tokenInput.value = ''
      curToken.value = data.token
      tokenMsg.value = { text: 'Token copied to clipboard', ok: true }
      await copyText(data.token)
    } else {
      tokenMsg.value = { text: 'Update failed: ' + (data.error || ''), ok: false }
    }
  } catch {
    tokenMsg.value = { text: 'Request failed', ok: false }
  }
}

// ---------- Change password ----------
const pwdOld = ref('')
const pwdNew = ref('')
const pwdConfirm = ref('')
const pwdMsg = ref<{ text: string; ok: boolean } | null>(null)

async function changePassword() {
  if (pwdNew.value.length < 8) {
    pwdMsg.value = { text: 'New password must be at least 8 characters', ok: false }
    return
  }
  if (pwdNew.value !== pwdConfirm.value) {
    pwdMsg.value = { text: 'The two password inputs do not match', ok: false }
    return
  }
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/password', {
      old_password: pwdOld.value,
      new_password: pwdNew.value,
    })
    if (data.ok) {
      pwdOld.value = ''
      pwdNew.value = ''
      pwdConfirm.value = ''
      pwdMsg.value = { text: 'Password updated. Please sign in again with the new password.', ok: true }
      setTimeout(() => router.push('/login'), 1200)
    } else {
      pwdMsg.value = { text: 'Update failed: ' + (data.error || ''), ok: false }
    }
  } catch {
    pwdMsg.value = { text: 'Request failed', ok: false }
  }
}

// ---------- Config hot reload ----------
const reloadMsg = ref<{ text: string; ok: boolean } | null>(null)
const reloading = ref(false)

async function reloadConfig() {
  reloading.value = true
  reloadMsg.value = null
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/reload')
    if (data.ok) {
      reloadMsg.value = { text: 'Config reloaded and applied', ok: true }
      loadAll()
      loadToken()
    } else {
      reloadMsg.value = { text: 'Reload failed: ' + (data.error || ''), ok: false }
    }
  } catch {
    reloadMsg.value = { text: 'Request failed', ok: false }
  } finally {
    reloading.value = false
  }
}

// ---------- Proxy rules ----------
const UNBOUND_KEY = '(Unbound client)'
const rules = ref<ProxyRule[]>([])
const onlineClients = ref<Set<string>>(new Set())

function groupKey(rule: ProxyRule): string {
  return rule.client_id || UNBOUND_KEY
}

// Group rules by client_id, unbound rules always sorted last
const groupedRules = computed(() => {
  const groups = new Map<string, ProxyRule[]>()
  for (const rule of rules.value) {
    const key = groupKey(rule)
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(rule)
  }
  return Array.from(groups.entries())
    .map(([clientId, items]) => ({
      clientId,
      items: items.sort((a, b) => a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => {
      const aU = a.clientId === UNBOUND_KEY ? 1 : 0
      const bU = b.clientId === UNBOUND_KEY ? 1 : 0
      return aU - bU || a.clientId.localeCompare(b.clientId)
    })
})

// Modal form state
const modal = reactive({
  show: false,
  editingName: '',
  clientId: '',
  name: '',
  type: 'tcp',
  listen: '',
  target: '',
  msg: '',
  fieldErr: { name: false, listen: false, target: false },
})

function isValidAddr(s: string): boolean {
  if (!s) return false
  const idx = s.lastIndexOf(':')
  if (idx <= 0 || idx === s.length - 1) return false
  const port = s.slice(idx + 1)
  if (!/^\d{1,5}$/.test(port)) return false
  const n = parseInt(port, 10)
  return n >= 1 && n <= 65535
}

async function loadAll() {
  try {
    const [pRes, cRes] = await Promise.all([
      http.get<ProxyRule[]>('/proxies'),
      http.get<ClientInfo[]>('/clients'),
    ])
    rules.value = pRes.data
    onlineClients.value = new Set(cRes.data.map((c) => c.client_id))
  } catch {
    /* ignore */
  }
}

function openProxyModal(clientId: string, proxy?: ProxyRule) {
  modal.show = true
  modal.editingName = proxy ? proxy.name : ''
  modal.clientId = clientId
  modal.name = proxy ? proxy.name : ''
  modal.type = proxy ? proxy.type : 'tcp'
  modal.listen = proxy?.listen || ''
  modal.target = proxy?.target || ''
  modal.msg = ''
  modal.fieldErr = { name: false, listen: false, target: false }
}

function closeProxyModal() {
  modal.show = false
}

async function submitProxy() {
  const name = modal.name.trim()
  const errs = {
    name: !name ? 'Name is required' : /\s/.test(name) ? 'Name cannot contain spaces' : name.length > 64 ? 'Name must be at most 64 characters' : '',
    listen: isValidAddr(modal.listen.trim()) ? '' : 'Listen address must be host:port (port range 1-65535)',
    target: isValidAddr(modal.target.trim()) ? '' : 'Target address must be host:port (port range 1-65535)',
  }
  modal.fieldErr = {
    name: !!errs.name,
    listen: !!errs.listen,
    target: !!errs.target,
  }
  if (errs.name || errs.listen || errs.target) {
    modal.msg = errs.name || errs.listen || errs.target
    return
  }
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/proxies', {
      name,
      type: modal.type,
      listen: modal.listen.trim(),
      client_id: modal.clientId === UNBOUND_KEY ? null : modal.clientId,
      target: modal.target.trim(),
    })
    if (data.ok) {
      closeProxyModal()
      loadAll()
    } else {
      modal.msg = 'Save failed: ' + (data.error || '')
    }
  } catch {
    modal.msg = 'Request failed: please try again later'
  }
}

async function deleteProxy(name: string) {
  if (!confirm('Delete proxy ' + name + '?')) return
  try {
    const { data } = await http.delete<{ ok: boolean; error?: string }>('/proxies', {
      params: { name },
    })
    if (!data.ok) alert('Delete failed: ' + (data.error || ''))
    loadAll()
  } catch {
    alert('Delete request failed: please try again later')
  }
}

onMounted(() => {
  loadAll()
  loadToken()
  setInterval(loadAll, 10000)
  setInterval(loadToken, 10000)
})
</script>

<template>
  <div class="space-y-6 sm:space-y-8">
    <!-- Token management -->
    <section class="bg-white rounded-xl p-5 sm:p-6 shadow-sm">
      <h2 class="text-lg font-semibold mb-1">Token Management</h2>
      <p class="text-sm text-slate-500 mb-4">All clients use this shared token to authenticate.</p>
      <div v-if="curToken" class="hidden flex flex-wrap items-center gap-3 mb-4 bg-slate-50 rounded-lg px-4 py-3">
        <span class="text-sm text-slate-500">Current Token</span>
        <code class="flex-1 min-w-0 font-mono text-sm text-slate-700 break-all">{{ curToken }}</code>
        <button class="text-sm text-emerald-700 hover:text-emerald-900 font-medium" @click="copyText(curToken)">Copy</button>
      </div>
      <div class="flex flex-col sm:flex-row gap-3">
        <input
          v-model="tokenInput"
          type="text"
          placeholder="Leave empty to generate new random token"
          class="w-full sm:flex-1 border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500"
        />
        <button class="bg-slate-800 text-white px-5 py-2 rounded-lg hover:bg-slate-700" @click="updateToken(false)">Save</button>
        <button class="bg-slate-200 text-slate-700 px-5 py-2 rounded-lg hover:bg-slate-300" @click="updateToken(true)">Generate Random Token</button>
      </div>
      <p v-if="tokenMsg" class="text-sm mt-2" :class="tokenMsg.ok ? 'text-emerald-600' : 'text-red-500'">{{ tokenMsg.text }}</p>
    </section>

    <!-- Change password -->
    <section class="bg-white rounded-xl p-5 sm:p-6 shadow-sm">
      <h2 class="text-lg font-semibold mb-1">Change Password</h2>
      <p class="text-sm text-slate-500 mb-4">
        Update the admin login password. After changing it, all active sessions will be logged out and you must sign in again.
      </p>
      <div class="space-y-3">
        <input v-model="pwdOld" type="password" autocomplete="current-password" placeholder="Current password"
          class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500" />
        <input v-model="pwdNew" type="password" autocomplete="new-password" placeholder="New password (at least 8 characters)"
          class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500" />
        <input v-model="pwdConfirm" type="password" autocomplete="new-password" placeholder="Confirm new password"
          class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500" />
      </div>
      <button class="mt-4 bg-slate-800 text-white px-5 py-2 rounded-lg hover:bg-slate-700" @click="changePassword">Update Password</button>
      <p v-if="pwdMsg" class="text-sm mt-2" :class="pwdMsg.ok ? 'text-emerald-600' : 'text-red-500'">{{ pwdMsg.text }}</p>
    </section>

    <!-- Config hot reload -->
    <section class="bg-white rounded-xl p-5 sm:p-6 shadow-sm">
      <h2 class="text-lg font-semibold mb-1">Config Hot Reload</h2>
      <p class="text-sm text-slate-500 mb-4">
        Directly edit the server config file
        <code class="font-mono bg-slate-100 px-1.5 py-0.5 rounded break-all">zorvd.toml</code>
        after editing, click reload to apply changes. (token and proxy rules will be applied)
      </p>
      <button class="bg-slate-800 text-white px-5 py-2 rounded-lg hover:bg-slate-700 disabled:opacity-60" :disabled="reloading" @click="reloadConfig">
        {{ reloading ? 'Reloading...' : 'Reload Config' }}
      </button>
      <p v-if="reloadMsg" class="text-sm mt-2" :class="reloadMsg.ok ? 'text-emerald-600' : 'text-red-500'">{{ reloadMsg.text }}</p>
    </section>

    <!-- Proxy rules -->
    <div>
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold">Proxy Rules</h2>
        <button class="text-sm bg-white border border-slate-200 px-4 py-2 rounded-lg hover:bg-slate-50" @click="loadAll">Refresh</button>
      </div>
      <div class="space-y-6">
        <div v-for="group in groupedRules" :key="group.clientId" class="bg-white rounded-xl shadow-sm overflow-hidden">
          <div class="px-5 sm:px-6 py-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-100">
            <div class="flex items-center gap-3 flex-wrap min-w-0">
              <span class="font-semibold text-lg break-all">{{ group.clientId }}</span>
              <span v-if="group.clientId !== UNBOUND_KEY"
                class="text-xs px-2 py-0.5 rounded-full"
                :class="onlineClients.has(group.clientId) ? 'bg-emerald-100 text-emerald-600' : 'bg-slate-100 text-slate-400'">
                {{ onlineClients.has(group.clientId) ? 'Online' : 'Offline' }}
              </span>
              <span class="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full">{{ group.items.length }} rules</span>
            </div>
            <button class="text-sm bg-slate-100 px-4 py-2 rounded-lg hover:bg-slate-200" @click="openProxyModal(group.clientId)">Add rule</button>
          </div>
          <div v-for="rule in group.items" :key="rule.name" class="flex flex-wrap items-center justify-between gap-3 px-5 sm:px-6 py-4 border-b border-slate-100 hover:bg-slate-50">
            <div class="min-w-0">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="font-medium">{{ rule.name }}</span>
                <span class="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full">{{ rule.type }}</span>
              </div>
              <p class="text-sm text-slate-500 font-mono mt-1 break-all">{{ rule.listen }} → {{ rule.target }}</p>
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <button class="text-slate-500 hover:text-slate-700 text-xs" @click="openProxyModal(group.clientId, rule)">编辑</button>
              <button class="text-red-500 hover:text-red-700 text-xs" @click="deleteProxy(rule.name)">删除</button>
            </div>
          </div>
        </div>
        <div v-if="!groupedRules.length" class="bg-white rounded-xl shadow-sm p-10 text-center text-slate-400">No proxy rules available</div>
      </div>
    </div>

    <!-- Proxy rule modal -->
    <div v-if="modal.show" class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center" @click.self="closeProxyModal">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
        <h3 class="text-lg font-semibold">{{ modal.editingName ? 'Edit proxy' : 'Create proxy' }}</h3>
        <p class="text-sm text-slate-500 mt-1 mb-4">
          {{ modal.clientId === UNBOUND_KEY ? 'Unbound client' : 'Bound client: ' + modal.clientId }}
        </p>
        <div class="space-y-3">
          <input v-model="modal.name" maxlength="64" placeholder="Name (required)" :disabled="!!modal.editingName"
            class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500 disabled:bg-slate-100"
            :class="{ 'border-red-400': modal.fieldErr.name }" />
          <select v-model="modal.type" class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none bg-white">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
          <input v-model="modal.listen" maxlength="64" placeholder="Public listen address 0.0.0.0:2222"
            class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500"
            :class="{ 'border-red-400': modal.fieldErr.listen }" />
          <input v-model="modal.target" maxlength="256" placeholder="Internal target 127.0.0.1:22"
            class="w-full border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-slate-500"
            :class="{ 'border-red-400': modal.fieldErr.target }" />
        </div>
        <p class="text-sm mt-2 text-red-500">{{ modal.msg }}</p>
        <div class="mt-5 flex justify-end gap-3">
          <button class="bg-slate-200 text-slate-700 px-5 py-2 rounded-lg hover:bg-slate-300" @click="closeProxyModal">Cancel</button>
          <button class="bg-slate-800 text-white px-5 py-2 rounded-lg hover:bg-slate-700" @click="submitProxy">
            {{ modal.editingName ? 'Save' : 'Create' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
