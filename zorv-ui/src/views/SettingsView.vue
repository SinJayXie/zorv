<script setup lang="ts">
// Settings page: Token management / Change password (both in modals) /
// Config hot reload / Proxy rule CRUD with collapsible groups
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import http from '@/api'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import CopyButton from '@/components/CopyButton.vue'
import { useToast } from '@/composables/useToast'
import type { ClientInfo, ProxyRule, Status } from '@/types'

const router = useRouter()
const toast = useToast()

// ---------- Token management (modal) ----------
const tokenModal = ref(false)
const curToken = ref('')
const tokenInput = ref('')
const tokenMsg = ref<{ text: string; ok: boolean } | null>(null)

function openTokenModal() {
  tokenInput.value = ''
  tokenMsg.value = null
  tokenModal.value = true
}

async function loadToken() {
  try {
    const { data } = await http.get<Status>('/status')
    curToken.value = data.token
  } catch {
    /* ignore */
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
      tokenMsg.value = { text: 'Token updated', ok: true }
    } else {
      tokenMsg.value = { text: 'Update failed: ' + (data.error || ''), ok: false }
    }
  } catch {
    tokenMsg.value = { text: 'Request failed', ok: false }
  }
}

// ---------- Change password (modal) ----------
const pwdModal = ref(false)
const pwdOld = ref('')
const pwdNew = ref('')
const pwdConfirm = ref('')
const pwdMsg = ref<{ text: string; ok: boolean } | null>(null)

function openPwdModal() {
  pwdOld.value = ''
  pwdNew.value = ''
  pwdConfirm.value = ''
  pwdMsg.value = null
  pwdModal.value = true
}

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
const reloading = ref(false)

async function reloadConfig() {
  reloading.value = true
  try {
    const { data } = await http.post<{ ok: boolean; error?: string }>('/reload')
    if (data.ok) {
      toast.success('Config reloaded and applied')
      loadAll()
      loadToken()
    } else {
      toast.error('Reload failed: ' + (data.error || ''))
    }
  } catch {
    toast.error('Reload failed, please try again')
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

// Group rules by client_id, unbound rules always sorted last.
// Online clients without any rule are also merged in, so a newly-online
// client gets a config card (0 rules) on the settings page.
const groupedRules = computed(() => {
  const groups = new Map<string, ProxyRule[]>()
  for (const rule of rules.value) {
    const key = groupKey(rule)
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(rule)
  }
  for (const cid of onlineClients.value) {
    if (!groups.has(cid)) groups.set(cid, [])
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

// Collapsible rule groups (collapsed state kept in memory per session)
const collapsed = reactive<Record<string, boolean>>({})
function isCollapsed(key: string): boolean {
  return !!collapsed[key]
}
function toggleGroup(key: string) {
  collapsed[key] = !collapsed[key]
}

function ruleStr(rule: ProxyRule): string {
  return `${rule.listen ?? ''} → ${rule.target}`
}

// Proxy rule modal form state
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
  // Proxy rule name follows the same naming rules as client_id:
  // 1-64 chars of ASCII letters, digits, `-` and `_` only.
  const errs = {
    name: /^[A-Za-z0-9_-]{1,64}$/.test(name)
      ? ''
      : 'Name must be 1-64 characters using only letters, digits, - and _',
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

// Delete rule requires explicit confirmation
const deleteTarget = ref<string | null>(null)
const deleting = ref(false)

function requestDelete(name: string) {
  deleteTarget.value = name
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    const { data } = await http.delete<{ ok: boolean; error?: string }>('/proxies', {
      params: { name: deleteTarget.value },
    })
    if (data.ok) {
      toast.success(`Rule ${deleteTarget.value} deleted`)
    } else {
      toast.error('Delete failed: ' + (data.error || ''))
    }
    loadAll()
  } catch {
    toast.error('Delete request failed, please try again')
  } finally {
    deleting.value = false
    deleteTarget.value = null
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
  <div class="space-y-5">
    <!-- Account & Token: buttons open the modals -->
    <section class="bg-white rounded-xl p-5 sm:p-6 shadow-sm border border-slate-100">
      <h2 class="text-lg font-semibold text-[#1d2129]">Account & Token</h2>
      <p class="text-sm text-[#86909c] mt-1 mb-4">
        Manage the admin login password and the shared tunnel authentication token.
      </p>
      <div class="flex flex-wrap gap-3">
        <button
          class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
          @click="openTokenModal"
        >
          Token Management
        </button>
        <button
          class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
          @click="openPwdModal"
        >
          Change Password
        </button>
      </div>
    </section>

    <!-- Config hot reload -->
    <section class="bg-white rounded-xl p-5 sm:p-6 shadow-sm border border-slate-100">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0">
          <h2 class="text-lg font-semibold text-[#1d2129]">Config Hot Reload</h2>
          <p class="text-sm text-[#86909c] mt-1">
            Directly edit the server config file
            <code class="font-mono bg-slate-100 px-1.5 py-0.5 rounded break-all">zorvd.toml</code>
            then click reload to apply changes. (token and proxy rules will be applied)
          </p>
        </div>
        <button
          class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-slate-800 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors disabled:opacity-60"
          :disabled="reloading"
          @click="reloadConfig"
        >
          {{ reloading ? 'Reloading…' : 'Reload Config' }}
        </button>
      </div>
    </section>

    <!-- Proxy rules -->
    <div>
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h2 class="text-lg font-semibold text-[#1d2129]">Proxy Rules</h2>
          <p class="text-sm text-[#86909c] mt-0.5">Port-mapping rules grouped by bound client</p>
        </div>
        <button
          class="min-h-11 sm:min-h-10 inline-flex items-center gap-2 bg-white text-slate-700 border border-slate-300 px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
          @click="loadAll"
        >
          Refresh
        </button>
      </div>

      <div class="space-y-4">
        <div v-for="group in groupedRules" :key="group.clientId" class="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
          <!-- Group header (click to collapse/expand) -->
          <div class="px-5 py-4 flex items-center gap-3 border-b border-slate-100">
            <button
              class="flex items-center gap-2.5 min-w-0 flex-1 text-left group"
              :aria-expanded="!isCollapsed(group.clientId)"
              @click="toggleGroup(group.clientId)"
            >
              <svg
                class="shrink-0 text-slate-400 transition-transform duration-200"
                :class="isCollapsed(group.clientId) ? '-rotate-90' : ''"
                width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
              >
                <path d="M6 9l6 6 6-6" />
              </svg>
              <span class="font-semibold text-[#1d2129] break-all">{{ group.clientId }}</span>
              <span
                v-if="group.clientId !== UNBOUND_KEY"
                class="inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full shrink-0"
                :class="onlineClients.has(group.clientId) ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-400'"
              >
                <span class="w-1.5 h-1.5 rounded-full" :class="onlineClients.has(group.clientId) ? 'bg-emerald-500' : 'bg-slate-300'"></span>
                {{ onlineClients.has(group.clientId) ? 'Online' : 'Offline' }}
              </span>
              <span class="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full shrink-0">{{ group.items.length }} rules</span>
            </button>
            <button
              class="min-h-10 sm:min-h-8 shrink-0 inline-flex items-center gap-1.5 bg-white text-slate-700 border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-slate-50 transition-colors"
              @click="openProxyModal(group.clientId)"
            >
              Add rule
            </button>
          </div>

          <!-- Rules list -->
          <div v-if="!isCollapsed(group.clientId)">
            <div v-for="rule in group.items" :key="rule.name" class="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-slate-100 last:border-b-0 hover:bg-slate-50/60">
              <div class="min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-medium text-[#1d2129]">{{ rule.name }}</span>
                  <span class="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full">{{ rule.type }}</span>
                </div>
                <div class="flex items-center gap-1.5 mt-1 min-w-0">
                  <code class="text-sm text-slate-500 font-mono break-all">{{ rule.listen }} → {{ rule.target }}</code>
                  <CopyButton :text="ruleStr(rule)" />
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button
                  class="min-h-10 sm:min-h-8 inline-flex items-center bg-white text-slate-600 border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-slate-50 transition-colors"
                  @click="openProxyModal(group.clientId, rule)"
                >
                  Edit
                </button>
                <button
                  class="min-h-10 sm:min-h-8 inline-flex items-center bg-white text-red-600 border border-red-300 rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-red-50 transition-colors"
                  @click="requestDelete(rule.name)"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Empty state -->
        <div v-if="!groupedRules.length" class="bg-white rounded-xl shadow-sm border border-slate-100 p-10 text-center">
          <svg class="mx-auto mb-2 text-slate-300" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
            <path d="M9 12h6M12 9v6" />
          </svg>
          <p class="text-sm text-slate-400">No proxy rules yet. Add a rule to expose a service through the tunnel.</p>
        </div>
      </div>
    </div>

    <!-- Token management modal -->
    <div v-if="tokenModal" class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center" @click.self="tokenModal = false">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
        <h3 class="text-lg font-semibold text-[#1d2129]">Token Management</h3>
        <p class="text-sm text-slate-500 mt-1 mb-4">All clients use this shared token to authenticate.</p>

        <div class="flex items-center gap-3 mb-4 bg-slate-50 rounded-lg px-4 py-3">
          <span class="text-sm text-slate-500 shrink-0">Current Token</span>
          <code class="flex-1 min-w-0 font-mono text-sm text-slate-700 break-all">{{ curToken || '-' }}</code>
          <CopyButton v-if="curToken" :text="curToken" />
        </div>

        <input
          v-model="tokenInput"
          type="text"
          placeholder="Leave empty to generate new random token"
          class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500"
        />

        <p v-if="tokenMsg" class="text-sm mt-2" :class="tokenMsg.ok ? 'text-emerald-600' : 'text-red-500'">{{ tokenMsg.text }}</p>

        <div class="mt-5 flex flex-col-reverse sm:flex-row justify-end gap-3">
          <button class="min-h-11 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors" @click="tokenModal = false">Close</button>
          <button class="min-h-11 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors" @click="updateToken(true)">Generate Random</button>
          <button class="min-h-11 bg-slate-800 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors" @click="updateToken(false)">Save</button>
        </div>
      </div>
    </div>

    <!-- Change password modal -->
    <div v-if="pwdModal" class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center" @click.self="pwdModal = false">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
        <h3 class="text-lg font-semibold text-[#1d2129]">Change Password</h3>
        <p class="text-sm text-slate-500 mt-1 mb-4">
          After changing it, all active sessions will be logged out and you must sign in again.
        </p>
        <div class="space-y-3">
          <input v-model="pwdOld" type="password" autocomplete="current-password" placeholder="Current password"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500" />
          <input v-model="pwdNew" type="password" autocomplete="new-password" placeholder="New password (at least 8 characters)"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500" />
          <input v-model="pwdConfirm" type="password" autocomplete="new-password" placeholder="Confirm new password"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500" />
        </div>
        <p v-if="pwdMsg" class="text-sm mt-2" :class="pwdMsg.ok ? 'text-emerald-600' : 'text-red-500'">{{ pwdMsg.text }}</p>
        <div class="mt-5 flex flex-col-reverse sm:flex-row justify-end gap-3">
          <button class="min-h-11 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors" @click="pwdModal = false">Cancel</button>
          <button class="min-h-11 bg-slate-800 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors" @click="changePassword">Update Password</button>
        </div>
      </div>
    </div>

    <!-- Proxy rule modal -->
    <div v-if="modal.show" class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center" @click.self="closeProxyModal">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
        <h3 class="text-lg font-semibold text-[#1d2129]">{{ modal.editingName ? 'Edit proxy' : 'Create proxy' }}</h3>
        <p class="text-sm text-slate-500 mt-1 mb-4">
          {{ modal.clientId === UNBOUND_KEY ? 'Unbound client' : 'Bound client: ' + modal.clientId }}
        </p>
        <div class="space-y-3">
          <input v-model="modal.name" maxlength="64" placeholder="Name (required)" :disabled="!!modal.editingName"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500 disabled:bg-slate-100"
            :class="{ 'border-red-400': modal.fieldErr.name }" />
          <select v-model="modal.type" class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none bg-white">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
          <input v-model="modal.listen" maxlength="64" placeholder="Public listen address 0.0.0.0:2222"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500"
            :class="{ 'border-red-400': modal.fieldErr.listen }" />
          <input v-model="modal.target" maxlength="256" placeholder="Internal target 127.0.0.1:22"
            class="w-full border border-slate-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-slate-500/40 focus:border-slate-500"
            :class="{ 'border-red-400': modal.fieldErr.target }" />
        </div>
        <p class="text-sm mt-2 text-red-500">{{ modal.msg }}</p>
        <div class="mt-5 flex flex-col-reverse sm:flex-row justify-end gap-3">
          <button class="min-h-11 bg-white text-slate-700 border border-slate-300 px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors" @click="closeProxyModal">Cancel</button>
          <button class="min-h-11 bg-slate-800 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-slate-700 transition-colors" @click="submitProxy">
            {{ modal.editingName ? 'Save' : 'Create' }}
          </button>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :open="!!deleteTarget"
      title="Delete Proxy Rule"
      :message="`Delete rule ${deleteTarget ?? ''}? This stops the public listener and removes the rule.`"
      confirm-text="Delete"
      cancel-text="Cancel"
      danger
      :loading="deleting"
      @confirm="confirmDelete"
      @cancel="deleteTarget = null"
    />
  </div>
</template>
