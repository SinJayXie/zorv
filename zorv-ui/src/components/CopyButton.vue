<script setup lang="ts">
// One-click copy button with inline success feedback + toast.
import { ref } from 'vue'
import { copyText } from '@/composables/useClipboard'
import { useToast } from '@/composables/useToast'

const props = withDefaults(
  defineProps<{
    text: string
    /** Optional text label shown next to the icon */
    label?: string
    /** 'ghost' = icon only, transparent; 'outline' = bordered button */
    variant?: 'ghost' | 'outline'
    size?: 'sm' | 'md'
  }>(),
  {
    label: '',
    variant: 'ghost',
    size: 'sm',
  },
)

const toast = useToast()
const copied = ref(false)

async function onCopy() {
  const ok = await copyText(props.text)
  if (ok) {
    copied.value = true
    toast.success('Copied to clipboard')
    window.setTimeout(() => (copied.value = false), 1500)
  } else {
    toast.error('Copy failed, please copy manually')
  }
}

const btnClass = {
  ghost:
    'text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors',
  outline:
    'bg-white text-slate-600 border border-slate-300 rounded-lg hover:bg-slate-50 hover:text-slate-800 transition-colors',
}
const sizeClass = { sm: 'w-8 h-8', md: 'w-9 h-9' }
</script>

<template>
  <button
    type="button"
    :title="copied ? 'Copied' : 'Copy to clipboard'"
    class="inline-flex items-center justify-center gap-1.5 shrink-0"
    :class="[btnClass[variant], sizeClass[size], { 'text-emerald-600!': copied }]"
    @click="onCopy"
  >
    <svg v-if="copied" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 6L9 17l-5-5" />
    </svg>
    <svg v-else width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
    <span v-if="label" class="text-sm">{{ copied ? 'Copied' : label }}</span>
  </button>
</template>
