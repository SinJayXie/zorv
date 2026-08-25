<script setup lang="ts">
// Reusable confirmation dialog for destructive actions (kick / delete).
// Emits `confirm` / `cancel`; auto-closes on overlay click unless loading.
const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    message: string
    confirmText?: string
    cancelText?: string
    danger?: boolean
    loading?: boolean
  }>(),
  {
    confirmText: 'Confirm',
    cancelText: 'Cancel',
    danger: false,
    loading: false,
  },
)

const emit = defineEmits<{
  (e: 'confirm'): void
  (e: 'cancel'): void
}>()

function onCancel() {
  if (!props.loading) emit('cancel')
}
</script>

<template>
  <div v-if="open" class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" @click.self="onCancel">
    <div class="bg-white rounded-xl shadow-xl w-full max-w-sm p-6">
      <h3 class="text-lg font-semibold flex items-center gap-2.5">
        <span class="w-2.5 h-2.5 rounded-full" :class="danger ? 'bg-red-500' : 'bg-slate-800'" />
        {{ title }}
      </h3>
      <p class="text-sm text-slate-600 mt-3 break-all">{{ message }}</p>
      <div class="mt-6 flex justify-end gap-3">
        <button
          type="button"
          class="min-h-11 px-4 py-2 rounded-lg text-sm font-medium bg-slate-200 text-slate-700 hover:bg-slate-300 transition-colors"
          :disabled="loading"
          @click="onCancel"
        >
          {{ cancelText }}
        </button>
        <button
          type="button"
          class="min-h-11 px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors disabled:opacity-60"
          :class="danger ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-800 hover:bg-slate-700'"
          :disabled="loading"
          @click="emit('confirm')"
        >
          {{ loading ? 'Working…' : confirmText }}
        </button>
      </div>
    </div>
  </div>
</template>
