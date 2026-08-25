<script setup lang="ts">
// Global toast host: renders all toasts pushed via useToast().
import { useToast } from '@/composables/useToast'

const { toasts, dismiss } = useToast()

const dotClass: Record<string, string> = {
  success: 'bg-emerald-500',
  error: 'bg-red-500',
  info: 'bg-sky-500',
}
</script>

<template>
  <div class="fixed top-16 right-3 sm:top-20 sm:right-6 z-[100] flex flex-col items-end gap-2 pointer-events-none">
    <TransitionGroup name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast pointer-events-auto flex items-start gap-2.5 max-w-[calc(100vw-1.5rem)] sm:max-w-sm bg-slate-900/95 text-white text-sm rounded-lg px-3.5 py-2.5 shadow-lg"
      >
        <span class="mt-1 w-2 h-2 rounded-full shrink-0" :class="dotClass[t.type]" />
        <span class="break-all min-w-0">{{ t.text }}</span>
        <button class="ml-1 text-slate-400 hover:text-white shrink-0 text-base leading-none" aria-label="Dismiss" @click="dismiss(t.id)">
          ×
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.2s ease;
}
.toast-enter-from {
  opacity: 0;
  transform: translateY(-6px);
}
.toast-leave-to {
  opacity: 0;
  transform: translateY(-6px);
}
</style>
