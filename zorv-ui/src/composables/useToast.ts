// Global toast notification store (module-level shared state).
// Any component can call `useToast()` and push a toast that renders in ToastHost.
import { reactive } from 'vue'

export interface ToastItem {
  id: number
  text: string
  type: 'success' | 'error' | 'info'
}

const toasts = reactive<ToastItem[]>([])
let nextId = 1

function dismiss(id: number) {
  const i = toasts.findIndex((t) => t.id === id)
  if (i !== -1) toasts.splice(i, 1)
}

function show(text: string, type: ToastItem['type'] = 'info', duration = 3000) {
  const id = nextId++
  toasts.push({ id, text, type })
  window.setTimeout(() => dismiss(id), duration)
}

export function useToast() {
  return {
    toasts,
    show,
    success: (text: string, duration?: number) => show(text, 'success', duration),
    error: (text: string, duration?: number) => show(text, 'error', duration),
    info: (text: string, duration?: number) => show(text, 'info', duration),
    dismiss,
  }
}
