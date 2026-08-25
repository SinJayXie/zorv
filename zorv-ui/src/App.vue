<script setup lang="ts">
// Root component: renders the active route + the global toast host
import ToastHost from '@/components/ToastHost.vue'
</script>

<template>
  <router-view />
  <ToastHost />
</template>
