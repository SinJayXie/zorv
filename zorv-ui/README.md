# Zorv UI

Vue 3 admin console for the Zorv intranet penetration tool.

- **Framework**: Vue 3 + TypeScript + Vite
- **Styling**: Tailwind CSS (v4, via `@tailwindcss/vite`) + SCSS
- **State**: Pinia
- **Routing**: vue-router
- **HTTP**: axios (attaches `Authorization: Bearer <token>` to every API call)

## Development

```bash
pnpm install
pnpm dev        # local dev server (proxy the API via the zorvd admin port if needed)
```

## Build

```bash
pnpm build
```

The build output is written to `../html` (the Rust project root), which is
embedded into the `zorvd` binary at compile time by `build.rs`. Rebuild the
Rust binaries afterwards:

```bash
cd .. && cargo build --release
```
