// Backend API data types (matching the zorvd admin API)

/** GET /api/status */
export interface Status {
  clients: number
  proxies: number
  tunnel_addr: string
  admin_listen: string
  token: string
}

/** GET /api/clients 返回的在线客户端 */
export interface ClientInfo {
  client_id: string
  session_id: string
  active_streams: number
  last_activity_ms: number
}

/** 单个客户端的流量计数器 */
export interface TrafficCounter {
  tcp_up: number
  tcp_down: number
  udp_up: number
  udp_down: number
}

/** GET /api/traffic 返回的单条流量汇总 */
export interface TrafficEntry {
  client_id: string
  online: boolean
  tcp_up: number
  tcp_down: number
  udp_up: number
  udp_down: number
}

/** Time-series sample from GET /api/traffic/history */
export interface HistorySample {
  ts_ms: number
  totals: Record<string, TrafficCounter>
}

/** Proxy rule (/api/proxies) */
export interface ProxyRule {
  name: string
  type: string
  listen?: string | null
  client_id?: string | null
  target: string
}

/** A single audit entry from GET /api/audit */
export interface AuditEntry {
  ts_ms: number
  action: string
  detail: string
  ip: string
}

/** Paged audit response */
export interface AuditPage {
  total: number
  page: number
  page_size: number
  items: AuditEntry[]
}

/** Common success response { ok: true, ... } */
export interface ApiOk {
  ok: boolean
  [key: string]: unknown
}

/** 统一失败响应 { ok: false, error } */
export interface ApiError {
  ok: boolean
  error: string
}
