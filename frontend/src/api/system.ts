import http from './http'

function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

// ==================== 审计日志 ====================

export interface AuditLog {
  id: string
  username: string
  login_ip: string | null
  log_type: string
  description: string
  status: string
  created_at: string
}

export interface AuditLogQuery {
  username?: string
  login_ip?: string
  log_type?: string
  status?: string
  description?: string
  start_time?: string
  end_time?: string
  page?: number
  page_size?: number
}

export interface PagedResult<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export const auditApi = {
  list: (params?: AuditLogQuery) =>
    unwrap<PagedResult<AuditLog>>(http.get('/audit/logs', { params })),
  types: () => unwrap<{ types: string[] }>(http.get('/audit/logs/types')),
  export: (params?: AuditLogQuery) =>
    http.get<Blob>('/audit/logs/export-xlsx', { params, responseType: 'blob' }),
  // 删除指定日志（按条件或全部）
  delete: (params?: AuditLogQuery) => http.delete('/audit/logs', { params }),
  // 清空日志
  clean: () => http.post('/audit/logs/clean'),
  // 备份策略
  getBackupPolicy: () =>
    unwrap<BackupPolicy>(http.get('/audit/logs/backup-policy')),
  updateBackupPolicy: (policy: BackupPolicy) =>
    http.put('/audit/logs/backup-policy', policy),
  // 执行备份
  backup: () => unwrap<{ message: string }>(http.post('/audit/logs/backup')),
}

// 日志备份策略
export interface BackupPolicy {
  enabled: boolean
  retention_days: number
  max_size_mb: number
  backup_dir: string
  schedule: string
}

// ==================== 报表 ====================

export type ReportFormat = 'pdf' | 'html' | 'xlsx' | 'xml'
export type ReportType = 'comprehensive' | 'vulnerability' | 'baseline' | 'weak_password'

export interface GenerateReportRequest {
  task_id: string
  format?: ReportFormat
  type?: ReportType
  name?: string
}

export const reportApi = {
  generate: (data: GenerateReportRequest) =>
    http.post<Blob>('/reports/generate', data, { responseType: 'blob' }),
  download: (taskId: string, format?: string) =>
    http.get<Blob>(`/reports/${taskId}/download`, {
      params: { format },
      responseType: 'blob',
    }),
}

// ==================== 系统管理 ====================

export interface PasswordPolicy {
  min_length: number
  require_complexity: boolean
  require_special_char: boolean
  expiry_days: number
  history_count: number
  lockout_threshold: number
  lockout_duration_minutes: number
}

export interface SystemMonitor {
  cpu: {
    usage_percent: number
    cores: number
    brand: string
  }
  memory: {
    total_bytes: number
    used_bytes: number
    usage_percent: number
  }
  swap: {
    total_bytes: number
    used_bytes: number
  }
  disks: Array<{
    name: string
    file_system: string
    mount_point: string
    total_bytes: number
    used_bytes: number
    available_bytes: number
    usage_percent: number
  }>
  load_average: any
  uptime_seconds: number
}

export interface NetworkInterface {
  name: string
  addresses: Array<{
    family: string
    address: string
    prefixlen: number
  }>
}

export interface ServiceInfo {
  name: string
  status: string
  enabled: boolean
  description: string | null
}

export const systemApi = {
  // 密码策略
  getPasswordPolicy: () => unwrap<PasswordPolicy>(http.get('/system/password-policy')),
  updatePasswordPolicy: (policy: PasswordPolicy) =>
    unwrap<{ message: string; policy: any }>(http.put('/system/password-policy', { policy })),
  // 系统监控
  monitor: () => unwrap<SystemMonitor>(http.get('/system/monitor')),
  // 网络配置
  getNetworkConfig: () =>
    unwrap<{ interfaces: NetworkInterface[]; hosts?: string }>(http.get('/system/network')),
  updateHosts: (hosts: string) => http.put('/system/network/hosts', { hosts }),
  // 服务管理
  listServices: () => unwrap<{ services: ServiceInfo[] }>(http.get('/system/services')),
  manageService: (action: string, name: string) =>
    http.post('/system/services', { action, name }),
  // 系统设置
  listSettings: () => unwrap<{ settings: Record<string, any> }>(http.get('/system/settings')),
  updateSetting: (key: string, value: any) =>
    unwrap<{ key: string; value: any }>(http.put(`/system/settings/${key}`, { value })),
  // 扫描引擎列表
  listScanners: () => unwrap<{ scanners: string[] }>(http.get('/scanners')),
  // API Key 管理
  listApiKeys: () => unwrap<{ items: ApiKey[] }>(http.get('/system/api-keys')),
  createApiKey: (data: CreateApiKeyRequest) =>
    unwrap<ApiKey>(http.post('/system/api-keys', data)),
  updateApiKey: (id: string, data: Partial<CreateApiKeyRequest>) =>
    unwrap<ApiKey>(http.put(`/system/api-keys/${id}`, data)),
  deleteApiKey: (id: string) => http.delete(`/system/api-keys/${id}`),
  // 任务设置
  listTaskSettings: () => unwrap<{ settings: Record<string, any> }>(http.get('/system/task-settings')),
  updateTaskSetting: (key: string, value: any) =>
    unwrap<{ key: string; value: any }>(http.put(`/system/task-settings/${key}`, { value })),
}

// ==================== API Key ====================

export interface ApiKey {
  id: string
  name: string
  key: string
  permissions: string[]
  expires_at: string | null
  created_at: string
  last_used_at: string | null
  enabled: boolean
}

export interface CreateApiKeyRequest {
  name: string
  permissions?: string[]
  expires_at?: string | null
}

// ==================== 任务设置 ====================

export interface TaskSettings {
  max_concurrent: number
  timeout_seconds: number
  retry_count: number
  retry_interval_seconds: number
  [key: string]: any
}

// ==================== 管理员：用户与角色 ====================

export interface AdminUser {
  id: string
  username: string
  email: string | null
  role: string
  role_id: string | null
  status: string
  locked: boolean
  created_at: string
  last_login_at: string | null
}

export interface CreateUserRequest {
  username: string
  password: string
  email?: string
  role_id?: string
}

export interface UpdateUserRequest {
  email?: string
  role_id?: string
  password?: string
  status?: string
}

export interface Role {
  id: string
  name: string
  description: string | null
  permissions: string[]
  created_at: string
}

export const adminApi = {
  // 角色
  listRoles: () => unwrap<{ items: Role[] }>(http.get('/admin/roles')),
  getRolePermissions: (id: string) =>
    unwrap<{ permissions: string[] }>(http.get(`/admin/roles/${id}/permissions`)),
  // 用户
  listUsers: (params?: { page?: number; page_size?: number; keyword?: string }) =>
    unwrap<PagedResult<AdminUser>>(http.get('/admin/users', { params })),
  createUser: (data: CreateUserRequest) =>
    unwrap<AdminUser>(http.post('/admin/users', data)),
  updateUser: (id: string, data: UpdateUserRequest) =>
    unwrap<AdminUser>(http.put(`/admin/users/${id}`, data)),
  deleteUser: (id: string) => http.delete(`/admin/users/${id}`),
  lockUser: (id: string) => http.post(`/admin/users/${id}/lock`),
  unlockUser: (id: string) => http.post(`/admin/users/${id}/unlock`),
}

// ==================== 辅助工具 ====================

export interface PingRequest {
  host: string
  count?: number
  timeout?: number
}

export interface TelnetRequest {
  host: string
  port: number
  timeout?: number
}

export interface HttpRequest {
  url: string
  timeout?: number
}

export interface DnsRequest {
  domain: string
  record_type?: string
  dns_server?: string
}

export interface TracerouteRequest {
  host: string
  max_hops?: number
  timeout?: number
}

export interface WhoisRequest {
  query: string
}

export interface EncodeRequest {
  text: string
  type?: 'base64' | 'hex' | 'url'
}

export interface HashRequest {
  text: string
  algorithm?: 'md5' | 'sha1' | 'sha256' | 'sha512'
}

export interface SubnetRequest {
  cidr: string
}

export const toolApi = {
  ping: (data: PingRequest) => unwrap<any>(http.post('/diagnostic/ping', data)),
  telnet: (data: TelnetRequest) => unwrap<any>(http.post('/diagnostic/telnet', data)),
  http: (data: HttpRequest) => unwrap<any>(http.post('/diagnostic/http', data)),
  dig: (data: DnsRequest) => unwrap<any>(http.post('/diagnostic/dig', data)),
  nslookup: (data: DnsRequest) => unwrap<any>(http.post('/diagnostic/nslookup', data)),
  traceroute: (data: TracerouteRequest) => unwrap<any>(http.post('/diagnostic/traceroute', data)),
  whois: (data: WhoisRequest) => unwrap<any>(http.post('/diagnostic/whois', data)),
  encode: (data: EncodeRequest) => unwrap<{ result: string }>(http.post('/tools/encode', data)),
  decode: (data: EncodeRequest) => unwrap<{ result: string }>(http.post('/tools/decode', data)),
  hash: (data: HashRequest) => unwrap<{ result: string }>(http.post('/tools/hash', data)),
  subnet: (data: SubnetRequest) => unwrap<any>(http.post('/tools/subnet', data)),
}
