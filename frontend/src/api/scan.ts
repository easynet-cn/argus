import http from './http'

// 响应拦截器已解包 response.data
function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

// ==================== 通用类型 ====================

/// 扫描任务接受响应
export interface TaskAccepted {
  task_id: string
  status: string
  message: string
}

/// 扫描任务状态
export interface ScanTaskStatus {
  task_id: string
  status: string
  progress: number
  task_type: string
  created_at: string
  started_at: string | null
  finished_at: string | null
  result_count: number
  open_port_count: number
  success_count: number
}

/// 扫描结果
export interface ScanResult {
  id: string
  task_id: string
  host: string
  port: number | null
  protocol: string | null
  state: string | null
  service: string | null
  product: string | null
  version: string | null
  success: boolean | null
  result_type: string
  detail: any
  created_at: string
}

/// 扫描结果列表
export interface ScanResultsResponse {
  task_id: string
  total: number
  open_ports: number
  success_count: number
  results: ScanResult[]
}

// ==================== 端口扫描 ====================

export interface PortScanRequest {
  hosts: string[]
  ports?: string
  tcp_scan_type?: 'connect' | 'syn' | 'ack' | 'null' | 'xmas' | 'fin' | 'window'
  scan_udp?: boolean
  fingerprint?: boolean
  concurrency?: number
  timeout_ms?: number
  rate_limit?: number
  asset_group_id?: string
}

// ==================== 漏洞扫描 ====================

export interface VulnScanRequest {
  hosts: string[]
  ports?: number[]
  mode?: 'active' | 'passive' | 'hybrid'
  concurrency?: number
  timeout_ms?: number
}

// ==================== 爆破扫描 ====================

export interface BruteForceRequest {
  host: string
  protocol: string
  port?: number
  usernames: string[]
  passwords: string[]
  concurrency?: number
  timeout_ms?: number
  stop_on_success?: boolean
  dict_level?: 'weak' | 'medium' | 'strong'
  hosts?: string[]
  link_port_scan?: boolean
}

// ==================== 基线核查 ====================

export interface BaselineScanRequest {
  host: string
  method?: 'ssh' | 'snmp' | 'offline'
  port?: number
  username?: string
  password?: string
  rule_set?: string
  timeout_ms?: number
  offline_data?: any
  rule_ids?: string[]
}

// ==================== 登录扫描 ====================

export interface LoginScanRequest {
  credential_ids?: string[]
  asset_type?: string
  asset_id?: string
  timeout_ms?: number
}

// ==================== Hash 爆破 ====================

export interface HashCrackRequest {
  hashes: string[]
  dict?: string[]
  use_builtin_dict?: boolean
  builtin_dict?: 'top10' | 'top50' | 'top100'
}

// ==================== 弱密码复检 ====================

export interface WeakPasswordRecheckRequest {
  host?: string
  protocol?: string
  since?: string
}

// ==================== 统一扫描 ====================

export interface UnifiedScanRequest {
  scan_type: 'system' | 'application' | 'database' | 'mobile' | 'vuln_verify'
  targets?: string[]
  ports?: number[]
  concurrency?: number
  timeout_ms?: number
  params?: any
  param_template_id?: string
  config?: any
  asset_group_id?: string
  credential_ids?: string[]
}

// ==================== 被动扫描 ====================

export interface PassiveScanRequest {
  name?: string
  mode: 'proxy' | 'kafka' | 'pcap' | 'agent'
  duration_sec?: number
  proxy_config?: any
  kafka_config?: any
  pcap_config?: any
  agent_config?: any
}

// ==================== 工控扫描 ====================

export interface IcsScanRequest {
  hosts: string[]
  protocols?: string[]
  timeout_ms?: number
}

// ==================== 容器扫描 ====================

export interface ContainerScanRequest {
  image: string
  harbor_url?: string
  harbor_username?: string
  harbor_password?: string
  scan_vulns?: boolean
  scan_sensitive?: boolean
}

// ==================== 模板与节点（任务管理辅助） ====================

/// 检测模板（YAML）
export interface ScanTemplateBrief {
  id: string
  name: string
  severity?: string
  cve?: string | null
  cvss?: number | null
  category?: string
  tags?: string[]
  service?: string | null
  port?: number | null
}

/// 端口模板
export interface PortTemplate {
  id: string
  name: string
  tcp_ports: string | null
  udp_ports: string | null
  is_builtin?: boolean
  tcp_port_count?: number
  udp_port_count?: number
  total_port_count?: number
  created_at?: string
  updated_at?: string
}

/// 参数模板
export interface ParamTemplate {
  id: string
  name: string
  scan_type?: string | null
  content?: any
  is_default?: boolean
  description?: string | null
  created_at?: string
  updated_at?: string
}

/// 扫描节点
export interface ScanNode {
  id: string
  name: string
  endpoint: string
  status: string
  capabilities?: any
  last_heartbeat?: string | null
  parent_id?: string | null
  organization?: string | null
}

export const scanApi = {
  // 端口扫描
  portScan: (data: PortScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/port', data)),
  // 漏洞扫描
  vulnScan: (data: VulnScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/vuln', data)),
  // 爆破扫描
  bruteForce: (data: BruteForceRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/bruteforce', data)),
  // 基线核查
  baselineScan: (data: BaselineScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/baseline', data)),
  // 登录扫描
  loginScan: (data: LoginScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/login', data)),
  // Hash 爆破
  hashCrack: (data: HashCrackRequest) =>
    unwrap<any>(http.post('/scan/hash-crack', data)),
  // 弱密码复检
  weakPasswordRecheck: (data: WeakPasswordRecheckRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/weak-password-recheck', data)),
  // 统一扫描
  unifiedScan: (data: UnifiedScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scans', data)),
  // 被动扫描
  passiveScan: (data: PassiveScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/passive', data)),
  // 工控扫描
  icsScan: (data: IcsScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/ics', data)),
  // 容器扫描
  containerScan: (data: ContainerScanRequest) =>
    unwrap<TaskAccepted>(http.post('/scan/container', data)),
  // 任务状态查询
  getStatus: (taskId: string) =>
    unwrap<ScanTaskStatus>(http.get(`/scan/status/${taskId}`)),
  // 取消任务
  cancel: (taskId: string) =>
    http.post(`/scan/cancel/${taskId}`),
  // 查询扫描结果
  getResults: (taskId: string) =>
    unwrap<ScanResultsResponse>(http.get(`/scan/results/${taskId}`)),
  // 基线核查报告
  getBaselineReport: (taskId: string) =>
    unwrap<any>(http.get(`/scan/baseline/report/${taskId}`)),
  // 漏洞扫描报告
  getVulnReport: (taskId: string) =>
    unwrap<any>(http.get(`/scan/vuln/report/${taskId}`)),
  // 工控扫描报告
  getIcsReport: (taskId: string) =>
    unwrap<any>(http.get(`/scan/ics/report/${taskId}`)),
  // 容器扫描报告
  getContainerReport: (taskId: string) =>
    unwrap<any>(http.get(`/scan/container/report/${taskId}`)),
  // ===== 任务管理辅助：模板与节点 =====
  // 检测模板列表
  listTemplates: () =>
    unwrap<{ total: number; templates: ScanTemplateBrief[] }>(
      http.get('/templates'),
    ),
  // 端口模板列表
  listPortTemplates: (params?: { page?: number; page_size?: number; name?: string }) =>
    unwrap<{ items: PortTemplate[]; page: number; page_size: number }>(
      http.get('/templates/ports', { params }),
    ),
  // 参数模板列表
  listParamTemplates: (params?: { page?: number; page_size?: number; scan_type?: string }) =>
    unwrap<{ items: ParamTemplate[]; page: number; page_size: number }>(
      http.get('/templates/params', { params }),
    ),
  // 扫描节点列表
  listNodes: () =>
    unwrap<{ total: number; nodes: ScanNode[] }>(http.get('/nodes')),
}
