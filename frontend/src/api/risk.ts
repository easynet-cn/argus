import http from './http'

function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

// ==================== 漏洞实例 ====================

export interface VulnFinding {
  id: string
  task_id: string
  template_id: string | null
  cve_id: string | null
  target_host: string
  target_port: number | null
  target_service: string | null
  target_cpe: string | null
  title: string | null
  description: string | null
  vuln_type: string | null
  cvss2: number | null
  cvss3: number | null
  severity: string
  cvss: number | null
  source: string
  status: string
  risk_status: string
  risk_type: string
  assigned_to: string | null
  remediation_note: string | null
  evidence: string | null
  impact_range: string | null
  fix_advice: string | null
  request_method: string | null
  request_url: string | null
  request_params: string | null
  payload: string | null
  db_instance: string | null
  sql_statement: string | null
  first_found: string
  last_found: string
  created_at: string
  // 扩展字段（漏洞维度视图 / Web 漏洞定位）
  position: string | null
  cnnvd: string | null
  bugtraq_id: string | null
  cncve: string | null
}

export interface VulnListQuery {
  risk_type?: string
  risk_status?: string
  severity?: string
  host?: string
  cve_id?: string
  name?: string
  asset_group_id?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
}

export interface UpdateVulnStatusRequest {
  risk_status: string
  assigned_to?: string
  remediation_note?: string
  reason?: string
  operator?: string
}

export interface BatchUpdateVulnStatusRequest extends UpdateVulnStatusRequest {
  ids: string[]
}

// ==================== 暴露端口 ====================

export interface ExposurePort {
  id: string
  task_id: string | null
  host: string
  port: number
  protocol: string
  service: string | null
  banner: string | null
  is_risky: boolean | null
  version: string | null
  response_code: string | null
  title: string | null
  server_arch: string | null
  page_encoding: string | null
  tags: string[] | null
  first_found: string
  last_found: string
}

export interface PortListQuery {
  host?: string
  port?: number
  is_risky?: boolean
  asset_group_id?: string
  page?: number
  page_size?: number
}

// ==================== 弱口令 ====================

export interface WeakPassword {
  id: string
  task_id: string | null
  host: string
  protocol: string
  port: number
  username: string
  password: string
  risk_status: string
  first_found: string
  last_found: string
  asset_group_id: string | null
}

export interface WeakPasswordListQuery {
  host?: string
  protocol?: string
  username?: string
  port?: number
  risk_status?: string
  asset_group_id?: string
  page?: number
  page_size?: number
}

// ==================== CVE 知识库 ====================

export interface CveRecord {
  id: string
  source: string
  description: string
  cvss_v2: number | null
  cvss_v3: number | null
  cvss_vector: string | null
  severity: string | null
  published: string | null
  last_modified: string | null
  references: any
  cpe_configurations: any
}

export interface CveListQuery {
  keyword?: string
  limit?: number
  offset?: number
}

export interface CveListResult {
  data: CveRecord[]
  total: number
  limit: number
  offset: number
}

// ==================== 风险统计 ====================

export interface VulnStats {
  total: number
  by_severity: Array<{ key: string; count: number }>
  by_status: Array<{ key: string; count: number }>
  by_type: Array<{ key: string; count: number }>
  fixed_count: number
  fix_rate: number
}

export interface PortStats {
  total: number
  risky_count: number
  top_ports: Array<{ key: string; count: number }>
  risky_by_protocol: Array<{ key: string; count: number }>
}

export interface WeakPasswordStats {
  total: number
  top_hosts?: Array<{ key: string; count: number }>
  top_assets?: Array<{ key: string; count: number }>
  by_username?: Array<{ key: string; count: number }>
  by_protocol?: Array<{ key: string; count: number }>
}

export interface RiskSummary {
  vulnerabilities: {
    total: number
    new: number
    processing: number
    closed: number
  }
  exposure_ports: {
    total: number
    risky: number
  }
  weak_passwords: {
    total: number
  }
}

// ==================== 分页结果通用 ====================

export interface PagedResult<T> {
  items: T[]
  page: number
  page_size: number
}

// ==================== API ====================

export const vulnApi = {
  list: (params?: VulnListQuery) =>
    unwrap<PagedResult<VulnFinding>>(http.get('/risk/vulns', { params })),
  get: (id: string) => unwrap<VulnFinding>(http.get(`/risk/vulns/${id}`)),
  updateStatus: (id: string, data: UpdateVulnStatusRequest) =>
    unwrap<VulnFinding>(http.put(`/risk/vulns/${id}/status`, data)),
  batchUpdateStatus: (data: BatchUpdateVulnStatusRequest) =>
    unwrap<{ updated: number; failed: any[] }>(http.put('/risk/vulns/batch-status', data)),
  batchDelete: (ids: string[]) =>
    unwrap<{ deleted: number; failed: string[] }>(http.post('/risk/vulns/batch-delete', { ids })),
  /// 清空所有漏洞数据
  clearAll: () => unwrap<{ deleted: number }>(http.post('/risk/vulns/clear-all')),
  getDispositionHistory: (id: string) =>
    unwrap<any>(http.get(`/risk/vulns/${id}/disposition-history`)),
  export: () => http.get<Blob>('/risk/vulns/export', { responseType: 'blob' }),
  stats: () => unwrap<VulnStats>(http.get('/risk/vulns/stats')),
}

export const portApi = {
  list: (params?: PortListQuery) =>
    unwrap<PagedResult<ExposurePort>>(http.get('/risk/ports', { params })),
  export: () => http.get<Blob>('/risk/ports/export', { responseType: 'blob' }),
  /// 清空所有端口数据
  clearAll: () => unwrap<{ deleted: number }>(http.post('/risk/ports/clear-all')),
  stats: () => unwrap<PortStats>(http.get('/risk/ports/stats')),
}

export const weakPasswordApi = {
  list: (params?: WeakPasswordListQuery) =>
    unwrap<PagedResult<WeakPassword>>(http.get('/risk/weak-passwords', { params })),
  batchDelete: (ids: string[]) =>
    unwrap<{ deleted: number }>(http.post('/risk/weak-passwords/batch-delete', { ids })),
  /// 清空所有弱密码数据
  clearAll: () => unwrap<{ deleted: number }>(http.post('/risk/weak-passwords/clear-all')),
  batchUpdateStatus: (ids: string[], risk_status: string) =>
    unwrap<any>(http.put('/risk/weak-passwords/batch-status', { ids, risk_status })),
  export: () => http.get<Blob>('/risk/weak-passwords/export', { responseType: 'blob' }),
  stats: () => unwrap<WeakPasswordStats>(http.get('/risk/weak-passwords/stats')),
}

export const riskApi = {
  summary: () => unwrap<RiskSummary>(http.get('/risk/summary')),
}

// ==================== 配置变更 ====================

export interface ConfigChange {
  id: string
  name: string
  config_item: string
  host: string
  ip: string | null
  risk_level: string
  detection_result: string
  last_detection_result: string
  first_found: string
  last_found: string
  created_at: string
}

export interface ConfigChangeListQuery {
  host?: string
  name?: string
  risk_level?: string
  page?: number
  page_size?: number
}

export const configChangeApi = {
  list: (params?: ConfigChangeListQuery) =>
    unwrap<PagedResult<ConfigChange>>(http.get('/config-changes', { params })),
}

// ==================== 告警记录 ====================

export interface AlertRecord {
  id: string
  created_at: string
  type: string
  vuln_name: string
  host: string
  domain: string | null
  severity: string | null
  message: string | null
}

export interface AlertListQuery {
  type?: string
  host?: string
  page?: number
  page_size?: number
}

export const alertApi = {
  list: (params?: AlertListQuery) =>
    unwrap<PagedResult<AlertRecord>>(http.get('/alerts/records', { params })),
}

export const cveApi = {
  list: (params?: CveListQuery) => unwrap<CveListResult>(http.get('/vulndb/cves', { params })),
  get: (cveId: string) => unwrap<CveRecord>(http.get(`/vulndb/cves/${cveId}`)),
  search: (keyword: string, limit?: number, offset?: number) =>
    unwrap<{ data: CveRecord[]; keyword: string }>(
      http.get('/vulndb/cves/search', { params: { keyword, limit, offset } }),
    ),
  stats: () =>
    unwrap<{ total: number; by_year: any[]; by_severity: any[] }>(http.get('/vulndb/stats')),
  import: (startYear?: number, endYear?: number) =>
    unwrap<{ task_id: string; status: string; message: string }>(
      http.post('/vulndb/import', { start_year: startYear, end_year: endYear }),
    ),
  importStatus: () =>
    unwrap<{
      task_id: string
      current_year: number
      current_page: number
      total_processed: number
      status: string
      error: string | null
    }>(http.get('/vulndb/import/status')),
}
