import http from './http'

// ==================== 通用工具 ====================

/// 分页列表响应
export interface PagedResult<T> {
  items: T[]
  page: number
  page_size: number
  total?: number
}

/// 分页查询参数
export interface PageQuery {
  page?: number
  page_size?: number
}

// 响应拦截器已解包 response.data
function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

// ==================== 扫描模板 ====================

export interface ScanTemplate {
  id: string
  name: string
  type: string
  description: string | null
  content: any
  created_at: string
  updated_at: string
}

export interface ScanTemplateCreate {
  name: string
  type: string
  description?: string
  content: any
}

export const scanTemplateApi = {
  // 扫描模板列表
  list: (params?: PageQuery & { type?: string; name?: string }) =>
    unwrap<PagedResult<ScanTemplate>>(http.get('/templates', { params })),
  // 创建扫描模板
  create: (data: ScanTemplateCreate) =>
    unwrap<ScanTemplate>(http.post('/templates', data)),
  // 模板详情
  detail: (id: string) =>
    unwrap<ScanTemplate>(http.get(`/templates/${id}`)),
  // 校验模板 JSON
  validate: (content: any) =>
    unwrap<{ valid: boolean; message: string }>(
      http.post('/templates/validate', { content }),
    ),
}

// ==================== 端口模板 ====================

export interface PortTemplate {
  id: string
  name: string
  port_range: string
  description: string | null
  is_builtin?: boolean
  created_at?: string
  updated_at?: string
}

export interface PortTemplateCreate {
  name: string
  port_range: string
  description?: string
}

export const portTemplateApi = {
  list: (params?: PageQuery & { name?: string }) =>
    unwrap<PagedResult<PortTemplate>>(http.get('/templates/ports', { params })),
  create: (data: PortTemplateCreate) =>
    unwrap<PortTemplate>(http.post('/templates/ports', data)),
  detail: (id: string) =>
    unwrap<PortTemplate>(http.get(`/templates/ports/${id}`)),
  update: (id: string, data: Partial<PortTemplateCreate>) =>
    unwrap<PortTemplate>(http.put(`/templates/ports/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/ports/${id}`),
  copy: (id: string) =>
    unwrap<PortTemplate>(http.post(`/templates/ports/${id}/copy`)),
}

// ==================== 字典管理 ====================

export interface Dictionary {
  id: string
  name: string
  type: string
  entry_count: number
  description: string | null
  created_at?: string
  updated_at?: string
}

export interface DictionaryCreate {
  name: string
  type: string
  description?: string
  entries?: string[]
}

export interface SocialEngineerRequest {
  keywords: string[]
  // 可选的附加信息
  name?: string
  birthday?: string
  phone?: string
  email?: string
  id_card?: string
}

export const dictionaryApi = {
  list: (params?: PageQuery & { name?: string; type?: string }) =>
    unwrap<PagedResult<Dictionary>>(
      http.get('/templates/dictionaries', { params }),
    ),
  create: (data: DictionaryCreate) =>
    unwrap<Dictionary>(http.post('/templates/dictionaries', data)),
  detail: (id: string) =>
    unwrap<Dictionary>(http.get(`/templates/dictionaries/${id}`)),
  update: (id: string, data: Partial<DictionaryCreate>) =>
    unwrap<Dictionary>(http.put(`/templates/dictionaries/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/dictionaries/${id}`),
  // 上传字典文件（返回上传后的字典）
  uploadUrl: '/api/v1/templates/dictionaries/upload',
  // 下载字典
  download: (id: string) =>
    http.get(`/templates/dictionaries/${id}/download`, {
      responseType: 'blob',
    }),
  // 生成社工字典
  socialEngineer: (data: SocialEngineerRequest) =>
    unwrap<Dictionary>(
      http.post('/templates/dictionaries/social-engineer', data),
    ),
}

// ==================== 组合字典 ====================

export interface ComboDictionary {
  id: string
  name: string
  username_dict_id: string
  password_dict_id: string
  username_dict_name?: string
  password_dict_name?: string
  description: string | null
  created_at?: string
  updated_at?: string
}

export interface ComboDictionaryCreate {
  name: string
  username_dict_id: string
  password_dict_id: string
  description?: string
}

export const comboDictionaryApi = {
  list: (params?: PageQuery & { name?: string }) =>
    unwrap<PagedResult<ComboDictionary>>(
      http.get('/templates/combo-dictionaries', { params }),
    ),
  create: (data: ComboDictionaryCreate) =>
    unwrap<ComboDictionary>(
      http.post('/templates/combo-dictionaries', data),
    ),
  detail: (id: string) =>
    unwrap<ComboDictionary>(http.get(`/templates/combo-dictionaries/${id}`)),
  update: (id: string, data: Partial<ComboDictionaryCreate>) =>
    unwrap<ComboDictionary>(
      http.put(`/templates/combo-dictionaries/${id}`, data),
    ),
  remove: (id: string) => http.delete(`/templates/combo-dictionaries/${id}`),
}

// ==================== 证书管理 ====================

export interface Certificate {
  id: string
  name: string
  type: string
  expires_at: string | null
  description: string | null
  created_at?: string
  updated_at?: string
}

export interface CertificateCreate {
  name: string
  type: string
  content?: string
  expires_at?: string
  description?: string
}

export const certificateApi = {
  list: (params?: PageQuery & { name?: string; type?: string }) =>
    unwrap<PagedResult<Certificate>>(
      http.get('/templates/certificates', { params }),
    ),
  create: (data: CertificateCreate) =>
    unwrap<Certificate>(http.post('/templates/certificates', data)),
  detail: (id: string) =>
    unwrap<Certificate>(http.get(`/templates/certificates/${id}`)),
  update: (id: string, data: Partial<CertificateCreate>) =>
    unwrap<Certificate>(http.put(`/templates/certificates/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/certificates/${id}`),
  // 下载证书
  download: (id: string) =>
    http.get(`/templates/certificates/${id}/download`, {
      responseType: 'blob',
    }),
}

// ==================== 参数模板 ====================

export interface ParamTemplate {
  id: string
  name: string
  scan_type: string | null
  content: any
  is_default: boolean
  description: string | null
  created_at?: string
  updated_at?: string
}

export interface ParamTemplateCreate {
  name: string
  scan_type?: string
  content?: any
  description?: string
}

/// 参数模板 schema 字段定义
export interface ParamSchemaField {
  key: string
  label: string
  type: 'string' | 'number' | 'boolean' | 'select' | 'textarea'
  required?: boolean
  default?: any
  options?: { label: string; value: any }[]
  placeholder?: string
  min?: number
  max?: number
}

export interface ParamSchema {
  scan_type: string
  fields: ParamSchemaField[]
}

export const paramTemplateApi = {
  list: (params?: PageQuery & { scan_type?: string; name?: string }) =>
    unwrap<PagedResult<ParamTemplate>>(
      http.get('/templates/params', { params }),
    ),
  create: (data: ParamTemplateCreate) =>
    unwrap<ParamTemplate>(http.post('/templates/params', data)),
  // 参数模板 schema
  schema: (scan_type?: string) =>
    unwrap<ParamSchema>(
      http.get('/templates/params/schema', { params: { scan_type } }),
    ),
  // 导入参数模板
  importTemplate: (data: any) =>
    unwrap<ParamTemplate>(http.post('/templates/params/import', data)),
  detail: (id: string) =>
    unwrap<ParamTemplate>(http.get(`/templates/params/${id}`)),
  update: (id: string, data: Partial<ParamTemplateCreate>) =>
    unwrap<ParamTemplate>(http.put(`/templates/params/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/params/${id}`),
  // 设为默认
  setDefault: (id: string) =>
    unwrap<ParamTemplate>(http.post(`/templates/params/${id}/default`)),
  // 导出
  export: (id: string) =>
    http.get(`/templates/params/${id}/export`, { responseType: 'blob' }),
  // 复制
  copy: (id: string) =>
    unwrap<ParamTemplate>(http.post(`/templates/params/${id}/copy`)),
}

// ==================== 配置模板（基线） ====================

export interface ConfigTemplate {
  id: string
  name: string
  rule_count: number
  description: string | null
  content?: any
  created_at?: string
  updated_at?: string
}

export interface ConfigTemplateCreate {
  name: string
  description?: string
  content?: any
  rule_ids?: string[]
}

export const configTemplateApi = {
  list: (params?: PageQuery & { name?: string }) =>
    unwrap<PagedResult<ConfigTemplate>>(
      http.get('/templates/configs', { params }),
    ),
  create: (data: ConfigTemplateCreate) =>
    unwrap<ConfigTemplate>(http.post('/templates/configs', data)),
  detail: (id: string) =>
    unwrap<ConfigTemplate>(http.get(`/templates/configs/${id}`)),
  update: (id: string, data: Partial<ConfigTemplateCreate>) =>
    unwrap<ConfigTemplate>(http.put(`/templates/configs/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/configs/${id}`),
}

// ==================== 服务风险等级 ====================

export interface ServiceRisk {
  id: string
  service: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  description: string | null
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface ServiceRiskCreate {
  service: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  description?: string
}

export const serviceRiskApi = {
  list: (params?: PageQuery & { service?: string }) =>
    unwrap<PagedResult<ServiceRisk>>(
      http.get('/templates/service-risks', { params }),
    ),
  create: (data: ServiceRiskCreate) =>
    unwrap<ServiceRisk>(http.post('/templates/service-risks', data)),
  detail: (id: string) =>
    unwrap<ServiceRisk>(http.get(`/templates/service-risks/${id}`)),
  update: (id: string, data: Partial<ServiceRiskCreate>) =>
    unwrap<ServiceRisk>(http.put(`/templates/service-risks/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/service-risks/${id}`),
}

// ==================== 端口违规配置 ====================

export interface PortViolation {
  id: string
  port: number
  protocol: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  description: string | null
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface PortViolationCreate {
  port: number
  protocol: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  description?: string
}

export const portViolationApi = {
  list: (params?: PageQuery & { port?: number; protocol?: string }) =>
    unwrap<PagedResult<PortViolation>>(
      http.get('/templates/port-violations', { params }),
    ),
  create: (data: PortViolationCreate) =>
    unwrap<PortViolation>(http.post('/templates/port-violations', data)),
  // 检查端口违规
  check: (data: { port: number; protocol: string }) =>
    unwrap<{ violation: boolean; risk_level: string }>(
      http.post('/templates/port-violations/check', data),
    ),
  detail: (id: string) =>
    unwrap<PortViolation>(http.get(`/templates/port-violations/${id}`)),
  update: (id: string, data: Partial<PortViolationCreate>) =>
    unwrap<PortViolation>(http.put(`/templates/port-violations/${id}`, data)),
  remove: (id: string) => http.delete(`/templates/port-violations/${id}`),
  // 切换启用状态
  toggle: (id: string) =>
    unwrap<PortViolation>(http.patch(`/templates/port-violations/${id}/toggle`)),
}

// ==================== 指纹规则 ====================

export interface FingerprintRule {
  id: string
  name: string
  service: string | null
  port: number | null
  pattern: string
  enabled: boolean
  description: string | null
  created_at?: string
  updated_at?: string
}

export interface FingerprintRuleCreate {
  name: string
  service?: string
  port?: number
  pattern: string
  description?: string
}

export const fingerprintRuleApi = {
  list: (params?: PageQuery & { name?: string; service?: string }) =>
    unwrap<PagedResult<FingerprintRule>>(
      http.get('/fingerprint-rules', { params }),
    ),
  create: (data: FingerprintRuleCreate) =>
    unwrap<FingerprintRule>(http.post('/fingerprint-rules', data)),
  detail: (id: string) =>
    unwrap<FingerprintRule>(http.get(`/fingerprint-rules/${id}`)),
  update: (id: string, data: Partial<FingerprintRuleCreate>) =>
    unwrap<FingerprintRule>(http.put(`/fingerprint-rules/${id}`, data)),
  remove: (id: string) => http.delete(`/fingerprint-rules/${id}`),
  toggle: (id: string) =>
    unwrap<FingerprintRule>(http.patch(`/fingerprint-rules/${id}/toggle`)),
}
