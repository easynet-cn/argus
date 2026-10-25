import http from './http'

// ==================== 通用类型 ====================

/// 资产状态
export type AssetStatus = 'active' | 'inactive' | 'unknown'

/// 资产类型
export type AssetKind = 'network' | 'application' | 'database'

/// 分页列表响应
export interface PagedResult<T> {
  items: T[]
  page: number
  page_size: number
}

/// 分页查询参数
export interface PageQuery {
  page?: number
  page_size?: number
}

/// 批量删除请求
export interface BatchDeleteRequest {
  ids: string[]
}

// 响应拦截器已解包 response.data，这里用类型断言获取实际数据
function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

// ==================== 网络资产 ====================

export interface NetworkAsset {
  id: string
  name: string
  ip: string
  mac: string | null
  os: string | null
  asset_type: AssetKind
  status: AssetStatus
  risk_score: number
  tags: any
  created_at: string
  updated_at: string
  // 阶段8 扩展字段
  device_no: string | null
  location: string | null
  weight: string | null
  asset_group_id: string | null
  network_zone: string | null
  business_system: string | null
  owner: string | null
  contact: string | null
  email: string | null
  is_industrial: boolean
  industrial_vendor: string | null
  industrial_model: string | null
  industrial_version: string | null
  protection_level: string | null
  confidentiality: string | null
  integrity: string | null
  availability: string | null
  importance: string | null
  // P0-1 补齐字段
  description: string | null
  trusted_device: boolean
  industrial_device_type: string | null
}

export interface CreateNetworkAssetRequest {
  name: string
  ip: string
  mac?: string
  os?: string
  asset_type?: AssetKind
  tags?: string[]
  device_no?: string
  location?: string
  weight?: string
  asset_group_id?: string
  network_zone?: string
  business_system?: string
  owner?: string
  contact?: string
  email?: string
  is_industrial?: boolean
  industrial_vendor?: string
  industrial_model?: string
  industrial_version?: string
  protection_level?: string
  confidentiality?: string
  integrity?: string
  availability?: string
  importance?: string
  description?: string
  trusted_device?: boolean
  industrial_device_type?: string
  // 扩展字段（资产表单补齐）
  credential_id?: string
  auto_identify?: boolean
  config_spec?: string
}

export type UpdateNetworkAssetRequest = Partial<CreateNetworkAssetRequest> & {
  status?: AssetStatus
  risk_score?: number
}

export const networkAssetApi = {
  list: (params?: PageQuery) =>
    unwrap<PagedResult<NetworkAsset>>(http.get('/assets/network', { params })),
  get: (id: string) => unwrap<NetworkAsset>(http.get(`/assets/network/${id}`)),
  create: (data: CreateNetworkAssetRequest) =>
    unwrap<NetworkAsset>(http.post('/assets/network', data)),
  update: (id: string, data: UpdateNetworkAssetRequest) =>
    unwrap<NetworkAsset>(http.put(`/assets/network/${id}`, data)),
  delete: (id: string) => http.delete(`/assets/network/${id}`),
  batchDelete: (ids: string[]) =>
    unwrap<{ deleted: number }>(http.post('/assets/network/batch-delete', { ids })),
  export: () =>
    http.get<Blob>('/assets/network/export', { responseType: 'blob' }),
  /// 下载 xlsx 导入模板
  template: () =>
    http.get<Blob>('/assets/network/template', { responseType: 'blob' }),
  /// 上传 xlsx 批量导入
  importFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return unwrap<{ success: number; failed: number; errors: string[] }>(
      http.post('/assets/network/import', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    )
  },
}

// ==================== 应用资产 ====================

export interface ApplicationAsset {
  id: string
  name: string
  url: string
  title: string | null
  server_arch: string | null
  status: AssetStatus
  risk_score: number
  created_at: string
  page_encoding: string | null
  os: string | null
  cert_type: string | null
  cert_id: string | null
  device_no: string | null
  location: string | null
  weight: string | null
  asset_group_id: string | null
  business_system: string | null
  owner: string | null
  contact: string | null
  email: string | null
  updated_at: string
  description: string | null
  ip: string | null
  tags: any
  trusted_device: boolean
  asset_type: string | null
  protection_level: string | null
  confidentiality: string | null
  integrity: string | null
  availability: string | null
  importance: string | null
  auto_fetch: boolean
}

export interface CreateApplicationAssetRequest {
  name: string
  url: string
  title?: string
  server_arch?: string
  page_encoding?: string
  os?: string
  cert_type?: string
  cert_id?: string
  device_no?: string
  location?: string
  weight?: string
  asset_group_id?: string
  business_system?: string
  owner?: string
  contact?: string
  email?: string
  description?: string
  ip?: string
  tags?: string[]
  trusted_device?: boolean
  asset_type?: string
  protection_level?: string
  confidentiality?: string
  integrity?: string
  availability?: string
  importance?: string
  auto_fetch?: boolean
  // 扩展字段（资产表单补齐）
  credential_id?: string
  auto_identify?: boolean
  config_spec?: string
  tech_stack?: string
}

export type UpdateApplicationAssetRequest = Partial<CreateApplicationAssetRequest> & {
  status?: AssetStatus
  risk_score?: number
}

export const applicationAssetApi = {
  list: (params?: PageQuery) =>
    unwrap<PagedResult<ApplicationAsset>>(http.get('/assets/application', { params })),
  get: (id: string) => unwrap<ApplicationAsset>(http.get(`/assets/application/${id}`)),
  create: (data: CreateApplicationAssetRequest) =>
    unwrap<ApplicationAsset>(http.post('/assets/application', data)),
  update: (id: string, data: UpdateApplicationAssetRequest) =>
    unwrap<ApplicationAsset>(http.put(`/assets/application/${id}`, data)),
  delete: (id: string) => http.delete(`/assets/application/${id}`),
  batchDelete: (ids: string[]) =>
    unwrap<{ deleted: number }>(http.post('/assets/application/batch-delete', { ids })),
  export: () =>
    http.get<Blob>('/assets/application/export', { responseType: 'blob' }),
  /// 下载 xlsx 导入模板
  template: () =>
    http.get<Blob>('/assets/application/template', { responseType: 'blob' }),
  /// 上传 xlsx 批量导入
  importFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return unwrap<{ success: number; failed: number; errors: string[] }>(
      http.post('/assets/application/import', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    )
  },
}

// ==================== 数据库资产 ====================

export interface DatabaseAsset {
  id: string
  name: string
  ip: string
  db_type: string
  port: number
  status: AssetStatus
  risk_score: number
  created_at: string
  username: string | null
  password: string | null
  enable_ssl: boolean
  db_name: string | null
  login_verified: boolean
  execute_login_scan: boolean
  device_no: string | null
  location: string | null
  weight: string | null
  asset_group_id: string | null
  business_system: string | null
  owner: string | null
  contact: string | null
  email: string | null
  updated_at: string
  description: string | null
  tags: any
  trusted_device: boolean
  asset_type: string | null
  protection_level: string | null
  confidentiality: string | null
  integrity: string | null
  availability: string | null
  importance: string | null
}

export interface CreateDatabaseAssetRequest {
  name: string
  ip: string
  db_type: string
  port: number
  username?: string
  password?: string
  enable_ssl?: boolean
  db_name?: string
  login_verified?: boolean
  execute_login_scan?: boolean
  device_no?: string
  location?: string
  weight?: string
  asset_group_id?: string
  business_system?: string
  owner?: string
  contact?: string
  email?: string
  description?: string
  tags?: string[]
  trusted_device?: boolean
  asset_type?: string
  protection_level?: string
  confidentiality?: string
  integrity?: string
  availability?: string
  importance?: string
  // 扩展字段（资产表单补齐）
  credential_id?: string
  auto_identify?: boolean
  config_spec?: string
  db_version?: string
  connection_string?: string
}

export type UpdateDatabaseAssetRequest = Partial<CreateDatabaseAssetRequest> & {
  status?: AssetStatus
  risk_score?: number
}

export const databaseAssetApi = {
  list: (params?: PageQuery) =>
    unwrap<PagedResult<DatabaseAsset>>(http.get('/assets/database', { params })),
  get: (id: string) => unwrap<DatabaseAsset>(http.get(`/assets/database/${id}`)),
  create: (data: CreateDatabaseAssetRequest) =>
    unwrap<DatabaseAsset>(http.post('/assets/database', data)),
  update: (id: string, data: UpdateDatabaseAssetRequest) =>
    unwrap<DatabaseAsset>(http.put(`/assets/database/${id}`, data)),
  delete: (id: string) => http.delete(`/assets/database/${id}`),
  batchDelete: (ids: string[]) =>
    unwrap<{ deleted: number }>(http.post('/assets/database/batch-delete', { ids })),
  export: () =>
    http.get<Blob>('/assets/database/export', { responseType: 'blob' }),
  /// 下载 xlsx 导入模板
  template: () =>
    http.get<Blob>('/assets/database/template', { responseType: 'blob' }),
  /// 上传 xlsx 批量导入
  importFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return unwrap<{ success: number; failed: number; errors: string[] }>(
      http.post('/assets/database/import', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    )
  },
}

// ==================== 凭证 ====================

/// 登录凭证（用于资产表单的 credential_id 选择）
export interface Credential {
  id: string
  name: string
  username: string
  protocol: string | null
  port: number | null
  created_at: string
  updated_at: string
}

export const credentialApi = {
  list: (params?: PageQuery) =>
    unwrap<PagedResult<Credential>>(http.get('/credentials', { params })),
}

// ==================== 资产组 ====================

export interface AssetGroup {
  id: string
  name: string
  parent_id: string | null
  ip_range: string | null
  owner: string | null
  contact: string | null
  email: string | null
  location: string | null
  created_at: string
  updated_at: string
}

export interface AssetGroupNode extends AssetGroup {
  children: AssetGroupNode[]
}

export interface CreateAssetGroupRequest {
  name: string
  parent_id?: string
  ip_range?: string
  owner?: string
  contact?: string
  email?: string
  location?: string
}

export type UpdateAssetGroupRequest = Partial<CreateAssetGroupRequest>

export const assetGroupApi = {
  list: (params?: PageQuery) =>
    unwrap<PagedResult<AssetGroup>>(http.get('/asset-groups', { params })),
  tree: () => unwrap<{ items: AssetGroupNode[] }>(http.get('/asset-groups/tree')),
  get: (id: string) => unwrap<AssetGroup>(http.get(`/asset-groups/${id}`)),
  create: (data: CreateAssetGroupRequest) =>
    unwrap<AssetGroup>(http.post('/asset-groups', data)),
  update: (id: string, data: UpdateAssetGroupRequest) =>
    unwrap<AssetGroup>(http.put(`/asset-groups/${id}`, data)),
  delete: (id: string) => http.delete(`/asset-groups/${id}`),
  listAssets: (id: string, params?: PageQuery) =>
    unwrap<PagedResult<NetworkAsset>>(http.get(`/asset-groups/${id}/assets`, { params })),
  scan: (id: string) => http.post(`/asset-groups/${id}/scan`),
}
