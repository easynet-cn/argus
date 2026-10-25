import http from './http'

// 响应拦截器已解包 response.data
function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

/// 风险总览（GET /risk/summary）
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

/// 漏洞统计（GET /risk/vulns/stats）
export interface VulnStats {
  total: number
  by_severity: Array<{ key: string; count: number }>
  by_status: Array<{ key: string; count: number }>
  by_type: Array<{ key: string; count: number }>
  fixed_count: number
  fix_rate: number
}

/// 端口统计（GET /risk/ports/stats）
export interface PortStats {
  total: number
  risky_count: number
  top_ports: Array<{ key: string; count: number }>
  risky_by_protocol: Array<{ key: string; count: number }>
}

/// 系统监控（GET /system/monitor）
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

/// 任务列表项
export interface TaskItem {
  id: string
  name: string
  task_type: string
  status: string
  created_at: string
  [key: string]: any
}

export interface TaskListResult {
  items: TaskItem[]
  page: number
  page_size: number
}

/// 按风险类型拆分（系统 / 应用 / 数据库）
export interface VulnTypeSection {
  total: number
  by_severity: Array<{ key: string; count: number }>
  top_assets: Array<{ key: string; count: number }>
}

/// 基线核查不符合项统计
export interface BaselineStats {
  noncompliant_total: number
  top_items: Array<{ key: string; count: number }>
  top_hosts: Array<{ key: string; count: number }>
}

/// 仪表盘聚合统计（GET /dashboard/overview）
export interface DashboardOverview {
  assets: {
    network: number
    application: number
    database: number
    total: number
  }
  vulns: {
    total: number
    by_severity: Array<{ key: string; count: number }>
    by_status: Array<{ key: string; count: number }>
    by_type: Array<{ key: string; count: number }>
    fixed_count: number
    fix_rate: number
  }
  /// 按风险类型拆分（system / application / database）
  vuln_types: Record<'system' | 'application' | 'database', VulnTypeSection>
  /// 基线核查不符合项统计
  baseline: BaselineStats
  ports: {
    total: number
    risky_count: number
    top_ports: Array<{ key: string; count: number }>
    risky_by_protocol: Array<{ key: string; count: number }>
  }
  weak_passwords: {
    total: number
    top_assets: Array<{ key: string; count: number }>
    by_username: Array<{ key: string; count: number }>
    by_protocol: Array<{ key: string; count: number }>
  }
  /// 漏洞趋势：[{key: 'YYYY-MM-DD', count: N}]
  vuln_trend: Array<{ key: string; count: number }>
  /// 操作系统分布
  os_distribution: Array<{ key: string; count: number }>
  /// 风险网络资产 TOP10（按漏洞数）
  top_risky_assets: Array<{ key: string; count: number }>
  /// 网络资产风险等级分布（严重/高危/中危/低危）
  risk_level_distribution: Array<{ key: string; count: number }>
  /// 最近 5 个任务
  recent_tasks: Array<TaskItem>
}

export const dashboardApi = {
  riskSummary: () => unwrap<RiskSummary>(http.get('/risk/summary')),
  vulnStats: () => unwrap<VulnStats>(http.get('/risk/vulns/stats')),
  portStats: () => unwrap<PortStats>(http.get('/risk/ports/stats')),
  systemMonitor: () => unwrap<SystemMonitor>(http.get('/system/monitor')),
  recentTasks: (params?: { page?: number; page_size?: number }) =>
    unwrap<TaskListResult>(http.get('/tasks', { params })),
  /// 仪表盘聚合统计（一次调用获取全部数据）
  overview: (params?: { days?: number }) =>
    unwrap<DashboardOverview>(http.get('/dashboard/overview', { params })),
}
