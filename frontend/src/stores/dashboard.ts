import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  dashboardApi,
  type RiskSummary,
  type VulnStats,
  type PortStats,
  type SystemMonitor,
  type TaskItem,
  type DashboardOverview,
} from '@/api/dashboard'

export const useDashboardStore = defineStore('dashboard', () => {
  const riskSummary = ref<RiskSummary | null>(null)
  const vulnStats = ref<VulnStats | null>(null)
  const portStats = ref<PortStats | null>(null)
  const systemMonitor = ref<SystemMonitor | null>(null)
  const recentTasks = ref<TaskItem[]>([])
  const overview = ref<DashboardOverview | null>(null)
  const loading = ref(false)
  /// 趋势天数（时间段筛选）
  const trendDays = ref(30)

  async function fetchAll() {
    loading.value = true
    try {
      const [risk, vuln, ports, monitor, tasks, ov] = await Promise.all([
        dashboardApi.riskSummary().catch(() => null),
        dashboardApi.vulnStats().catch(() => null),
        dashboardApi.portStats().catch(() => null),
        dashboardApi.systemMonitor().catch(() => null),
        dashboardApi.recentTasks({ page: 1, page_size: 10 }).catch(() => null),
        dashboardApi.overview({ days: trendDays.value }).catch(() => null),
      ])
      riskSummary.value = risk
      vulnStats.value = vuln
      portStats.value = ports
      systemMonitor.value = monitor
      recentTasks.value = tasks?.items || []
      overview.value = ov
    } finally {
      loading.value = false
    }
  }

  /// 仅刷新系统监控（高频轮询场景）
  async function refreshSystemMonitor() {
    systemMonitor.value = await dashboardApi.systemMonitor().catch(() => null)
  }

  /// 仅刷新聚合统计（时间段切换场景）
  async function refreshOverview() {
    overview.value = await dashboardApi
      .overview({ days: trendDays.value })
      .catch(() => null)
  }

  /// 切换趋势天数并重新加载
  async function setTrendDays(days: number) {
    trendDays.value = days
    await refreshOverview()
  }

  return {
    riskSummary,
    vulnStats,
    portStats,
    systemMonitor,
    recentTasks,
    overview,
    loading,
    trendDays,
    fetchAll,
    refreshSystemMonitor,
    refreshOverview,
    setTrendDays,
  }
})
