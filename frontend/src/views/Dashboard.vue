<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick, computed } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts/core'
import { BarChart, PieChart, LineChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import {
  AlertTriangle,
  ShieldAlert,
  KeyRound,
  Cpu,
  MemoryStick,
  HardDrive,
  Network,
  AppWindow,
  Database,
  Activity,
  TrendingUp,
  Server,
  ScanLine,
  FileCheck,
  Smartphone,
  Image,
  Globe,
  Wrench,
  Router as RouterIcon,
  Settings,
} from '@lucide/vue'
import { useDashboardStore } from '@/stores/dashboard'

echarts.use([
  BarChart,
  PieChart,
  LineChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  CanvasRenderer,
])

const store = useDashboardStore()
const router = useRouter()

// 图表 DOM 引用
const vulnChartRef = ref<HTMLElement>()
const portChartRef = ref<HTMLElement>()
const typeChartRef = ref<HTMLElement>()
const trendChartRef = ref<HTMLElement>()
const osChartRef = ref<HTMLElement>()
const riskyAssetChartRef = ref<HTMLElement>()
const riskLevelChartRef = ref<HTMLElement>()
const wpProtocolChartRef = ref<HTMLElement>()
// 新增图表 DOM 引用（应用 / 数据库 / 基线 / 弱密码）
const appTopChartRef = ref<HTMLElement>()
const appSeverityChartRef = ref<HTMLElement>()
const dbSeverityChartRef = ref<HTMLElement>()
const dbTopChartRef = ref<HTMLElement>()
const baselineItemChartRef = ref<HTMLElement>()
const baselineHostChartRef = ref<HTMLElement>()
const wpAssetChartRef = ref<HTMLElement>()
const wpUserChartRef = ref<HTMLElement>()

let vulnChart: echarts.ECharts | null = null
let portChart: echarts.ECharts | null = null
let typeChart: echarts.ECharts | null = null
let trendChart: echarts.ECharts | null = null
let osChart: echarts.ECharts | null = null
let riskyAssetChart: echarts.ECharts | null = null
let riskLevelChart: echarts.ECharts | null = null
let wpProtocolChart: echarts.ECharts | null = null
let appTopChart: echarts.ECharts | null = null
let appSeverityChart: echarts.ECharts | null = null
let dbSeverityChart: echarts.ECharts | null = null
let dbTopChart: echarts.ECharts | null = null
let baselineItemChart: echarts.ECharts | null = null
let baselineHostChart: echarts.ECharts | null = null
let wpAssetChart: echarts.ECharts | null = null
let wpUserChart: echarts.ECharts | null = null

// 时间段选项
const trendDaysOptions = [
  { label: '近 7 天', value: 7 },
  { label: '近 30 天', value: 30 },
  { label: '近 90 天', value: 90 },
]

// 快速入口（路由与 router/index.ts 保持一致）
const quickEntries = [
  { label: '资产发现', icon: Network, route: '/assets', color: 'text-cyan-400' },
  { label: '系统扫描', icon: ScanLine, route: '/scan/system', color: 'text-blue-400' },
  { label: '应用扫描', icon: AppWindow, route: '/scan/web', color: 'text-violet-400' },
  { label: '基线核查', icon: FileCheck, route: '/baseline', color: 'text-emerald-400' },
  { label: '口令猜解', icon: KeyRound, route: '/bruteforce', color: 'text-amber-400' },
  { label: '数据库扫描', icon: Database, route: '/scan/database', color: 'text-pink-400' },
  { label: '移动扫描', icon: Smartphone, route: '/mobile', color: 'text-indigo-400' },
  { label: '镜像扫描', icon: Image, route: '/container', color: 'text-orange-400' },
  { label: '被动扫描', icon: Globe, route: '/scan/web', color: 'text-teal-400' },
  { label: '网络管理', icon: RouterIcon, route: '/assets', color: 'text-sky-400' },
  { label: '诊断工具', icon: Wrench, route: '/tools', color: 'text-slate-400' },
]

// ==================== 仪表盘分组显示设置 ====================
const SECTION_STORAGE_KEY = 'argus_dashboard_sections'

// 分组定义（顺序与页面布局一致）
const sectionDefs = [
  { key: 'quick', label: '快速入口' },
  { key: 'overview', label: '总览与资产风险图组' },
  { key: 'system', label: '系统扫描图组' },
  { key: 'application', label: '应用扫描图组' },
  { key: 'database', label: '数据库扫描图组' },
  { key: 'baseline', label: '基线配置图组' },
  { key: 'weak', label: '弱密码图组' },
  { key: 'tasks', label: '实时任务' },
  { key: 'monitor', label: '资源监控' },
]

const defaultSections: Record<string, boolean> = {
  quick: true,
  overview: true,
  system: true,
  application: true,
  database: true,
  baseline: true,
  weak: true,
  tasks: true,
  monitor: true,
}

// 从 localStorage 读取分组显示状态
function loadSections(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(SECTION_STORAGE_KEY)
    if (raw) return { ...defaultSections, ...JSON.parse(raw) }
  } catch {
    // 忽略解析异常
  }
  return { ...defaultSections }
}

const sectionVisible = ref<Record<string, boolean>>(loadSections())

// 格式化字节
function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let n = bytes
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(1)} ${units[i]}`
}

// 格式化运行时间
function formatUptime(seconds: number): string {
  if (!seconds) return '-'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}天 ${hours}小时`
  if (hours > 0) return `${hours}小时 ${mins}分`
  return `${mins}分钟`
}

// 严重程度中文映射
const severityLabel = (key: string) => {
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return map[key?.toLowerCase()] || key
}

const severityColor = (key: string) => {
  const map: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#06b6d4',
    info: '#64748b',
  }
  return map[key?.toLowerCase()] || '#64748b'
}

// 任务状态中文映射
const taskStatusLabel = (status: string) => {
  const map: Record<string, string> = {
    pending: '等待中',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    failed: '失败',
    stopped: '已停止',
  }
  return map[status?.toLowerCase()] || status
}

const taskStatusType = (status: string) => {
  const map: Record<string, string> = {
    pending: 'info',
    running: 'warning',
    paused: 'info',
    completed: 'success',
    failed: 'danger',
    stopped: 'info',
  }
  return map[status?.toLowerCase()] || 'info'
}

// 任务类型中文映射
const taskTypeLabel = (type: string) => {
  const map: Record<string, string> = {
    portscan: '端口扫描',
    hostdiscovery: '主机发现',
    bruteforce: '弱口令',
    baselinecheck: '基线核查',
    systemscan: '系统扫描',
    appscan: '应用扫描',
    dbscan: '数据库扫描',
    imagescan: '镜像扫描',
    mobilescan: '移动扫描',
    vulnverify: '漏洞验证',
    fingerprint: '指纹扫描',
    vulndetect: '漏洞检测',
    icscan: '工控扫描',
  }
  return map[type?.toLowerCase()] || type
}

// 渲染漏洞严重程度饼图
function renderVulnChart() {
  if (!vulnChartRef.value || !store.overview) return
  if (!vulnChart) vulnChart = echarts.init(vulnChartRef.value)
  const data = store.overview.vulns.by_severity.map((item) => ({
    name: severityLabel(item.key),
    value: item.count,
    itemStyle: { color: severityColor(item.key) },
  }))
  vulnChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data,
        label: { color: '#cbd5e1' },
      },
    ],
  })
}

// 渲染暴露端口 TOP10
function renderPortChart() {
  if (!portChartRef.value || !store.overview) return
  if (!portChart) portChart = echarts.init(portChartRef.value)
  const data = store.overview.ports.top_ports.map((item) => ({
    name: `端口 ${item.key}`,
    value: item.count,
  }))
  portChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map((d) => d.name),
      axisLabel: { color: '#94a3b8', rotate: 30 },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
    },
    series: [
      {
        type: 'bar',
        data: data.map((d) => d.value),
        itemStyle: { color: '#06b6d4', borderRadius: [4, 4, 0, 0] },
      },
    ],
  })
}

// 渲染漏洞类型分布
function renderTypeChart() {
  if (!typeChartRef.value || !store.overview) return
  if (!typeChart) typeChart = echarts.init(typeChartRef.value)
  const data = store.overview.vulns.by_type.slice(0, 8).map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  typeChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
    },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.name),
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    series: [
      {
        type: 'bar',
        data: data.map((d) => d.value),
        itemStyle: { color: '#8b5cf6', borderRadius: [0, 4, 4, 0] },
      },
    ],
  })
}

// 渲染漏洞趋势折线图
function renderTrendChart() {
  if (!trendChartRef.value || !store.overview) return
  if (!trendChart) trendChart = echarts.init(trendChartRef.value)
  const data = store.overview.vuln_trend
  trendChart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map((d) => d.key),
      axisLabel: { color: '#94a3b8', rotate: 30 },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
    },
    series: [
      {
        name: '漏洞数',
        type: 'line',
        data: data.map((d) => d.count),
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: { color: '#06b6d4', width: 2 },
        itemStyle: { color: '#06b6d4' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(6, 182, 212, 0.3)' },
            { offset: 1, color: 'rgba(6, 182, 212, 0.01)' },
          ]),
        },
      },
    ],
  })
}

// 渲染操作系统分布饼图
function renderOsChart() {
  if (!osChartRef.value || !store.overview) return
  if (!osChart) osChart = echarts.init(osChartRef.value)
  const data = store.overview.os_distribution.map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  osChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { type: 'scroll', bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        data,
        label: { color: '#cbd5e1', formatter: '{b}' },
      },
    ],
  })
}

// 渲染风险网络资产 TOP10
function renderRiskyAssetChart() {
  if (!riskyAssetChartRef.value || !store.overview) return
  if (!riskyAssetChart) riskyAssetChart = echarts.init(riskyAssetChartRef.value)
  const data = store.overview.top_risky_assets.map((item) => ({
    name: item.key,
    value: item.count,
  }))
  riskyAssetChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
    },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.name),
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    series: [
      {
        type: 'bar',
        data: data.map((d) => d.value),
        itemStyle: { color: '#dc2626', borderRadius: [0, 4, 4, 0] },
      },
    ],
  })
}

// 渲染网络资产风险等级分布
function renderRiskLevelChart() {
  if (!riskLevelChartRef.value || !store.overview) return
  if (!riskLevelChart) riskLevelChart = echarts.init(riskLevelChartRef.value)
  const colors: Record<string, string> = {
    严重: '#dc2626',
    高危: '#ea580c',
    中危: '#f59e0b',
    低危: '#06b6d4',
  }
  const data = store.overview.risk_level_distribution.map((item) => ({
    name: item.key,
    value: item.count,
    itemStyle: { color: colors[item.key] || '#64748b' },
  }))
  riskLevelChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data,
        label: { color: '#cbd5e1' },
      },
    ],
  })
}

// 渲染弱密码协议分布
function renderWpProtocolChart() {
  if (!wpProtocolChartRef.value || !store.overview) return
  if (!wpProtocolChart) wpProtocolChart = echarts.init(wpProtocolChartRef.value)
  const data = store.overview.weak_passwords.by_protocol.map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  wpProtocolChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { type: 'scroll', bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        data,
        label: { color: '#cbd5e1' },
      },
    ],
  })
}

// 横向柱状图通用 option（沿用现有暗色主题样式）
function horizontalBarOption(data: Array<{ name: string; value: number }>, color: string) {
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
    },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.name),
      axisLabel: { color: '#94a3b8' },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    series: [
      {
        type: 'bar',
        data: data.map((d) => d.value),
        itemStyle: { color, borderRadius: [0, 4, 4, 0] },
      },
    ],
  }
}

// 饼图通用 option（严重程度配色）
function severityPieOption(data: Array<{ key: string; count: number }>) {
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data: data.map((item) => ({
          name: severityLabel(item.key),
          value: item.count,
          itemStyle: { color: severityColor(item.key) },
        })),
        label: { color: '#cbd5e1' },
      },
    ],
  }
}

// 渲染应用漏洞 TOP10
function renderAppTopChart() {
  if (!appTopChartRef.value || !store.overview) return
  if (!appTopChart) appTopChart = echarts.init(appTopChartRef.value)
  const list = store.overview?.vuln_types?.application?.top_assets ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  appTopChart.setOption(horizontalBarOption(data, '#8b5cf6'))
}

// 渲染应用漏洞等级分布
function renderAppSeverityChart() {
  if (!appSeverityChartRef.value || !store.overview) return
  if (!appSeverityChart) appSeverityChart = echarts.init(appSeverityChartRef.value)
  const list = store.overview?.vuln_types?.application?.by_severity ?? []
  appSeverityChart.setOption(severityPieOption(list))
}

// 渲染数据库漏洞等级分布
function renderDbSeverityChart() {
  if (!dbSeverityChartRef.value || !store.overview) return
  if (!dbSeverityChart) dbSeverityChart = echarts.init(dbSeverityChartRef.value)
  const list = store.overview?.vuln_types?.database?.by_severity ?? []
  dbSeverityChart.setOption(severityPieOption(list))
}

// 渲染风险数据库资产 TOP10
function renderDbTopChart() {
  if (!dbTopChartRef.value || !store.overview) return
  if (!dbTopChart) dbTopChart = echarts.init(dbTopChartRef.value)
  const list = store.overview?.vuln_types?.database?.top_assets ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  dbTopChart.setOption(horizontalBarOption(data, '#ec4899'))
}

// 渲染基线不符合项 TOP10
function renderBaselineItemChart() {
  if (!baselineItemChartRef.value || !store.overview) return
  if (!baselineItemChart) baselineItemChart = echarts.init(baselineItemChartRef.value)
  const list = store.overview?.baseline?.top_items ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  baselineItemChart.setOption(horizontalBarOption(data, '#f59e0b'))
}

// 渲染基线不符合 IP TOP10
function renderBaselineHostChart() {
  if (!baselineHostChartRef.value || !store.overview) return
  if (!baselineHostChart) baselineHostChart = echarts.init(baselineHostChartRef.value)
  const list = store.overview?.baseline?.top_hosts ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  baselineHostChart.setOption(horizontalBarOption(data, '#10b981'))
}

// 渲染弱密码主机 TOP10
function renderWpAssetChart() {
  if (!wpAssetChartRef.value || !store.overview) return
  if (!wpAssetChart) wpAssetChart = echarts.init(wpAssetChartRef.value)
  const list = store.overview?.weak_passwords?.top_assets ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  wpAssetChart.setOption(horizontalBarOption(data, '#06b6d4'))
}

// 渲染弱密码用户名 TOP10
function renderWpUserChart() {
  if (!wpUserChartRef.value || !store.overview) return
  if (!wpUserChart) wpUserChart = echarts.init(wpUserChartRef.value)
  const list = store.overview?.weak_passwords?.by_username ?? []
  const data = list.map((item) => ({ name: item.key || '未知', value: item.count }))
  wpUserChart.setOption(horizontalBarOption(data, '#8b5cf6'))
}

// 渲染全部图表（隐藏分组因 DOM 不存在会自动跳过）
function renderAllCharts() {
  renderVulnChart()
  renderPortChart()
  renderTypeChart()
  renderTrendChart()
  renderOsChart()
  renderRiskyAssetChart()
  renderRiskLevelChart()
  renderWpProtocolChart()
  renderAppTopChart()
  renderAppSeverityChart()
  renderDbSeverityChart()
  renderDbTopChart()
  renderBaselineItemChart()
  renderBaselineHostChart()
  renderWpAssetChart()
  renderWpUserChart()
}

// 销毁全部图表实例（分组隐藏/切换后需重建以保证尺寸正确）
function disposeCharts() {
  vulnChart?.dispose()
  vulnChart = null
  portChart?.dispose()
  portChart = null
  typeChart?.dispose()
  typeChart = null
  trendChart?.dispose()
  trendChart = null
  osChart?.dispose()
  osChart = null
  riskyAssetChart?.dispose()
  riskyAssetChart = null
  riskLevelChart?.dispose()
  riskLevelChart = null
  wpProtocolChart?.dispose()
  wpProtocolChart = null
  appTopChart?.dispose()
  appTopChart = null
  appSeverityChart?.dispose()
  appSeverityChart = null
  dbSeverityChart?.dispose()
  dbSeverityChart = null
  dbTopChart?.dispose()
  dbTopChart = null
  baselineItemChart?.dispose()
  baselineItemChart = null
  baselineHostChart?.dispose()
  baselineHostChart = null
  wpAssetChart?.dispose()
  wpAssetChart = null
  wpUserChart?.dispose()
  wpUserChart = null
}

// 监听 overview 变化重新渲染所有图表
watch(
  () => store.overview,
  () => {
    nextTick(() => {
      renderAllCharts()
    })
  },
)

// 监听分组显示设置：持久化并重建图表
watch(
  sectionVisible,
  (val) => {
    try {
      localStorage.setItem(SECTION_STORAGE_KEY, JSON.stringify(val))
    } catch {
      // 忽略写入异常
    }
    nextTick(() => {
      disposeCharts()
      renderAllCharts()
    })
  },
  { deep: true },
)

// 窗口大小变化时调整图表
function handleResize() {
  vulnChart?.resize()
  portChart?.resize()
  typeChart?.resize()
  trendChart?.resize()
  osChart?.resize()
  riskyAssetChart?.resize()
  riskLevelChart?.resize()
  wpProtocolChart?.resize()
  appTopChart?.resize()
  appSeverityChart?.resize()
  dbSeverityChart?.resize()
  dbTopChart?.resize()
  baselineItemChart?.resize()
  baselineHostChart?.resize()
  wpAssetChart?.resize()
  wpUserChart?.resize()
}

// 跳转快速入口
function goQuick(route: string) {
  router.push(route)
}

// 跳转任务详情（对应 router 中 /scan/system 路由）
function goTask(task: any) {
  router.push(`/scan/system?task_id=${task.id}`)
}

// 趋势天数切换
async function handleDaysChange(days: number) {
  await store.setTrendDays(days)
}

onMounted(async () => {
  await store.fetchAll()
  await nextTick()
  renderAllCharts()
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  disposeCharts()
})

// 计算属性：今日新增漏洞数（简化：取最近 1 天数据）
const todayNewVulns = computed(() => {
  if (!store.overview?.vuln_trend?.length) return 0
  return store.overview.vuln_trend[store.overview.vuln_trend.length - 1]?.count || 0
})
</script>

<template>
  <div v-loading="store.loading" class="space-y-6">
    <!-- 顶部工具栏：时间段筛选 + 刷新 -->
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <h2 class="text-lg font-semibold text-slate-200">风险态势总览</h2>
        <el-select
          :model-value="store.trendDays"
          size="small"
          class="w-32"
          @change="handleDaysChange"
        >
          <el-option
            v-for="opt in trendDaysOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
      </div>
      <div class="flex items-center gap-2">
        <el-popover placement="bottom-end" :width="220" trigger="click">
          <template #reference>
            <el-button :icon="Settings" size="small">设置</el-button>
          </template>
          <div class="space-y-1">
            <p class="mb-1 text-xs text-slate-400">仪表盘图表分组显示</p>
            <el-checkbox
              v-for="sec in sectionDefs"
              :key="sec.key"
              v-model="sectionVisible[sec.key]"
              class="block"
            >
              {{ sec.label }}
            </el-checkbox>
          </div>
        </el-popover>
        <el-button :icon="Activity" size="small" @click="store.fetchAll()">刷新</el-button>
      </div>
    </div>

    <!-- 快速入口（11 个一键创建按钮） -->
    <div v-if="sectionVisible.quick" class="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <h3 class="mb-3 text-sm font-medium text-slate-300">快速入口</h3>
      <div class="grid grid-cols-3 gap-2 sm:grid-cols-6 lg:grid-cols-11">
        <button
          v-for="entry in quickEntries"
          :key="entry.label"
          class="flex flex-col items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/50 px-2 py-3 transition hover:border-cyan-500 hover:bg-slate-800"
          @click="goQuick(entry.route)"
        >
          <component :is="entry.icon" :class="['h-5 w-5', entry.color]" />
          <span class="text-xs text-slate-300">{{ entry.label }}</span>
        </button>
      </div>
    </div>

    <!-- 统计卡片：资产数 + 漏洞数 + 端口 + 弱口令 -->
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <!-- 资产总数 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm text-slate-400">资产总数</p>
            <p class="mt-2 text-3xl font-bold text-white">
              {{ store.overview?.assets.total ?? 0 }}
            </p>
            <div class="mt-1 flex gap-3 text-xs text-slate-500">
              <span>网络 {{ store.overview?.assets.network ?? 0 }}</span>
              <span>应用 {{ store.overview?.assets.application ?? 0 }}</span>
              <span>数据库 {{ store.overview?.assets.database ?? 0 }}</span>
            </div>
          </div>
          <Server class="h-10 w-10 text-cyan-400 opacity-80" />
        </div>
      </div>

      <!-- 漏洞总数 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm text-slate-400">漏洞总数</p>
            <p class="mt-2 text-3xl font-bold text-white">
              {{ store.overview?.vulns.total ?? 0 }}
            </p>
            <div class="mt-1 flex gap-3 text-xs text-slate-500">
              <span>今日新增 {{ todayNewVulns }}</span>
              <span>已修复 {{ store.overview?.vulns.fixed_count ?? 0 }}</span>
            </div>
          </div>
          <AlertTriangle class="h-10 w-10 text-rose-400 opacity-80" />
        </div>
      </div>

      <!-- 暴露端口 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm text-slate-400">暴露端口</p>
            <p class="mt-2 text-3xl font-bold text-white">
              {{ store.overview?.ports.total ?? 0 }}
            </p>
            <p class="mt-1 text-xs text-rose-400">
              高危端口 {{ store.overview?.ports.risky_count ?? 0 }}
            </p>
          </div>
          <ShieldAlert class="h-10 w-10 text-amber-400 opacity-80" />
        </div>
      </div>

      <!-- 弱口令 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm text-slate-400">弱口令</p>
            <p class="mt-2 text-3xl font-bold text-white">
              {{ store.overview?.weak_passwords.total ?? 0 }}
            </p>
          </div>
          <KeyRound class="h-10 w-10 text-violet-400 opacity-80" />
        </div>
      </div>
    </div>

    <!-- 系统扫描趋势 + 实时任务 -->
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <!-- 漏洞发现变化趋势 -->
      <div
        v-if="sectionVisible.overview"
        :class="[
          'rounded-xl border border-slate-800 bg-slate-900/50 p-5',
          sectionVisible.tasks ? 'lg:col-span-2' : 'lg:col-span-3',
        ]"
      >
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-base font-medium text-slate-200">漏洞发现变化趋势</h3>
          <TrendingUp class="h-5 w-5 text-cyan-400" />
        </div>
        <div ref="trendChartRef" class="h-72"></div>
      </div>

      <!-- 实时任务列表（5 个最新） -->
      <div
        v-if="sectionVisible.tasks"
        :class="[
          'rounded-xl border border-slate-800 bg-slate-900/50 p-5',
          sectionVisible.overview ? '' : 'lg:col-span-3',
        ]"
      >
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-base font-medium text-slate-200">实时任务</h3>
          <Activity class="h-5 w-5 text-emerald-400" />
        </div>
        <div v-if="store.overview?.recent_tasks?.length" class="space-y-3">
          <div
            v-for="task in store.overview.recent_tasks"
            :key="task.id"
            class="cursor-pointer rounded-lg border border-slate-700 bg-slate-800/50 p-3 transition hover:border-cyan-500"
            @click="goTask(task)"
          >
            <div class="flex items-center justify-between">
              <span class="truncate text-sm text-slate-200">{{ task.name }}</span>
              <el-tag :type="taskStatusType(task.status)" size="small">
                {{ taskStatusLabel(task.status) }}
              </el-tag>
            </div>
            <div class="mt-1 flex items-center justify-between text-xs text-slate-500">
              <span>{{ taskTypeLabel(task.task_type) }}</span>
              <span>{{ task.progress?.toFixed(0) }}%</span>
            </div>
          </div>
        </div>
        <div v-else class="flex h-72 items-center justify-center text-slate-500">
          暂无任务
        </div>
      </div>
    </div>

    <!-- 风险网络漏洞 TOP10 + 网络资产风险等级分布 -->
    <div v-if="sectionVisible.overview" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">风险网络资产 TOP10</h3>
        <div ref="riskyAssetChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">网络资产风险等级分布</h3>
        <div ref="riskLevelChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 漏洞严重程度 + 暴露端口 TOP10 -->
    <div v-if="sectionVisible.system" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">漏洞严重程度分布</h3>
        <div ref="vulnChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">暴露端口 TOP10</h3>
        <div ref="portChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 操作系统分布 + 漏洞类型分布 -->
    <div v-if="sectionVisible.system" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">操作系统分布</h3>
        <div ref="osChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">漏洞类型分布 TOP8</h3>
        <div ref="typeChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 应用扫描图组：应用漏洞 TOP10 + 应用漏洞等级分布 -->
    <div v-if="sectionVisible.application" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">应用漏洞 TOP10</h3>
        <div ref="appTopChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">应用漏洞等级分布</h3>
        <div ref="appSeverityChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 数据库扫描图组：数据库漏洞等级分布 + 风险数据库资产 TOP10 -->
    <div v-if="sectionVisible.database" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">数据库漏洞等级分布</h3>
        <div ref="dbSeverityChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">风险数据库资产 TOP10</h3>
        <div ref="dbTopChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 基线配置图组：基线不符合项 TOP10 + 基线不符合 IP TOP10 -->
    <div v-if="sectionVisible.baseline" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">基线不符合项 TOP10</h3>
        <div ref="baselineItemChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">基线不符合 IP TOP10</h3>
        <div ref="baselineHostChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 弱密码图组：弱密码协议分布 + 主机 TOP10 + 用户名 TOP10 -->
    <div v-if="sectionVisible.weak" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">弱密码协议分布</h3>
        <div ref="wpProtocolChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">弱密码主机 TOP10</h3>
        <div ref="wpAssetChartRef" class="h-72"></div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">弱密码用户名 TOP10</h3>
        <div ref="wpUserChartRef" class="h-72"></div>
      </div>
    </div>

    <!-- 系统资源监控 -->
    <div v-if="sectionVisible.monitor" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <h3 class="mb-4 text-base font-medium text-slate-200">系统资源监控</h3>
        <div v-if="store.systemMonitor" class="space-y-4">
          <!-- CPU -->
          <div>
            <div class="mb-1 flex items-center justify-between text-sm">
              <span class="flex items-center gap-1.5 text-slate-300">
                <Cpu class="h-4 w-4 text-cyan-400" />
                CPU 使用率
              </span>
              <span class="text-slate-400">
                {{ store.systemMonitor.cpu.usage_percent.toFixed(1) }}%
                ({{ store.systemMonitor.cpu.cores }} 核)
              </span>
            </div>
            <el-progress
              :percentage="Math.round(store.systemMonitor.cpu.usage_percent)"
              :color="'#06b6d4'"
              :stroke-width="8"
            />
          </div>

          <!-- 内存 -->
          <div>
            <div class="mb-1 flex items-center justify-between text-sm">
              <span class="flex items-center gap-1.5 text-slate-300">
                <MemoryStick class="h-4 w-4 text-violet-400" />
                内存使用率
              </span>
              <span class="text-slate-400">
                {{ formatBytes(store.systemMonitor.memory.used_bytes) }} /
                {{ formatBytes(store.systemMonitor.memory.total_bytes) }}
              </span>
            </div>
            <el-progress
              :percentage="Math.round(store.systemMonitor.memory.usage_percent)"
              :color="'#8b5cf6'"
              :stroke-width="8"
            />
          </div>

          <!-- 磁盘 -->
          <div v-for="(disk, idx) in store.systemMonitor.disks.slice(0, 3)" :key="idx">
            <div class="mb-1 flex items-center justify-between text-sm">
              <span class="flex items-center gap-1.5 text-slate-300">
                <HardDrive class="h-4 w-4 text-amber-400" />
                {{ disk.mount_point || disk.name }}
              </span>
              <span class="text-slate-400">
                {{ formatBytes(disk.used_bytes) }} / {{ formatBytes(disk.total_bytes) }}
              </span>
            </div>
            <el-progress
              :percentage="Math.round(disk.usage_percent)"
              :color="disk.usage_percent > 90 ? '#dc2626' : '#f59e0b'"
              :stroke-width="8"
            />
          </div>

          <!-- 运行时间 -->
          <div class="flex items-center justify-between border-t border-slate-800 pt-3 text-sm">
            <span class="text-slate-400">系统运行时间</span>
            <span class="text-slate-300">
              {{ formatUptime(store.systemMonitor.uptime_seconds) }}
            </span>
          </div>
        </div>
        <div v-else class="flex h-72 items-center justify-center text-slate-500">
          暂无系统监控数据
        </div>
      </div>
    </div>
  </div>
</template>
