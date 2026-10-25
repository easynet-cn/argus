<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts/core'
import { BarChart, PieChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import {
  RefreshCw,
  Download,
  Trash2,
  Eye,
  Search,
  Bug,
  Network,
  KeyRound,
  BookOpen,
  AppWindow,
  Database,
  Wrench,
  Bell,
  Play,
  ExternalLink,
} from '@lucide/vue'
import {
  vulnApi,
  portApi,
  weakPasswordApi,
  cveApi,
  configChangeApi,
  alertApi,
  type VulnFinding,
  type ExposurePort,
  type WeakPassword,
  type CveRecord,
  type ConfigChange,
  type AlertRecord,
  type VulnListQuery,
  type PortListQuery,
  type WeakPasswordListQuery,
  type ConfigChangeListQuery,
  type AlertListQuery,
  type VulnStats,
  type PortStats,
  type WeakPasswordStats,
} from '@/api/risk'
import { assetGroupApi, type AssetGroupNode } from '@/api/asset'

echarts.use([
  BarChart,
  PieChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  CanvasRenderer,
])

// ===== Tab 管理 =====
type TabName =
  | 'system_vuln'
  | 'application_vuln'
  | 'database_vuln'
  | 'ports'
  | 'weak'
  | 'config_changes'
  | 'alerts'
  | 'cve'
const activeTab = ref<TabName>('system_vuln')
const isVulnTab = computed(() =>
  ['system_vuln', 'application_vuln', 'database_vuln'].includes(activeTab.value),
)

// ===== 资产组树（多 Tab 共用筛选） =====
const assetGroupTree = ref<AssetGroupNode[]>([])
async function loadAssetGroupTree() {
  try {
    const res = await assetGroupApi.tree()
    assetGroupTree.value = res.items
  } catch {
    // 忽略
  }
}
// 扁平化资产组用于 el-select
const flatGroups = computed(() => {
  const result: { id: string; name: string }[] = []
  const walk = (nodes: AssetGroupNode[], prefix = '') => {
    for (const n of nodes) {
      result.push({ id: n.id, name: prefix + n.name })
      if (n.children?.length) walk(n.children, prefix + '  ')
    }
  }
  walk(assetGroupTree.value)
  return result
})

// ===== 状态/等级映射（共用） =====
const riskStatusOptions = [
  { label: '新建', value: 'new' },
  { label: '处理中', value: 'processing' },
  { label: '已挂起', value: 'deferred' },
  { label: '已修复', value: 'fixed' },
  { label: '已验证', value: 'verified' },
  { label: '已关闭', value: 'closed' },
  { label: '误报', value: 'false_positive' },
  { label: '已忽略', value: 'ignored' },
  { label: '已重开', value: 'reopened' },
]

const severityType = (sev: string) => {
  const map: Record<string, string> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'info',
    info: 'info',
  }
  return map[sev?.toLowerCase()] || 'info'
}

const severityLabel = (sev: string) => {
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return map[sev?.toLowerCase()] || sev
}

const riskStatusLabel = (status: string) => {
  const map: Record<string, string> = {
    new: '新建',
    processing: '处理中',
    deferred: '已挂起',
    fixed: '已修复',
    verified: '已验证',
    closed: '已关闭',
    false_positive: '误报',
    ignored: '已忽略',
    reopened: '已重开',
  }
  return map[status] || status
}

const riskStatusType = (status: string) => {
  const map: Record<string, string> = {
    new: 'danger',
    processing: 'warning',
    deferred: 'info',
    fixed: 'success',
    verified: 'success',
    closed: 'info',
    false_positive: 'info',
    ignored: 'info',
    reopened: 'danger',
  }
  return map[status] || 'info'
}

// 危险等级映射（配置变更）
const riskLevelLabel = (level: string) => {
  const map: Record<string, string> = {
    high: '高危',
    medium: '中危',
    low: '低危',
    critical: '严重',
    info: '信息',
  }
  return map[level?.toLowerCase()] || level
}

const riskLevelType = (level: string) => {
  const map: Record<string, string> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'info',
    info: 'info',
  }
  return map[level?.toLowerCase()] || 'info'
}

// ===== 漏洞列表（系统/应用/数据库共用，通过 risk_type 切换） =====
const vulns = ref<VulnFinding[]>([])
const vulnLoading = ref(false)
const vulnPage = ref(1)
const vulnPageSize = ref(20)
const vulnFilter = ref<VulnListQuery>({})
const vulnDateRange = ref<[Date, Date] | null>(null)
const vulnTotal = ref(0)
const selectedVulns = ref<string[]>([])
const vulnViewMode = ref<'list' | 'dimension'>('list')

// 当前 Tab 对应的 risk_type
function currentVulnRiskType(): string {
  if (activeTab.value === 'application_vuln') return 'application'
  if (activeTab.value === 'database_vuln') return 'database'
  return 'system'
}

// 加载漏洞列表
async function loadVulns() {
  vulnLoading.value = true
  try {
    const params: VulnListQuery = {
      ...vulnFilter.value,
      risk_type: currentVulnRiskType(),
      page: vulnPage.value,
      page_size: vulnPageSize.value,
    }
    // 处理时间范围筛选
    if (vulnDateRange.value && vulnDateRange.value.length === 2) {
      const [start, end] = vulnDateRange.value
      params.start_date = start ? start.toISOString().slice(0, 10) : undefined
      params.end_date = end ? end.toISOString().slice(0, 10) : undefined
    }
    const res = await vulnApi.list(params)
    vulns.value = res.items
    vulnTotal.value = res.items.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    vulnLoading.value = false
  }
}

// 漏洞维度聚合（按漏洞名称分组，统计影响 IP 数等）
const vulnDimension = computed(() => {
  const map = new Map<
    string,
    {
      name: string
      severity: string
      cve_id: string
      cvss2: number | null
      cvss3: number | null
      cnnvd: string
      bugtraq_id: string
      cncve: string
      hosts: Set<string>
    }
  >()
  for (const v of vulns.value) {
    const key = v.title || v.cve_id || '未知'
    if (!map.has(key)) {
      map.set(key, {
        name: key,
        severity: v.severity,
        cve_id: v.cve_id || '-',
        cvss2: v.cvss2,
        cvss3: v.cvss3,
        cnnvd: v.cnnvd || '-',
        bugtraq_id: v.bugtraq_id || '-',
        cncve: v.cncve || '-',
        hosts: new Set(),
      })
    }
    const entry = map.get(key)!
    if (v.target_host) entry.hosts.add(v.target_host)
  }
  return Array.from(map.values()).map((e) => ({
    ...e,
    hostCount: e.hosts.size,
  }))
})

// 漏洞选择
function handleVulnSelectionChange(selection: VulnFinding[]) {
  selectedVulns.value = selection.map((item) => item.id)
}

// 漏洞详情弹窗
const vulnDetailVisible = ref(false)
const vulnDetail = ref<VulnFinding | null>(null)
const dispositionHistory = ref<any[]>([])

async function handleViewVuln(row: VulnFinding) {
  vulnDetail.value = row
  vulnDetailVisible.value = true
  try {
    const history = await vulnApi.getDispositionHistory(row.id)
    dispositionHistory.value = history?.items || history || []
  } catch {
    dispositionHistory.value = []
  }
}

// 漏洞处置弹窗（单条）
const dispositionVisible = ref(false)
const dispositionForm = ref({
  id: '',
  risk_status: '',
  assigned_to: '',
  remediation_note: '',
  reason: '',
})
const dispositionLoading = ref(false)

function openDisposition(row: VulnFinding) {
  dispositionForm.value = {
    id: row.id,
    risk_status: row.risk_status,
    assigned_to: row.assigned_to || '',
    remediation_note: row.remediation_note || '',
    reason: '',
  }
  dispositionVisible.value = true
}

async function handleSubmitDisposition() {
  dispositionLoading.value = true
  try {
    await vulnApi.updateStatus(dispositionForm.value.id, {
      risk_status: dispositionForm.value.risk_status,
      assigned_to: dispositionForm.value.assigned_to || undefined,
      remediation_note: dispositionForm.value.remediation_note || undefined,
      reason: dispositionForm.value.reason || undefined,
    })
    ElMessage.success('处置状态已更新')
    dispositionVisible.value = false
    await loadVulns()
  } catch {
    // 错误已在拦截器处理
  } finally {
    dispositionLoading.value = false
  }
}

// 批量处置弹窗（漏洞）
const batchDispositionVisible = ref(false)
const batchDispositionForm = ref({ risk_status: '', assigned_to: '', reason: '' })
const batchDispositionLoading = ref(false)

function openBatchDisposition() {
  if (selectedVulns.value.length === 0) {
    ElMessage.warning('请先选择要处置的漏洞')
    return
  }
  batchDispositionForm.value = { risk_status: '', assigned_to: '', reason: '' }
  batchDispositionVisible.value = true
}

async function handleSubmitBatchDisposition() {
  if (!batchDispositionForm.value.risk_status) {
    ElMessage.warning('请选择处置状态')
    return
  }
  batchDispositionLoading.value = true
  try {
    await vulnApi.batchUpdateStatus({
      ids: selectedVulns.value,
      risk_status: batchDispositionForm.value.risk_status,
      assigned_to: batchDispositionForm.value.assigned_to || undefined,
      reason: batchDispositionForm.value.reason || undefined,
    })
    ElMessage.success('批量处置成功')
    batchDispositionVisible.value = false
    selectedVulns.value = []
    await loadVulns()
  } catch {
    // 错误已在拦截器处理
  } finally {
    batchDispositionLoading.value = false
  }
}

// 漏洞导出
async function handleExportVulns() {
  try {
    const res = await vulnApi.export()
    const blob = res as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'vulnerabilities.xlsx'
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    // 错误已在拦截器处理
  }
}

// 清空所有漏洞数据
async function handleClearAllVulns() {
  try {
    await ElMessageBox.confirm(
      '此操作将删除全部漏洞数据且不可恢复，请谨慎操作！',
      '清空所有漏洞',
      {
        type: 'warning',
        confirmButtonText: '确认清空',
        cancelButtonText: '取消',
      },
    )
  } catch {
    // 用户取消
    return
  }
  try {
    const res = await vulnApi.clearAll()
    ElMessage.success(`已清空 ${res.deleted} 条数据`)
    selectedVulns.value = []
    await loadVulns()
    await loadVulnStats()
  } catch {
    ElMessage.error('清空失败')
  }
}

// Web 漏洞验证（应用漏洞 Tab）
function handleVerifyVuln(row: VulnFinding) {
  ElMessageBox.confirm(
    `确认对漏洞 "${row.title || row.cve_id || '未命名'}" 发起验证任务？`,
    '漏洞验证',
    { type: 'info' },
  )
    .then(() => {
      ElMessage.success('验证任务已发起，请稍后在任务列表查看')
    })
    .catch(() => {
      // 用户取消
    })
}

// 浏览器验证（应用漏洞 Tab）
function handleBrowserVerify(row: VulnFinding) {
  const url = row.request_url || ''
  if (!url) {
    ElMessage.warning('该漏洞无 URL 信息')
    return
  }
  window.open(url.startsWith('http') ? url : `http://${url}`, '_blank')
}

// ===== 漏洞统计图表 =====
const vulnStats = ref<VulnStats | null>(null)
const vulnFixRateChartRef = ref<HTMLElement>()
const vulnSeverityChartRef = ref<HTMLElement>()
let vulnFixRateChart: echarts.ECharts | null = null
let vulnSeverityChart: echarts.ECharts | null = null

async function loadVulnStats() {
  try {
    vulnStats.value = await vulnApi.stats()
    await nextTick()
    renderVulnFixRateChart()
    renderVulnSeverityChart()
  } catch {
    // 错误已在拦截器处理
  }
}

// 修复率统计饼图
function renderVulnFixRateChart() {
  if (!vulnFixRateChartRef.value || !vulnStats.value) return
  if (!vulnFixRateChart) vulnFixRateChart = echarts.init(vulnFixRateChartRef.value)
  const fixed = vulnStats.value.fixed_count || 0
  const unfixed = Math.max(0, vulnStats.value.total - fixed)
  vulnFixRateChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
    title: {
      text: `修复率 ${((vulnStats.value.fix_rate || 0) * 100).toFixed(1)}%`,
      left: 'center',
      top: '38%',
      textStyle: { color: '#e2e8f0', fontSize: 16 },
    },
    series: [
      {
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['50%', '45%'],
        data: [
          { name: '已修复', value: fixed, itemStyle: { color: '#10b981' } },
          { name: '未修复', value: unfixed, itemStyle: { color: '#475569' } },
        ],
        label: { color: '#cbd5e1' },
      },
    ],
  })
}

// 漏洞等级数量占比柱状图
function renderVulnSeverityChart() {
  if (!vulnSeverityChartRef.value || !vulnStats.value) return
  if (!vulnSeverityChart) vulnSeverityChart = echarts.init(vulnSeverityChartRef.value)
  const colors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#06b6d4',
    info: '#64748b',
  }
  const data = (vulnStats.value.by_severity || []).map((item) => ({
    name: severityLabel(item.key),
    value: item.count,
    color: colors[item.key?.toLowerCase()] || '#64748b',
  }))
  vulnSeverityChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map((d) => d.name),
      axisLabel: { color: '#94a3b8' },
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
        data: data.map((d) => ({ value: d.value, itemStyle: { color: d.color } })),
        itemStyle: { borderRadius: [4, 4, 0, 0] },
        barMaxWidth: 48,
      },
    ],
  })
}

// ===== 暴露端口 =====
const ports = ref<ExposurePort[]>([])
const portLoading = ref(false)
const portPage = ref(1)
const portPageSize = ref(20)
const portFilter = ref<PortListQuery>({})
const portTotal = ref(0)
const portViewMode = ref<'list' | 'dimension'>('list')

async function loadPorts() {
  portLoading.value = true
  try {
    const res = await portApi.list({
      ...portFilter.value,
      page: portPage.value,
      page_size: portPageSize.value,
    })
    ports.value = res.items
    portTotal.value = res.items.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    portLoading.value = false
  }
}

// 端口维度聚合（按端口分组：影响IP数/服务/标签）
const portDimension = computed(() => {
  const map = new Map<
    number,
    { port: number; hosts: Set<string>; services: Set<string>; tags: Set<string> }
  >()
  for (const p of ports.value) {
    if (!map.has(p.port))
      map.set(p.port, { port: p.port, hosts: new Set(), services: new Set(), tags: new Set() })
    const entry = map.get(p.port)!
    if (p.host) entry.hosts.add(p.host)
    if (p.service) entry.services.add(p.service)
    if (Array.isArray(p.tags)) p.tags.forEach((t) => entry.tags.add(t))
  }
  return Array.from(map.values()).map((e) => ({
    port: e.port,
    hostCount: e.hosts.size,
    services: Array.from(e.services).join(', ') || '-',
    tags: Array.from(e.tags).join(', ') || '-',
  }))
})

// 端口导出
async function handleExportPorts() {
  try {
    const res = await portApi.export()
    const blob = res as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'exposure-ports.xlsx'
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    // 错误已在拦截器处理
  }
}

// 清空所有端口数据
async function handleClearAllPorts() {
  try {
    await ElMessageBox.confirm(
      '此操作将删除全部端口数据且不可恢复，请谨慎操作！',
      '清空所有端口',
      {
        type: 'warning',
        confirmButtonText: '确认清空',
        cancelButtonText: '取消',
      },
    )
  } catch {
    // 用户取消
    return
  }
  try {
    const res = await portApi.clearAll()
    ElMessage.success(`已清空 ${res.deleted} 条数据`)
    await loadPorts()
    await loadPortStats()
  } catch {
    ElMessage.error('清空失败')
  }
}

// ===== 端口统计图表 =====
const portStats = ref<PortStats | null>(null)
const portTopIpChartRef = ref<HTMLElement>()
const portSurfaceChartRef = ref<HTMLElement>()
const portTypeChartRef = ref<HTMLElement>()
let portTopIpChart: echarts.ECharts | null = null
let portSurfaceChart: echarts.ECharts | null = null
let portTypeChart: echarts.ECharts | null = null

async function loadPortStats() {
  try {
    portStats.value = await portApi.stats()
    await nextTick()
    renderPortTopIpChart()
    renderPortSurfaceChart()
    renderPortTypeChart()
  } catch {
    // 错误已在拦截器处理
  }
}

// 端口暴露 IP TOP10 柱状图
function renderPortTopIpChart() {
  if (!portTopIpChartRef.value || !portStats.value) return
  if (!portTopIpChart) portTopIpChart = echarts.init(portTopIpChartRef.value)
  const data = (portStats.value.top_ports || [])
    .slice(0, 10)
    .map((item) => ({ name: `端口 ${item.key}`, value: item.count }))
  portTopIpChart.setOption({
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
        barMaxWidth: 32,
      },
    ],
  })
}

// 端口暴露面分布饼图（高危 vs 普通）
function renderPortSurfaceChart() {
  if (!portSurfaceChartRef.value || !portStats.value) return
  if (!portSurfaceChart) portSurfaceChart = echarts.init(portSurfaceChartRef.value)
  const risky = portStats.value.risky_count || 0
  const normal = Math.max(0, portStats.value.total - risky)
  portSurfaceChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8' } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data: [
          { name: '高危端口', value: risky, itemStyle: { color: '#dc2626' } },
          { name: '普通端口', value: normal, itemStyle: { color: '#475569' } },
        ],
        label: { color: '#cbd5e1' },
      },
    ],
  })
}

// 端口类型暴露分布占比饼图（按协议）
function renderPortTypeChart() {
  if (!portTypeChartRef.value || !portStats.value) return
  if (!portTypeChart) portTypeChart = echarts.init(portTypeChartRef.value)
  const data = (portStats.value.risky_by_protocol || []).map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  portTypeChart.setOption({
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

// ===== 弱口令 =====
const weakPasswords = ref<WeakPassword[]>([])
const weakLoading = ref(false)
const weakPage = ref(1)
const weakPageSize = ref(20)
const weakFilter = ref<WeakPasswordListQuery>({})
const weakTotal = ref(0)
const selectedWeak = ref<string[]>([])

async function loadWeakPasswords() {
  weakLoading.value = true
  try {
    const res = await weakPasswordApi.list({
      ...weakFilter.value,
      page: weakPage.value,
      page_size: weakPageSize.value,
    })
    weakPasswords.value = res.items
    weakTotal.value = res.items.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    weakLoading.value = false
  }
}

function handleWeakSelectionChange(selection: WeakPassword[]) {
  selectedWeak.value = selection.map((item) => item.id)
}

// 批量删除弱口令
async function handleBatchDeleteWeak() {
  if (selectedWeak.value.length === 0) {
    ElMessage.warning('请先选择要删除的项')
    return
  }
  await ElMessageBox.confirm(
    `确认删除选中的 ${selectedWeak.value.length} 项弱口令？`,
    '批量删除',
    { type: 'warning' },
  )
  try {
    await weakPasswordApi.batchDelete(selectedWeak.value)
    ElMessage.success('批量删除成功')
    selectedWeak.value = []
    await loadWeakPasswords()
  } catch {
    // 错误已在拦截器处理
  }
}

// 批量处置弱口令
const batchWeakVisible = ref(false)
const batchWeakForm = ref({ risk_status: '' })
const batchWeakLoading = ref(false)

function openBatchWeakDisposition() {
  if (selectedWeak.value.length === 0) {
    ElMessage.warning('请先选择要处置的项')
    return
  }
  batchWeakForm.value = { risk_status: '' }
  batchWeakVisible.value = true
}

async function handleSubmitBatchWeak() {
  if (!batchWeakForm.value.risk_status) {
    ElMessage.warning('请选择处置状态')
    return
  }
  batchWeakLoading.value = true
  try {
    await weakPasswordApi.batchUpdateStatus(
      selectedWeak.value,
      batchWeakForm.value.risk_status,
    )
    ElMessage.success('批量处置成功')
    batchWeakVisible.value = false
    selectedWeak.value = []
    await loadWeakPasswords()
  } catch {
    // 错误已在拦截器处理
  } finally {
    batchWeakLoading.value = false
  }
}

// 弱口令导出
async function handleExportWeak() {
  try {
    const res = await weakPasswordApi.export()
    const blob = res as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'weak-passwords.xlsx'
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    // 错误已在拦截器处理
  }
}

// 清空所有弱口令数据
async function handleClearAllWeak() {
  try {
    await ElMessageBox.confirm(
      '此操作将删除全部弱口令数据且不可恢复，请谨慎操作！',
      '清空所有弱口令',
      {
        type: 'warning',
        confirmButtonText: '确认清空',
        cancelButtonText: '取消',
      },
    )
  } catch {
    // 用户取消
    return
  }
  try {
    const res = await weakPasswordApi.clearAll()
    ElMessage.success(`已清空 ${res.deleted} 条数据`)
    selectedWeak.value = []
    await loadWeakPasswords()
    await loadWeakStats()
  } catch {
    ElMessage.error('清空失败')
  }
}

// ===== 弱口令统计图表 =====
const weakStats = ref<WeakPasswordStats | null>(null)
const weakTopAssetChartRef = ref<HTMLElement>()
const weakUsernameChartRef = ref<HTMLElement>()
let weakTopAssetChart: echarts.ECharts | null = null
let weakUsernameChart: echarts.ECharts | null = null

async function loadWeakStats() {
  try {
    weakStats.value = await weakPasswordApi.stats()
    await nextTick()
    renderWeakTopAssetChart()
    renderWeakUsernameChart()
  } catch {
    // 错误已在拦截器处理
  }
}

// 弱密码风险资产 TOP10 柱状图
function renderWeakTopAssetChart() {
  if (!weakTopAssetChartRef.value || !weakStats.value) return
  if (!weakTopAssetChart) weakTopAssetChart = echarts.init(weakTopAssetChartRef.value)
  const source = weakStats.value.top_assets || weakStats.value.top_hosts || []
  const data = source.slice(0, 10).map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  weakTopAssetChart.setOption({
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
        barMaxWidth: 24,
      },
    ],
  })
}

// 弱密码用户名分布饼图
function renderWeakUsernameChart() {
  if (!weakUsernameChartRef.value || !weakStats.value) return
  if (!weakUsernameChart) weakUsernameChart = echarts.init(weakUsernameChartRef.value)
  const data = (weakStats.value.by_username || []).map((item) => ({
    name: item.key || '未知',
    value: item.count,
  }))
  weakUsernameChart.setOption({
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

// ===== 配置变更 =====
const configChanges = ref<ConfigChange[]>([])
const configLoading = ref(false)
const configPage = ref(1)
const configPageSize = ref(20)
const configFilter = ref<ConfigChangeListQuery>({})
const configTotal = ref(0)

async function loadConfigChanges() {
  configLoading.value = true
  try {
    const res = await configChangeApi.list({
      ...configFilter.value,
      page: configPage.value,
      page_size: configPageSize.value,
    })
    configChanges.value = res.items
    configTotal.value = res.items.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    configLoading.value = false
  }
}

// ===== 告警管理 =====
const alerts = ref<AlertRecord[]>([])
const alertLoading = ref(false)
const alertPage = ref(1)
const alertPageSize = ref(20)
const alertFilter = ref<AlertListQuery>({})
const alertTotal = ref(0)

async function loadAlerts() {
  alertLoading.value = true
  try {
    const res = await alertApi.list({
      ...alertFilter.value,
      page: alertPage.value,
      page_size: alertPageSize.value,
    })
    alerts.value = res.items
    alertTotal.value = res.items.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    alertLoading.value = false
  }
}

// ===== CVE 知识库 =====
const cves = ref<CveRecord[]>([])
const cveLoading = ref(false)
const cveKeyword = ref('')
const cveOffset = ref(0)
const cveLimit = ref(20)
const cveTotal = ref(0)
const cveDetailVisible = ref(false)
const cveDetail = ref<CveRecord | null>(null)

// CVE 导入
const cveImportVisible = ref(false)
const cveImportForm = ref({ start_year: 2002, end_year: 2024 })
const cveImportLoading = ref(false)

async function loadCves() {
  cveLoading.value = true
  try {
    const res = await cveApi.list({
      keyword: cveKeyword.value || undefined,
      limit: cveLimit.value,
      offset: cveOffset.value,
    })
    cves.value = res.data
    cveTotal.value = res.total
  } catch {
    // 错误已在拦截器处理
  } finally {
    cveLoading.value = false
  }
}

async function handleCveSearch() {
  cveOffset.value = 0
  await loadCves()
}

function handleViewCve(row: CveRecord) {
  cveDetail.value = row
  cveDetailVisible.value = true
}

async function handleCveImport() {
  cveImportLoading.value = true
  try {
    const res = await cveApi.import(cveImportForm.value.start_year, cveImportForm.value.end_year)
    ElMessage.success(`CVE 导入已启动：${res.message}`)
    cveImportVisible.value = false
    // 轮询导入状态
    const timer = setInterval(async () => {
      const status = await cveApi.importStatus()
      if (status.status === 'completed' || status.status === 'failed') {
        clearInterval(timer)
        if (status.status === 'completed') {
          ElMessage.success(`CVE 导入完成，共处理 ${status.total_processed} 条`)
          await loadCves()
        } else {
          ElMessage.error(`CVE 导入失败：${status.error}`)
        }
      }
    }, 5000)
  } catch {
    // 错误已在拦截器处理
  } finally {
    cveImportLoading.value = false
  }
}

// ===== 通用工具 =====
function formatTime(t: string | null): string {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

// ===== Tab 切换 =====
watch(activeTab, (tab) => {
  switch (tab) {
    case 'system_vuln':
      vulnPage.value = 1
      loadVulns()
      loadVulnStats()
      break
    case 'application_vuln':
    case 'database_vuln':
      vulnPage.value = 1
      loadVulns()
      break
    case 'ports':
      if (!ports.value.length) {
        loadPorts()
        loadPortStats()
      }
      break
    case 'weak':
      if (!weakPasswords.value.length) {
        loadWeakPasswords()
        loadWeakStats()
      }
      break
    case 'config_changes':
      if (!configChanges.value.length) loadConfigChanges()
      break
    case 'alerts':
      if (!alerts.value.length) loadAlerts()
      break
    case 'cve':
      if (!cves.value.length) loadCves()
      break
  }
})

// ===== 图表 resize =====
function handleResize() {
  vulnFixRateChart?.resize()
  vulnSeverityChart?.resize()
  portTopIpChart?.resize()
  portSurfaceChart?.resize()
  portTypeChart?.resize()
  weakTopAssetChart?.resize()
  weakUsernameChart?.resize()
}

onMounted(async () => {
  loadAssetGroupTree()
  await loadVulns()
  await loadVulnStats()
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  vulnFixRateChart?.dispose()
  vulnSeverityChart?.dispose()
  portTopIpChart?.dispose()
  portSurfaceChart?.dispose()
  portTypeChart?.dispose()
  weakTopAssetChart?.dispose()
  weakUsernameChart?.dispose()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 顶部 Tab 栏 -->
    <el-tabs v-model="activeTab" class="flex-1">
      <el-tab-pane name="system_vuln">
        <template #label>
          <span class="flex items-center gap-1.5"><Bug class="h-4 w-4" />系统漏洞</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="application_vuln">
        <template #label>
          <span class="flex items-center gap-1.5"><AppWindow class="h-4 w-4" />应用漏洞</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="database_vuln">
        <template #label>
          <span class="flex items-center gap-1.5"><Database class="h-4 w-4" />数据库漏洞</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="ports">
        <template #label>
          <span class="flex items-center gap-1.5"><Network class="h-4 w-4" />暴露端口</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="weak">
        <template #label>
          <span class="flex items-center gap-1.5"><KeyRound class="h-4 w-4" />弱口令</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="config_changes">
        <template #label>
          <span class="flex items-center gap-1.5"><Wrench class="h-4 w-4" />配置变更</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="alerts">
        <template #label>
          <span class="flex items-center gap-1.5"><Bell class="h-4 w-4" />告警管理</span>
        </template>
      </el-tab-pane>
      <el-tab-pane name="cve">
        <template #label>
          <span class="flex items-center gap-1.5"><BookOpen class="h-4 w-4" />CVE 知识库</span>
        </template>
      </el-tab-pane>
    </el-tabs>

    <!-- ===================== 漏洞列表（系统/应用/数据库） ===================== -->
    <div v-show="isVulnTab">
      <!-- 统计图（仅系统漏洞 Tab 显示） -->
      <div v-if="activeTab === 'system_vuln'" class="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">修复率统计</h3>
          <div ref="vulnFixRateChartRef" class="h-64"></div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">漏洞等级数量占比</h3>
          <div ref="vulnSeverityChartRef" class="h-64"></div>
        </div>
      </div>

      <!-- 过滤器 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="vulnFilter.name"
          placeholder="漏洞标题"
          style="width: 180px"
          clearable
        />
        <el-input
          v-model="vulnFilter.host"
          placeholder="目标主机"
          style="width: 150px"
          clearable
        />
        <el-input
          v-model="vulnFilter.cve_id"
          placeholder="CVE ID"
          style="width: 150px"
          clearable
        />
        <el-select
          v-model="vulnFilter.severity"
          placeholder="严重程度"
          style="width: 120px"
          clearable
        >
          <el-option label="严重" value="critical" />
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>
        <el-select
          v-model="vulnFilter.risk_status"
          placeholder="处置状态"
          style="width: 130px"
          clearable
        >
          <el-option
            v-for="opt in riskStatusOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <!-- 资产组筛选 -->
        <el-select
          v-model="vulnFilter.asset_group_id"
          placeholder="资产组"
          style="width: 160px"
          clearable
        >
          <el-option
            v-for="g in flatGroups"
            :key="g.id"
            :label="g.name"
            :value="g.id"
          />
        </el-select>
        <!-- 时间范围筛选 -->
        <el-date-picker
          v-model="vulnDateRange"
          type="daterange"
          range-separator="至"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
          style="width: 260px"
        />
        <!-- 维度视图切换 -->
        <el-radio-group v-model="vulnViewMode" size="small">
          <el-radio-button value="list">漏洞列表</el-radio-button>
          <el-radio-button value="dimension">漏洞维度</el-radio-button>
        </el-radio-group>
        <el-button :icon="Search" type="primary" @click="vulnPage = 1; loadVulns()">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadVulns()">刷新</el-button>
        <el-button :icon="Download" @click="handleExportVulns">导出</el-button>
        <el-button
          type="danger"
          :icon="Trash2"
          class="border-rose-500/40 text-rose-400"
          @click="handleClearAllVulns"
        >
          清空所有
        </el-button>
        <el-button
          v-if="selectedVulns.length > 0"
          type="warning"
          @click="openBatchDisposition"
        >
          批量处置 ({{ selectedVulns.length }})
        </el-button>
      </div>

      <!-- 漏洞列表视图 -->
      <el-table
        v-if="vulnViewMode === 'list'"
        :data="vulns"
        v-loading="vulnLoading"
        @selection-change="handleVulnSelectionChange"
        stripe
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="title" label="漏洞标题" min-width="180" show-overflow-tooltip />
        <el-table-column prop="cve_id" label="CVE" width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.cve_id || '-' }}</template>
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">
              {{ severityLabel(row.severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <!-- 应用漏洞 Tab 显示方法 / URL 列 -->
        <el-table-column
          v-if="activeTab === 'application_vuln'"
          prop="request_method"
          label="方法"
          width="80"
        >
          <template #default="{ row }">
            <el-tag v-if="row.request_method" size="small" type="warning">
              {{ row.request_method }}
            </el-tag>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column
          v-if="activeTab === 'application_vuln'"
          prop="request_url"
          label="URL"
          min-width="200"
          show-overflow-tooltip
        >
          <template #default="{ row }">{{ row.request_url || '-' }}</template>
        </el-table-column>
        <!-- 数据库漏洞 Tab 显示数据库实例/SQL 语句 -->
        <el-table-column
          v-if="activeTab === 'database_vuln'"
          prop="db_instance"
          label="数据库实例"
          width="130"
          show-overflow-tooltip
        >
          <template #default="{ row }">{{ row.db_instance || '-' }}</template>
        </el-table-column>
        <el-table-column prop="target_host" label="目标主机" width="130" />
        <el-table-column prop="target_port" label="端口" width="70">
          <template #default="{ row }">{{ row.target_port || '-' }}</template>
        </el-table-column>
        <el-table-column prop="risk_status" label="处置状态" width="100">
          <template #default="{ row }">
            <el-tag :type="riskStatusType(row.risk_status)" size="small">
              {{ riskStatusLabel(row.risk_status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_found" label="最后发现时间" width="170">
          <template #default="{ row }">{{ formatTime(row.last_found) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="Eye" @click="handleViewVuln(row)">详情</el-button>
            <el-button link type="warning" @click="openDisposition(row)">处置</el-button>
            <!-- 应用漏洞 Tab 显示验证 / 浏览器验证按钮 -->
            <el-button
              v-if="activeTab === 'application_vuln'"
              link
              type="success"
              :icon="Play"
              @click="handleVerifyVuln(row)"
            >验证</el-button>
            <el-button
              v-if="activeTab === 'application_vuln'"
              link
              type="info"
              :icon="ExternalLink"
              @click="handleBrowserVerify(row)"
            >浏览器验证</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 漏洞维度视图 -->
      <el-table
        v-else
        :data="vulnDimension"
        v-loading="vulnLoading"
        stripe
        style="width: 100%"
      >
        <el-table-column prop="name" label="漏洞名称" min-width="200" show-overflow-tooltip />
        <el-table-column prop="severity" label="等级" width="90">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">
              {{ severityLabel(row.severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="cve_id" label="CVE" width="140" show-overflow-tooltip />
        <el-table-column prop="cvss2" label="CVSS2" width="80">
          <template #default="{ row }">{{ row.cvss2 ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="cvss3" label="CVSS3" width="80">
          <template #default="{ row }">{{ row.cvss3 ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="cnnvd" label="CNNVD" width="130" show-overflow-tooltip />
        <el-table-column prop="bugtraq_id" label="BugtraqID" width="110" show-overflow-tooltip />
        <el-table-column prop="cncve" label="CNCVE" width="130" show-overflow-tooltip />
        <el-table-column prop="hostCount" label="影响IP数" width="100" sortable />
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="vulnPage"
          v-model:page-size="vulnPageSize"
          :total="vulnTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadVulns"
          @size-change="loadVulns"
        />
      </div>
    </div>

    <!-- ===================== 暴露端口 ===================== -->
    <div v-show="activeTab === 'ports'">
      <!-- 统计图：3 个 -->
      <div class="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">端口暴露 IP TOP10</h3>
          <div ref="portTopIpChartRef" class="h-64"></div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">端口暴露面分布</h3>
          <div ref="portSurfaceChartRef" class="h-64"></div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">端口类型暴露分布占比</h3>
          <div ref="portTypeChartRef" class="h-64"></div>
        </div>
      </div>

      <!-- 过滤器 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="portFilter.host"
          placeholder="主机 IP"
          style="width: 150px"
          clearable
        />
        <el-input-number
          v-model="portFilter.port"
          placeholder="端口"
          :min="1"
          :max="65535"
          style="width: 120px"
        />
        <el-select
          v-model="portFilter.is_risky"
          placeholder="风险级别"
          style="width: 120px"
          clearable
        >
          <el-option label="高危端口" :value="true" />
          <el-option label="普通端口" :value="false" />
        </el-select>
        <!-- 资产组筛选 -->
        <el-select
          v-model="portFilter.asset_group_id"
          placeholder="资产组"
          style="width: 160px"
          clearable
        >
          <el-option
            v-for="g in flatGroups"
            :key="g.id"
            :label="g.name"
            :value="g.id"
          />
        </el-select>
        <!-- 维度视图切换 -->
        <el-radio-group v-model="portViewMode" size="small">
          <el-radio-button value="list">端口列表</el-radio-button>
          <el-radio-button value="dimension">端口维度</el-radio-button>
        </el-radio-group>
        <el-button :icon="Search" type="primary" @click="portPage = 1; loadPorts()">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadPorts()">刷新</el-button>
        <el-button :icon="Download" @click="handleExportPorts">导出</el-button>
        <el-button
          type="danger"
          :icon="Trash2"
          class="border-rose-500/40 text-rose-400"
          @click="handleClearAllPorts"
        >
          清空所有
        </el-button>
      </div>

      <!-- 端口列表视图 -->
      <el-table
        v-if="portViewMode === 'list'"
        :data="ports"
        v-loading="portLoading"
        stripe
        style="width: 100%"
      >
        <el-table-column prop="host" label="主机" width="140" />
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="service" label="服务" width="120" show-overflow-tooltip>
          <template #default="{ row }">{{ row.service || '-' }}</template>
        </el-table-column>
        <el-table-column prop="is_risky" label="风险" width="70">
          <template #default="{ row }">
            <el-tag v-if="row.is_risky" type="danger" size="small">高危</el-tag>
            <el-tag v-else type="info" size="small">普通</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="version" label="版本" width="120" show-overflow-tooltip>
          <template #default="{ row }">{{ row.version || '-' }}</template>
        </el-table-column>
        <el-table-column prop="banner" label="Banner" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.banner || '-' }}</template>
        </el-table-column>
        <el-table-column prop="last_found" label="最后发现" width="170">
          <template #default="{ row }">{{ formatTime(row.last_found) }}</template>
        </el-table-column>
      </el-table>

      <!-- 端口维度视图 -->
      <el-table
        v-else
        :data="portDimension"
        v-loading="portLoading"
        stripe
        style="width: 100%"
      >
        <el-table-column prop="port" label="端口" width="100" sortable />
        <el-table-column prop="hostCount" label="影响IP数" width="120" sortable />
        <el-table-column prop="services" label="服务" min-width="180" show-overflow-tooltip />
        <el-table-column prop="tags" label="标签" min-width="160" show-overflow-tooltip />
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="portPage"
          v-model:page-size="portPageSize"
          :total="portTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadPorts"
          @size-change="loadPorts"
        />
      </div>
    </div>

    <!-- ===================== 弱口令 ===================== -->
    <div v-show="activeTab === 'weak'">
      <!-- 统计图：2 个 -->
      <div class="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">弱密码风险资产 TOP10</h3>
          <div ref="weakTopAssetChartRef" class="h-64"></div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
          <h3 class="mb-4 text-base font-medium text-slate-200">弱密码用户名分布</h3>
          <div ref="weakUsernameChartRef" class="h-64"></div>
        </div>
      </div>

      <!-- 过滤器 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="weakFilter.host"
          placeholder="主机 IP"
          style="width: 150px"
          clearable
        />
        <el-input
          v-model="weakFilter.protocol"
          placeholder="协议"
          style="width: 120px"
          clearable
        />
        <el-input-number
          v-model="weakFilter.port"
          placeholder="端口"
          :min="1"
          :max="65535"
          style="width: 120px"
        />
        <el-input
          v-model="weakFilter.username"
          placeholder="用户名"
          style="width: 120px"
          clearable
        />
        <el-select
          v-model="weakFilter.risk_status"
          placeholder="处置状态"
          style="width: 130px"
          clearable
        >
          <el-option
            v-for="opt in riskStatusOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <!-- 资产组筛选 -->
        <el-select
          v-model="weakFilter.asset_group_id"
          placeholder="资产组"
          style="width: 160px"
          clearable
        >
          <el-option
            v-for="g in flatGroups"
            :key="g.id"
            :label="g.name"
            :value="g.id"
          />
        </el-select>
        <el-button :icon="Search" type="primary" @click="weakPage = 1; loadWeakPasswords()">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadWeakPasswords()">刷新</el-button>
        <el-button :icon="Download" @click="handleExportWeak">导出</el-button>
        <el-button
          v-if="selectedWeak.length > 0"
          type="warning"
          @click="openBatchWeakDisposition"
        >
          批量处置 ({{ selectedWeak.length }})
        </el-button>
        <el-button
          v-if="selectedWeak.length > 0"
          type="danger"
          :icon="Trash2"
          @click="handleBatchDeleteWeak"
        >
          批量删除 ({{ selectedWeak.length }})
        </el-button>
        <el-button
          type="danger"
          :icon="Trash2"
          class="border-rose-500/40 text-rose-400"
          @click="handleClearAllWeak"
        >
          清空所有
        </el-button>
      </div>

      <el-table
        :data="weakPasswords"
        v-loading="weakLoading"
        @selection-change="handleWeakSelectionChange"
        stripe
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="host" label="主机" width="140" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="username" label="用户名" width="120" />
        <el-table-column prop="password" label="密码" width="120" show-overflow-tooltip />
        <el-table-column prop="risk_status" label="处置状态" width="100">
          <template #default="{ row }">
            <el-tag :type="riskStatusType(row.risk_status)" size="small">
              {{ riskStatusLabel(row.risk_status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_found" label="最后发现" width="170">
          <template #default="{ row }">{{ formatTime(row.last_found) }}</template>
        </el-table-column>
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="weakPage"
          v-model:page-size="weakPageSize"
          :total="weakTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadWeakPasswords"
          @size-change="loadWeakPasswords"
        />
      </div>
    </div>

    <!-- ===================== 配置变更 ===================== -->
    <div v-show="activeTab === 'config_changes'">
      <!-- 过滤器 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="configFilter.name"
          placeholder="配置名称"
          style="width: 180px"
          clearable
        />
        <el-input
          v-model="configFilter.host"
          placeholder="主机 IP"
          style="width: 150px"
          clearable
        />
        <el-select
          v-model="configFilter.risk_level"
          placeholder="危险等级"
          style="width: 120px"
          clearable
        >
          <el-option label="严重" value="critical" />
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>
        <el-button :icon="Search" type="primary" @click="configPage = 1; loadConfigChanges()">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadConfigChanges()">刷新</el-button>
      </div>

      <el-table :data="configChanges" v-loading="configLoading" stripe style="width: 100%">
        <el-table-column prop="name" label="名称" min-width="160" show-overflow-tooltip />
        <el-table-column prop="config_item" label="配置项" min-width="180" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="130">
          <template #default="{ row }">{{ row.ip || row.host || '-' }}</template>
        </el-table-column>
        <el-table-column prop="risk_level" label="危险等级" width="100">
          <template #default="{ row }">
            <el-tag :type="riskLevelType(row.risk_level)" size="small">
              {{ riskLevelLabel(row.risk_level) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="detection_result" label="检测结果" width="110" show-overflow-tooltip />
        <el-table-column prop="last_detection_result" label="最近检测结果" width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.last_detection_result || '-' }}</template>
        </el-table-column>
        <el-table-column prop="first_found" label="首次发现" width="170">
          <template #default="{ row }">{{ formatTime(row.first_found) }}</template>
        </el-table-column>
        <el-table-column prop="last_found" label="最后发现" width="170">
          <template #default="{ row }">{{ formatTime(row.last_found) }}</template>
        </el-table-column>
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="configPage"
          v-model:page-size="configPageSize"
          :total="configTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadConfigChanges"
          @size-change="loadConfigChanges"
        />
      </div>
    </div>

    <!-- ===================== 告警管理 ===================== -->
    <div v-show="activeTab === 'alerts'">
      <!-- 过滤器 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="alertFilter.type"
          placeholder="告警类型"
          style="width: 150px"
          clearable
        />
        <el-input
          v-model="alertFilter.host"
          placeholder="IP/域名"
          style="width: 150px"
          clearable
        />
        <el-button :icon="Search" type="primary" @click="alertPage = 1; loadAlerts()">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadAlerts()">刷新</el-button>
      </div>

      <el-table :data="alerts" v-loading="alertLoading" stripe style="width: 100%">
        <el-table-column prop="created_at" label="时间" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="120" show-overflow-tooltip />
        <el-table-column prop="vuln_name" label="漏洞名称" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ row.vuln_name || '-' }}</template>
        </el-table-column>
        <el-table-column prop="host" label="IP" width="130" />
        <el-table-column prop="domain" label="域名" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.domain || '-' }}</template>
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.severity" :type="severityType(row.severity)" size="small">
              {{ severityLabel(row.severity) }}
            </el-tag>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="告警信息" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.message || '-' }}</template>
        </el-table-column>
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="alertPage"
          v-model:page-size="alertPageSize"
          :total="alertTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadAlerts"
          @size-change="loadAlerts"
        />
      </div>
    </div>

    <!-- ===================== CVE 知识库 ===================== -->
    <div v-show="activeTab === 'cve'">
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="cveKeyword"
          placeholder="关键字搜索（CVE ID、描述）"
          style="width: 280px"
          clearable
          @keyup.enter="handleCveSearch"
        />
        <el-button :icon="Search" type="primary" @click="handleCveSearch">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadCves">刷新</el-button>
        <el-button type="primary" @click="cveImportVisible = true">导入 CVE</el-button>
      </div>

      <el-table :data="cves" v-loading="cveLoading" stripe style="width: 100%">
        <el-table-column prop="id" label="CVE ID" width="160" />
        <el-table-column prop="source" label="来源" width="80" />
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity || '')" size="small">
              {{ severityLabel(row.severity || '') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="cvss_v3" label="CVSS v3" width="90">
          <template #default="{ row }">{{ row.cvss_v3 ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="300" show-overflow-tooltip />
        <el-table-column prop="published" label="发布时间" width="170">
          <template #default="{ row }">{{ formatTime(row.published) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="Eye" @click="handleViewCve(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="cveOffset"
          :page-size="cveLimit"
          :total="cveTotal"
          layout="total, prev, pager, next"
          @current-change="(p: number) => { cveOffset = (p - 1) * cveLimit; loadCves() }"
        />
      </div>
    </div>

    <!-- 漏洞详情弹窗 -->
    <el-dialog v-model="vulnDetailVisible" title="漏洞详情" width="720px">
      <template v-if="vulnDetail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="漏洞标题">{{ vulnDetail.title || '-' }}</el-descriptions-item>
          <el-descriptions-item label="CVE ID">{{ vulnDetail.cve_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag :type="severityType(vulnDetail.severity)" size="small">
              {{ severityLabel(vulnDetail.severity) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="CVSS v3">{{ vulnDetail.cvss3 ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="CVSS v2">{{ vulnDetail.cvss2 ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="漏洞类型">{{ vulnDetail.vuln_type || '-' }}</el-descriptions-item>
          <el-descriptions-item label="风险类型">{{ vulnDetail.risk_type }}</el-descriptions-item>
          <el-descriptions-item label="目标主机">{{ vulnDetail.target_host }}</el-descriptions-item>
          <el-descriptions-item label="目标端口">{{ vulnDetail.target_port || '-' }}</el-descriptions-item>
          <el-descriptions-item label="处置状态">
            <el-tag :type="riskStatusType(vulnDetail.risk_status)" size="small">
              {{ riskStatusLabel(vulnDetail.risk_status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="负责人">{{ vulnDetail.assigned_to || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="vulnDetail.position" label="漏洞位置" :span="2">
            {{ vulnDetail.position }}
          </el-descriptions-item>
          <el-descriptions-item v-if="vulnDetail.request_url" label="URL" :span="2">
            {{ vulnDetail.request_url }}
          </el-descriptions-item>
          <el-descriptions-item v-if="vulnDetail.cnnvd" label="CNNVD">{{ vulnDetail.cnnvd }}</el-descriptions-item>
          <el-descriptions-item v-if="vulnDetail.bugtraq_id" label="BugtraqID">{{ vulnDetail.bugtraq_id }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatTime(vulnDetail.first_found) }}</el-descriptions-item>
          <el-descriptions-item label="最后发现">{{ formatTime(vulnDetail.last_found) }}</el-descriptions-item>
          <el-descriptions-item label="漏洞描述" :span="2">
            {{ vulnDetail.description || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="影响范围" :span="2">
            {{ vulnDetail.impact_range || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="修复建议" :span="2">
            {{ vulnDetail.fix_advice || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="证据" :span="2">
            <pre class="max-h-40 overflow-auto whitespace-pre-wrap text-xs">{{ vulnDetail.evidence || '-' }}</pre>
          </el-descriptions-item>
        </el-descriptions>

        <div v-if="dispositionHistory.length > 0" class="mt-4">
          <h4 class="mb-2 text-sm font-medium text-slate-300">处置历史</h4>
          <el-timeline>
            <el-timeline-item
              v-for="(h, idx) in dispositionHistory"
              :key="idx"
              :timestamp="h.created_at ? formatTime(h.created_at) : ''"
              placement="top"
            >
              <p class="text-sm text-slate-300">
                {{ riskStatusLabel(h.from_status) }} → {{ riskStatusLabel(h.to_status) }}
              </p>
              <p v-if="h.operator" class="text-xs text-slate-500">操作人：{{ h.operator }}</p>
              <p v-if="h.reason" class="text-xs text-slate-500">原因：{{ h.reason }}</p>
            </el-timeline-item>
          </el-timeline>
        </div>
      </template>
    </el-dialog>

    <!-- 漏洞处置弹窗（单条） -->
    <el-dialog v-model="dispositionVisible" title="漏洞处置" width="500px">
      <el-form :model="dispositionForm" label-width="100px">
        <el-form-item label="处置状态" required>
          <el-select v-model="dispositionForm.risk_status" style="width: 100%">
            <el-option
              v-for="opt in riskStatusOptions"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="dispositionForm.assigned_to" placeholder="处理人" />
        </el-form-item>
        <el-form-item label="修复说明">
          <el-input
            v-model="dispositionForm.remediation_note"
            type="textarea"
            :rows="2"
            placeholder="修复说明"
          />
        </el-form-item>
        <el-form-item label="处置原因">
          <el-input
            v-model="dispositionForm.reason"
            type="textarea"
            :rows="2"
            placeholder="处置原因（记录到处置历史）"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dispositionVisible = false">取消</el-button>
        <el-button type="primary" :loading="dispositionLoading" @click="handleSubmitDisposition">
          确认处置
        </el-button>
      </template>
    </el-dialog>

    <!-- 批量处置弹窗（漏洞） -->
    <el-dialog v-model="batchDispositionVisible" title="批量处置漏洞" width="500px">
      <p class="mb-4 text-sm text-slate-400">
        将对选中的 {{ selectedVulns.length }} 条漏洞统一变更处置状态。
      </p>
      <el-form :model="batchDispositionForm" label-width="100px">
        <el-form-item label="处置状态" required>
          <el-select v-model="batchDispositionForm.risk_status" style="width: 100%">
            <el-option
              v-for="opt in riskStatusOptions"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="batchDispositionForm.assigned_to" placeholder="处理人（可选）" />
        </el-form-item>
        <el-form-item label="处置原因">
          <el-input
            v-model="batchDispositionForm.reason"
            type="textarea"
            :rows="2"
            placeholder="处置原因（可选）"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="batchDispositionVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="batchDispositionLoading"
          @click="handleSubmitBatchDisposition"
        >
          确认批量处置
        </el-button>
      </template>
    </el-dialog>

    <!-- 批量处置弹窗（弱口令） -->
    <el-dialog v-model="batchWeakVisible" title="批量处置弱口令" width="440px">
      <p class="mb-4 text-sm text-slate-400">
        将对选中的 {{ selectedWeak.length }} 条弱口令统一变更处置状态。
      </p>
      <el-form :model="batchWeakForm" label-width="100px">
        <el-form-item label="处置状态" required>
          <el-select v-model="batchWeakForm.risk_status" style="width: 100%">
            <el-option
              v-for="opt in riskStatusOptions"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="batchWeakVisible = false">取消</el-button>
        <el-button type="primary" :loading="batchWeakLoading" @click="handleSubmitBatchWeak">
          确认批量处置
        </el-button>
      </template>
    </el-dialog>

    <!-- CVE 详情弹窗 -->
    <el-dialog v-model="cveDetailVisible" title="CVE 详情" width="720px">
      <template v-if="cveDetail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="CVE ID">{{ cveDetail.id }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ cveDetail.source }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag :type="severityType(cveDetail.severity || '')" size="small">
              {{ severityLabel(cveDetail.severity || '') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="CVSS v3">{{ cveDetail.cvss_v3 ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="CVSS v2">{{ cveDetail.cvss_v2 ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="向量">{{ cveDetail.cvss_vector || '-' }}</el-descriptions-item>
          <el-descriptions-item label="发布时间">{{ formatTime(cveDetail.published) }}</el-descriptions-item>
          <el-descriptions-item label="最后修改">{{ formatTime(cveDetail.last_modified) }}</el-descriptions-item>
          <el-descriptions-item label="描述" :span="2">{{ cveDetail.description }}</el-descriptions-item>
          <el-descriptions-item
            v-if="Array.isArray(cveDetail.references) && cveDetail.references.length > 0"
            label="参考链接"
            :span="2"
          >
            <div v-for="(ref, idx) in cveDetail.references" :key="idx" class="text-xs">
              <a :href="ref.url || ref" target="_blank" class="text-cyan-400 hover:underline">
                {{ ref.url || ref }}
              </a>
            </div>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>

    <!-- CVE 导入弹窗 -->
    <el-dialog v-model="cveImportVisible" title="导入 CVE 知识库" width="420px">
      <el-form :model="cveImportForm" label-width="100px">
        <el-form-item label="起始年份">
          <el-input-number v-model="cveImportForm.start_year" :min="2002" :max="2026" />
        </el-form-item>
        <el-form-item label="结束年份">
          <el-input-number v-model="cveImportForm.end_year" :min="2002" :max="2026" />
        </el-form-item>
      </el-form>
      <p class="text-xs text-slate-500">
        从 NVD 导入 CVE 数据，导入过程异步执行，可在列表中查看进度。
      </p>
      <template #footer>
        <el-button @click="cveImportVisible = false">取消</el-button>
        <el-button type="primary" :loading="cveImportLoading" @click="handleCveImport">
          开始导入
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
