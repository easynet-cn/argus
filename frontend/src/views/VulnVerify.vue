<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import {
  ShieldCheck,
  Plus,
  RefreshCw,
  Eye,
  Delete,
  Search,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  FileText,
  Globe,
} from '@lucide/vue'
import http from '@/api/http'
import { taskApi, type ScanTask, type TaskListQuery } from '@/api/task'
import { vulnApi, type VulnFinding } from '@/api/risk'
import { scanApi, type ScanTaskStatus } from '@/api/scan'

// ==================== 枚举与常量 ====================

// 任务状态
const taskStatusOptions = [
  { label: '等待中', value: 'pending' },
  { label: '运行中', value: 'running' },
  { label: '已完成', value: 'completed' },
  { label: '失败', value: 'failed' },
]

// 验证方式
const verifyModeOptions = [
  { label: '主动验证', value: 'active', desc: '对目标重新发起漏洞验证扫描' },
  { label: '被动验证', value: 'passive', desc: '基于已有扫描结果进行验证' },
  { label: '浏览器验证', value: 'browser', desc: '使用浏览器模拟访问验证 Web 漏洞' },
]

// 验证结果枚举
type VerifyResult = 'fixed' | 'exists' | 'false_positive' | 'unknown'

const verifyResultLabel: Record<VerifyResult, string> = {
  fixed: '已修复',
  exists: '仍存在',
  false_positive: '误报',
  unknown: '未知',
}

const verifyResultType: Record<VerifyResult, string> = {
  fixed: 'success',
  exists: 'danger',
  false_positive: 'info',
  unknown: 'warning',
}

// 漏洞等级
const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
  { label: '信息', value: 'info' },
]

const severityLabelMap: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const severityTypeMap: Record<string, string> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  info: 'info',
}

// ==================== 工具函数 ====================

const statusLabel = (status: string) => {
  const map: Record<string, string> = {
    pending: '等待中',
    running: '运行中',
    completed: '已完成',
    failed: '失败',
  }
  return map[status] || status || '-'
}

const statusType = (status: string) => {
  const map: Record<string, string> = {
    pending: 'info',
    running: 'primary',
    completed: 'success',
    failed: 'danger',
  }
  return map[status] || 'info'
}

const verifyModeLabel = (mode: string) => {
  const map: Record<string, string> = {
    active: '主动验证',
    passive: '被动验证',
    browser: '浏览器验证',
  }
  return map[mode] || mode || '-'
}

const formatTime = (t: string | null | undefined): string => {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN')
  } catch {
    return '-'
  }
}

// 从任务目标字段中提取主机字符串
function formatTargets(targets: any): string {
  if (!targets) return '-'
  if (Array.isArray(targets)) return targets.join(', ')
  if (typeof targets === 'string') return targets
  try {
    const arr = JSON.parse(targets)
    if (Array.isArray(arr)) return arr.join(', ')
  } catch {
    /* ignore */
  }
  return String(targets)
}

// ==================== 任务列表 ====================

const tasks = ref<ScanTask[]>([])
const totalTasks = ref(0)
const tasksLoading = ref(false)
const taskListQuery = reactive<TaskListQuery & { start_date?: string; end_date?: string }>({
  page: 1,
  page_size: 10,
  name: '',
  status: '',
  task_type: 'vuln_verify',
  start_date: '',
  end_date: '',
})

async function fetchTasks() {
  tasksLoading.value = true
  try {
    const params: any = {
      page: taskListQuery.page,
      page_size: taskListQuery.page_size,
      task_type: 'vuln_verify',
    }
    if (taskListQuery.name) params.name = taskListQuery.name
    if (taskListQuery.status) params.status = taskListQuery.status
    const res = await taskApi.list(params)
    tasks.value = res.items || []
    totalTasks.value = tasks.value.length
  } catch {
    // 错误已在拦截器处理
  } finally {
    tasksLoading.value = false
  }
}

function handleSearch() {
  taskListQuery.page = 1
  fetchTasks()
}

function handleResetFilter() {
  taskListQuery.name = ''
  taskListQuery.status = ''
  taskListQuery.start_date = ''
  taskListQuery.end_date = ''
  taskListQuery.page = 1
  fetchTasks()
}

function handlePageChange(page: number) {
  taskListQuery.page = page
  fetchTasks()
}

async function handleDeleteTask(row: ScanTask) {
  try {
    await ElMessageBox.confirm(`确认删除验证任务「${row.name}」？该操作不可恢复。`, '删除确认', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
    await taskApi.delete(row.id)
    ElMessage.success('任务已删除')
    await fetchTasks()
  } catch {
    // 用户取消或错误
  }
}

// ==================== 新建验证任务弹窗 ====================

const dialogVisible = ref(false)
const formRef = ref<FormInstance | null>(null)
const submitting = ref(false)

interface VerifyFormState {
  name: string
  targets: string
  verify_mode: 'active' | 'passive' | 'browser'
  vuln_ids: string[]
  template_ids: string[]
  timeout: number
  concurrency: number
}

function createDefaultForm(): VerifyFormState {
  return {
    name: '',
    targets: '',
    verify_mode: 'active',
    vuln_ids: [],
    template_ids: [],
    timeout: 300,
    concurrency: 10,
  }
}

const verifyForm = reactive<VerifyFormState>(createDefaultForm())

const formRules: FormRules<VerifyFormState> = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  targets: [{ required: true, message: '请输入目标主机', trigger: 'blur' }],
  verify_mode: [{ required: true, message: '请选择验证方式', trigger: 'change' }],
}

function openCreateDialog() {
  Object.assign(verifyForm, createDefaultForm())
  selectedVulnIds.value = []
  selectedVulnRows.value = []
  dialogVisible.value = true
  // 加载漏洞候选列表与模板列表
  fetchVulnCandidates()
  fetchVulnTemplates()
}

async function handleSubmitVerify() {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (!valid) return
    const targets = (verifyForm.targets || '')
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (targets.length === 0 && selectedVulnIds.value.length === 0) {
      ElMessage.warning('请输入目标主机或选择待验证漏洞')
      return
    }
    submitting.value = true
    try {
      // 构造请求体，同时兼容后端 hosts 字段与任务约定的 targets 字段
      const payload: any = {
        name: verifyForm.name,
        targets,
        hosts: targets,
        mode: verifyForm.verify_mode,
        concurrency: verifyForm.concurrency,
        timeout_ms: verifyForm.timeout * 1000,
      }
      if (selectedVulnIds.value.length > 0) payload.vuln_ids = selectedVulnIds.value
      if (verifyForm.template_ids.length > 0) payload.templates = verifyForm.template_ids

      // 调用后端漏洞验证接口
      const res: any = await http.post('/scan/vuln', payload)
      if (res?.task_id) {
        ElMessage.success('验证任务已提交')
      } else {
        ElMessage.success('验证任务已提交')
      }
      dialogVisible.value = false
      await fetchTasks()
    } catch {
      // 错误已在拦截器处理
    } finally {
      submitting.value = false
    }
  })
}

// ==================== 漏洞候选选择（el-table 多选） ====================

const vulnCandidates = ref<VulnFinding[]>([])
const vulnCandidatesLoading = ref(false)
const vulnFilter = reactive({ host: '', severity: '', name: '', cve_id: '' })
const selectedVulnIds = ref<string[]>([])
const selectedVulnRows = ref<VulnFinding[]>([])

async function fetchVulnCandidates() {
  vulnCandidatesLoading.value = true
  try {
    const params: any = { page: 1, page_size: 100 }
    if (vulnFilter.host) params.host = vulnFilter.host
    if (vulnFilter.severity) params.severity = vulnFilter.severity
    if (vulnFilter.name) params.name = vulnFilter.name
    if (vulnFilter.cve_id) params.cve_id = vulnFilter.cve_id
    const res = await vulnApi.list(params)
    vulnCandidates.value = res.items || []
  } catch {
    vulnCandidates.value = []
  } finally {
    vulnCandidatesLoading.value = false
  }
}

function handleVulnSelectionChange(selection: VulnFinding[]) {
  selectedVulnRows.value = selection
  selectedVulnIds.value = selection.map((v) => v.id)
}

// ==================== 漏洞模板选择（el-select 多选） ====================

interface VulnTemplate {
  id: string
  name: string
  severity: string
  cve: string | null
  category: string | null
  enabled: boolean
}

const vulnTemplates = ref<VulnTemplate[]>([])
const vulnTemplatesLoading = ref(false)

async function fetchVulnTemplates() {
  vulnTemplatesLoading.value = true
  try {
    const res: any = await http.get('/risk/vuln-templates', { params: { page: 1, page_size: 200 } })
    vulnTemplates.value = (res?.items || []).map((t: any) => ({
      id: t.id,
      name: t.name,
      severity: t.severity,
      cve: t.cve,
      category: t.category,
      enabled: t.enabled,
    }))
  } catch {
    vulnTemplates.value = []
  } finally {
    vulnTemplatesLoading.value = false
  }
}

// ==================== 验证结果详情抽屉 ====================

const drawerVisible = ref(false)
const drawerLoading = ref(false)
const drawerTask = ref<ScanTask | null>(null)
const drawerStatus = ref<ScanTaskStatus | null>(null)
const drawerFindings = ref<any[]>([])
const drawerReport = ref<any>(null)
const activeResultTab = ref<'results' | 'report' | 'browser'>('results')
const resultPollTimer: { value: ReturnType<typeof setInterval> | null } = { value: null }

// 浏览器验证结果（从 findings 中提取）
const browserResults = computed(() => {
  return drawerFindings.value
    .map((f) => {
      const raw = f.raw_data || f || {}
      const url = raw.request_url || raw.url || f.host || ''
      const statusCode = raw.response_code || raw.http_status || raw.status_code || '-'
      const summary = raw.response_summary || raw.banner || raw.description || raw.title || ''
      return { url, status_code: statusCode, summary }
    })
    .filter((r) => r.url || r.summary)
})

// 统计卡片数据
const resultStats = computed(() => {
  const total = drawerFindings.value.length
  let fixed = 0
  let exists = 0
  let falsePositive = 0
  let unknown = 0
  for (const f of drawerFindings.value) {
    const r = deriveVerifyResult(f)
    if (r === 'fixed') fixed++
    else if (r === 'exists') exists++
    else if (r === 'false_positive') falsePositive++
    else unknown++
  }
  return { total, fixed, exists, false_positive: falsePositive, unknown }
})

// 根据发现数据推导验证结果（后端无该字段时用合理规则）
function deriveVerifyResult(finding: any): VerifyResult {
  // 优先使用显式字段
  const explicit = finding.verify_result || finding.result || finding.status
  if (explicit && verifyResultLabel[explicit as VerifyResult]) {
    return explicit as VerifyResult
  }
  // 基于 state / success 推导
  const state = (finding.state || '').toLowerCase()
  const success = finding.success
  if (state === 'fixed' || state === 'remediated') return 'fixed'
  if (state === 'false_positive' || state === 'fp') return 'false_positive'
  if (state === 'vulnerable' || state === 'exists' || success === true) return 'exists'
  if (success === false) return 'fixed'
  return 'unknown'
}

async function openResultDrawer(row: ScanTask) {
  drawerVisible.value = true
  drawerLoading.value = true
  drawerTask.value = row
  activeResultTab.value = 'results'
  try {
    const [statusRes, findingsRes, reportRes] = await Promise.allSettled([
      scanApi.getStatus(row.id),
      http.get(`/scan/vuln/findings/${row.id}`),
      http.get(`/scan/vuln/report/${row.id}`),
    ])
    drawerStatus.value = statusRes.status === 'fulfilled' ? statusRes.value : null
    const findingsData: any = findingsRes.status === 'fulfilled' ? findingsRes.value : null
    drawerFindings.value = findingsData?.findings || []
    drawerReport.value = reportRes.status === 'fulfilled' ? reportRes.value : null

    // 若任务仍在运行则启动轮询
    stopResultPolling()
    if (drawerStatus.value && ['pending', 'running'].includes(drawerStatus.value.status)) {
      startResultPolling(row.id)
    }
  } catch {
    // 错误已在拦截器处理
  } finally {
    drawerLoading.value = false
  }
}

function startResultPolling(taskId: string, interval = 3000) {
  stopResultPolling()
  resultPollTimer.value = setInterval(async () => {
    try {
      drawerStatus.value = await scanApi.getStatus(taskId)
      if (drawerStatus.value && !['pending', 'running'].includes(drawerStatus.value.status)) {
        stopResultPolling()
        // 刷新结果
        try {
          const findingsData: any = await http.get(`/scan/vuln/findings/${taskId}`)
          drawerFindings.value = findingsData?.findings || []
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
  }, interval)
}

function stopResultPolling() {
  if (resultPollTimer.value) {
    clearInterval(resultPollTimer.value)
    resultPollTimer.value = null
  }
}

function handleDrawerClose() {
  stopResultPolling()
  drawerVisible.value = false
  drawerTask.value = null
  drawerStatus.value = null
  drawerFindings.value = []
  drawerReport.value = null
  logDialogVisible.value = false
}

// ==================== 验证日志详情弹窗 ====================

const logDialogVisible = ref(false)
const currentFinding = ref<any>(null)

function openLogDialog(finding: any) {
  currentFinding.value = finding
  logDialogVisible.value = true
}

const findingDetailText = computed(() => {
  const f = currentFinding.value
  if (!f) return ''
  const raw = f.raw_data || f
  const lines: string[] = []
  lines.push(`漏洞名称: ${raw.title || raw.name || f.title || '-'}`)
  lines.push(`目标主机: ${f.host || raw.target || '-'}`)
  if (f.port || raw.port) lines.push(`端口: ${f.port || raw.port}`)
  if (raw.cve_id || f.cve_id) lines.push(`CVE: ${raw.cve_id || f.cve_id}`)
  lines.push(`原始等级: ${severityLabelMap[(raw.severity || f.severity || '').toLowerCase()] || raw.severity || f.severity || '-'}`)
  lines.push(`验证结果: ${verifyResultLabel[deriveVerifyResult(f)]}`)
  lines.push(`验证时间: ${formatTime(f.created_at || raw.verified_at)}`)
  if (raw.description) lines.push(`\n描述:\n${raw.description}`)
  if (raw.evidence) lines.push(`\n证据:\n${raw.evidence}`)
  if (raw.fix_advice) lines.push(`\n修复建议:\n${raw.fix_advice}`)
  if (raw.request_url) lines.push(`\n请求 URL: ${raw.request_url}`)
  if (raw.request_method) lines.push(`请求方法: ${raw.request_method}`)
  if (raw.response_code) lines.push(`HTTP 状态码: ${raw.response_code}`)
  if (raw.response_summary) lines.push(`响应摘要:\n${raw.response_summary}`)
  return lines.join('\n')
})

// ==================== 漏洞知识库联动（CVE 搜索） ====================

const kbDialogVisible = ref(false)
const cveKeyword = ref('')
const cveSearchLoading = ref(false)
const cveSearchResults = ref<any[]>([])
const cveDetail = ref<any>(null)

function openKbDialog() {
  kbDialogVisible.value = true
  cveKeyword.value = ''
  cveSearchResults.value = []
  cveDetail.value = null
}

async function handleCveSearch() {
  if (!cveKeyword.value.trim()) {
    ElMessage.warning('请输入 CVE 编号或关键词')
    return
  }
  cveSearchLoading.value = true
  cveDetail.value = null
  try {
    const res: any = await http.get('/vulndb/cves/search', {
      params: { keyword: cveKeyword.value.trim(), limit: 20 },
    })
    cveSearchResults.value = res?.data || []
    if (cveSearchResults.value.length === 0) {
      ElMessage.info('未找到匹配的 CVE 记录')
    }
  } catch {
    cveSearchResults.value = []
  } finally {
    cveSearchLoading.value = false
  }
}

async function viewCveDetail(cveId: string) {
  try {
    const res: any = await http.get(`/vulndb/cves/${cveId}`)
    cveDetail.value = res
  } catch {
    cveDetail.value = null
  }
}

// ==================== 生命周期 ====================

onMounted(() => {
  fetchTasks()
})

onBeforeUnmount(() => {
  stopResultPolling()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 漏洞验证任务列表 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <div class="mb-4 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <ShieldCheck class="h-5 w-5 text-cyan-400" />
          <h2 class="text-base font-medium text-slate-200">漏洞验证任务</h2>
          <span class="text-xs text-slate-500">6.10 漏洞验证</span>
        </div>
        <div class="flex items-center gap-2">
          <el-button type="primary" :icon="Plus" @click="openCreateDialog">新建验证任务</el-button>
          <el-button :icon="RefreshCw" circle size="small" @click="fetchTasks" />
          <el-button :icon="Search" @click="openKbDialog">漏洞知识库</el-button>
        </div>
      </div>

      <!-- 筛选区 -->
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <el-input
          v-model="taskListQuery.name"
          placeholder="按任务名称搜索"
          clearable
          style="width: 220px"
          @keyup.enter="handleSearch"
        />
        <el-select
          v-model="taskListQuery.status"
          placeholder="按状态筛选"
          clearable
          style="width: 160px"
        >
          <el-option
            v-for="opt in taskStatusOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-date-picker
          v-model="taskListQuery.start_date"
          type="date"
          placeholder="开始日期"
          value-format="YYYY-MM-DD"
          style="width: 160px"
        />
        <el-date-picker
          v-model="taskListQuery.end_date"
          type="date"
          placeholder="结束日期"
          value-format="YYYY-MM-DD"
          style="width: 160px"
        />
        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button @click="handleResetFilter">重置</el-button>
      </div>

      <!-- 任务列表 -->
      <el-table
        :data="tasks"
        v-loading="tasksLoading"
        stripe
        border
        max-height="520"
        style="width: 100%"
      >
        <el-table-column prop="name" label="任务名称" min-width="160" show-overflow-tooltip />
        <el-table-column label="目标主机" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ formatTargets(row.targets) }}</template>
        </el-table-column>
        <el-table-column label="验证方式" width="120">
          <template #default="{ row }">
            {{ verifyModeLabel(row.params?.mode || row.params?.verify_mode) }}
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="90">
          <template #default="{ row }">{{ (row.progress || 0).toFixed(1) }}%</template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="started_at" label="开始时间" width="170">
          <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="finished_at" label="完成时间" width="170">
          <template #default="{ row }">{{ formatTime(row.finished_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="Eye" @click="openResultDrawer(row)">
              查看结果
            </el-button>
            <el-button link type="danger" :icon="Delete" @click="handleDeleteTask(row)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="taskListQuery.page"
          v-model:page-size="taskListQuery.page_size"
          :total="totalTasks"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="handlePageChange"
          @size-change="handlePageChange"
        />
      </div>
    </div>

    <!-- 新建验证任务弹窗 -->
    <el-dialog
      v-model="dialogVisible"
      title="新建漏洞验证任务"
      width="900px"
      top="5vh"
      destroy-on-close
      class="dark-dialog"
    >
      <el-form
        ref="formRef"
        :model="verifyForm"
        :rules="formRules"
        label-width="110px"
        label-position="right"
      >
        <!-- 任务名称 -->
        <el-form-item label="任务名称" prop="name" required>
          <el-input v-model="verifyForm.name" placeholder="请输入任务名称" maxlength="64" show-word-limit />
        </el-form-item>

        <!-- 目标主机 -->
        <el-form-item label="目标主机" prop="targets" required>
          <el-input
            v-model="verifyForm.targets"
            type="textarea"
            :rows="3"
            placeholder="支持 IP / 域名，多个用逗号或换行分隔，例: 192.168.1.10, example.com"
          />
        </el-form-item>

        <!-- 验证方式 -->
        <el-form-item label="验证方式" prop="verify_mode" required>
          <el-radio-group v-model="verifyForm.verify_mode">
            <el-radio
              v-for="opt in verifyModeOptions"
              :key="opt.value"
              :value="opt.value"
            >
              {{ opt.label }}
            </el-radio>
          </el-radio-group>
          <div class="mt-1 text-xs text-slate-500">
            {{ verifyModeOptions.find((o) => o.value === verifyForm.verify_mode)?.desc }}
          </div>
        </el-form-item>

        <!-- 漏洞选择 -->
        <el-form-item label="漏洞选择">
          <div class="w-full">
            <div class="mb-2 flex flex-wrap items-center gap-2">
              <el-input
                v-model="vulnFilter.host"
                placeholder="按主机筛选"
                clearable
                style="width: 160px"
              />
              <el-select
                v-model="vulnFilter.severity"
                placeholder="按等级筛选"
                clearable
                style="width: 140px"
              >
                <el-option
                  v-for="opt in severityOptions"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
              <el-input
                v-model="vulnFilter.name"
                placeholder="按漏洞名称筛选"
                clearable
                style="width: 180px"
              />
              <el-input
                v-model="vulnFilter.cve_id"
                placeholder="按 CVE 筛选"
                clearable
                style="width: 160px"
              />
              <el-button type="primary" size="small" :icon="Search" @click="fetchVulnCandidates">
                查询
              </el-button>
            </div>
            <el-table
              :data="vulnCandidates"
              v-loading="vulnCandidatesLoading"
              stripe
              border
              max-height="260"
              style="width: 100%"
              @selection-change="handleVulnSelectionChange"
              :row-key="(row: any) => row.id"
            >
              <el-table-column type="selection" width="50" />
              <el-table-column prop="title" label="漏洞名称" min-width="180" show-overflow-tooltip />
              <el-table-column prop="target_host" label="主机" width="140" show-overflow-tooltip />
              <el-table-column prop="severity" label="等级" width="80">
                <template #default="{ row }">
                  <el-tag :type="severityTypeMap[(row.severity || '').toLowerCase()]" size="small">
                    {{ severityLabelMap[(row.severity || '').toLowerCase()] || row.severity }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="cve_id" label="CVE" width="140" show-overflow-tooltip />
            </el-table>
            <div class="mt-1 text-xs text-slate-500">
              已选择 {{ selectedVulnIds.length }} 个漏洞（也可仅通过目标主机 + 模板进行验证）
            </div>
          </div>
        </el-form-item>

        <!-- 漏洞模板选择 -->
        <el-form-item label="漏洞模板">
          <el-select
            v-model="verifyForm.template_ids"
            multiple
            filterable
            clearable
            placeholder="选择漏洞模板（可多选）"
            style="width: 100%"
            :loading="vulnTemplatesLoading"
          >
            <el-option
              v-for="t in vulnTemplates"
              :key="t.id"
              :label="`${t.name}${t.cve ? ' (' + t.cve + ')' : ''}`"
              :value="t.id"
            >
              <div class="flex items-center justify-between">
                <span>{{ t.name }}</span>
                <el-tag :type="severityTypeMap[(t.severity || '').toLowerCase()]" size="small">
                  {{ severityLabelMap[(t.severity || '').toLowerCase()] || t.severity }}
                </el-tag>
              </div>
            </el-option>
          </el-select>
        </el-form-item>

        <!-- 超时与并发 -->
        <el-form-item label="验证超时(秒)">
          <el-input-number v-model="verifyForm.timeout" :min="10" :max="3600" />
        </el-form-item>
        <el-form-item label="并发数">
          <el-input-number v-model="verifyForm.concurrency" :min="1" :max="200" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmitVerify">
          提交验证
        </el-button>
      </template>
    </el-dialog>

    <!-- 验证结果详情抽屉 -->
    <el-drawer
      v-model="drawerVisible"
      title="验证结果详情"
      direction="rtl"
      size="70%"
      destroy-on-close
      @close="handleDrawerClose"
    >
      <div v-loading="drawerLoading" class="space-y-4">
        <!-- 任务基本信息 -->
        <div class="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <div class="flex flex-wrap items-center gap-x-8 gap-y-2 text-sm">
            <div><span class="text-slate-500">任务名称：</span>{{ drawerTask?.name || '-' }}</div>
            <div><span class="text-slate-500">目标主机：</span>{{ formatTargets(drawerTask?.targets) }}</div>
            <div>
              <span class="text-slate-500">验证方式：</span>
              {{ verifyModeLabel(drawerTask?.params?.mode || drawerTask?.params?.verify_mode) }}
            </div>
            <div>
              <span class="text-slate-500">状态：</span>
              <el-tag :type="statusType(drawerStatus?.status || drawerTask?.status || '')" size="small">
                {{ statusLabel(drawerStatus?.status || drawerTask?.status || '') }}
              </el-tag>
            </div>
          </div>
        </div>

        <!-- 统计卡片 -->
        <div class="grid grid-cols-2 gap-3 md:grid-cols-5">
          <div class="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <div class="flex items-center gap-2 text-slate-400">
              <FileText class="h-4 w-4" />
              <span class="text-xs">验证总数</span>
            </div>
            <div class="mt-2 text-2xl font-bold text-slate-100">{{ resultStats.total }}</div>
          </div>
          <div class="rounded-lg border border-emerald-800/50 bg-emerald-900/10 p-4">
            <div class="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 class="h-4 w-4" />
              <span class="text-xs">已修复</span>
            </div>
            <div class="mt-2 text-2xl font-bold text-emerald-400">{{ resultStats.fixed }}</div>
          </div>
          <div class="rounded-lg border border-rose-800/50 bg-rose-900/10 p-4">
            <div class="flex items-center gap-2 text-rose-400">
              <AlertTriangle class="h-4 w-4" />
              <span class="text-xs">仍存在</span>
            </div>
            <div class="mt-2 text-2xl font-bold text-rose-400">{{ resultStats.exists }}</div>
          </div>
          <div class="rounded-lg border border-slate-700 bg-slate-800/40 p-4">
            <div class="flex items-center gap-2 text-slate-400">
              <XCircle class="h-4 w-4" />
              <span class="text-xs">误报</span>
            </div>
            <div class="mt-2 text-2xl font-bold text-slate-300">{{ resultStats.false_positive }}</div>
          </div>
          <div class="rounded-lg border border-amber-800/50 bg-amber-900/10 p-4">
            <div class="flex items-center gap-2 text-amber-400">
              <HelpCircle class="h-4 w-4" />
              <span class="text-xs">未知</span>
            </div>
            <div class="mt-2 text-2xl font-bold text-amber-400">{{ resultStats.unknown }}</div>
          </div>
        </div>

        <!-- 结果 Tab -->
        <el-tabs v-model="activeResultTab">
          <el-tab-pane label="验证结果列表" name="results">
            <el-table
              :data="drawerFindings"
              stripe
              border
              max-height="420"
              style="width: 100%"
            >
              <el-table-column label="漏洞名称" min-width="200" show-overflow-tooltip>
                <template #default="{ row }">
                  {{ row.raw_data?.title || row.title || row.raw_data?.name || '-' }}
                </template>
              </el-table-column>
              <el-table-column label="目标主机" width="150" show-overflow-tooltip>
                <template #default="{ row }">{{ row.host || row.raw_data?.target || '-' }}</template>
              </el-table-column>
              <el-table-column label="原始等级" width="100">
                <template #default="{ row }">
                  <el-tag
                    :type="severityTypeMap[((row.severity || row.raw_data?.severity) || '').toLowerCase()]"
                    size="small"
                  >
                    {{
                      severityLabelMap[((row.severity || row.raw_data?.severity) || '').toLowerCase()] ||
                        row.severity ||
                        row.raw_data?.severity ||
                        '-'
                    }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="验证结果" width="110">
                <template #default="{ row }">
                  <el-tag :type="verifyResultType[deriveVerifyResult(row)]" size="small">
                    {{ verifyResultLabel[deriveVerifyResult(row)] }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="验证时间" width="170">
                <template #default="{ row }">
                  {{ formatTime(row.created_at || row.raw_data?.verified_at) }}
                </template>
              </el-table-column>
              <el-table-column label="操作" width="100" fixed="right">
                <template #default="{ row }">
                  <el-button link type="primary" :icon="Eye" @click="openLogDialog(row)">
                    详情
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="验证报告" name="report">
            <div v-if="drawerReport" class="space-y-3">
              <div class="text-sm text-slate-400">
                报告任务 ID：{{ drawerReport.task_id }}，共 {{ drawerReport.count || 0 }} 条发现
              </div>
              <pre
                class="max-h-[420px] overflow-auto rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs text-slate-300"
              >{{ JSON.stringify(drawerReport, null, 2) }}</pre>
            </div>
            <el-empty v-else description="暂无报告数据" />
          </el-tab-pane>

          <el-tab-pane label="浏览器验证结果" name="browser">
            <el-table
              :data="browserResults"
              stripe
              border
              max-height="420"
              style="width: 100%"
            >
              <el-table-column label="URL" min-width="260" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="flex items-center gap-1">
                    <Globe class="h-3.5 w-3.5 text-cyan-400" />
                    {{ row.url || '-' }}
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="HTTP 状态码" width="130">
                <template #default="{ row }">
                  <el-tag
                    :type="String(row.status_code).startsWith('2') ? 'success' : 'warning'"
                    size="small"
                  >
                    {{ row.status_code }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="响应摘要" min-width="300" show-overflow-tooltip>
                <template #default="{ row }">{{ row.summary || '-' }}</template>
              </el-table-column>
            </el-table>
            <el-empty
              v-if="browserResults.length === 0"
              description="暂无浏览器验证结果（仅浏览器验证方式会产生该数据）"
            />
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>

    <!-- 验证日志详情弹窗 -->
    <el-dialog
      v-model="logDialogVisible"
      title="验证详情日志"
      width="680px"
      destroy-on-close
      class="dark-dialog"
    >
      <pre
        class="max-h-[500px] overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs text-slate-300"
      >{{ findingDetailText }}</pre>
    </el-dialog>

    <!-- 漏洞知识库弹窗 -->
    <el-dialog
      v-model="kbDialogVisible"
      title="漏洞知识库（CVE 检索）"
      width="900px"
      top="8vh"
      destroy-on-close
      class="dark-dialog"
    >
      <div class="space-y-3">
        <div class="flex items-center gap-2">
          <el-input
            v-model="cveKeyword"
            placeholder="输入 CVE 编号或关键词，例: CVE-2021-44228"
            clearable
            style="flex: 1"
            @keyup.enter="handleCveSearch"
          />
          <el-button type="primary" :icon="Search" :loading="cveSearchLoading" @click="handleCveSearch">
            搜索
          </el-button>
        </div>

        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <!-- 搜索结果列表 -->
          <div>
            <div class="mb-2 text-sm text-slate-400">搜索结果（{{ cveSearchResults.length }}）</div>
            <el-table
              :data="cveSearchResults"
              v-loading="cveSearchLoading"
              stripe
              border
              max-height="440"
              style="width: 100%"
              highlight-current-row
              @current-change="(row: any) => row && viewCveDetail(row.id)"
            >
              <el-table-column label="CVE" min-width="160" show-overflow-tooltip>
                <template #default="{ row }">{{ row.id }}</template>
              </el-table-column>
              <el-table-column label="等级" width="80">
                <template #default="{ row }">
                  <el-tag
                    :type="severityTypeMap[(row.severity || '').toLowerCase()]"
                    size="small"
                  >
                    {{ severityLabelMap[(row.severity || '').toLowerCase()] || row.severity || '-' }}
                  </el-tag>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <!-- 详情 -->
          <div>
            <div class="mb-2 text-sm text-slate-400">漏洞详情</div>
            <div
              v-if="cveDetail"
              class="space-y-2 rounded-lg border border-slate-800 bg-slate-900/40 p-4 text-sm"
            >
              <div>
                <div class="text-xs text-slate-500">名称 / CVE</div>
                <div class="font-medium text-slate-200">{{ cveDetail.id }}</div>
              </div>
              <div>
                <div class="text-xs text-slate-500">等级</div>
                <el-tag
                  :type="severityTypeMap[(cveDetail.severity || '').toLowerCase()]"
                  size="small"
                >
                  {{ severityLabelMap[(cveDetail.severity || '').toLowerCase()] || cveDetail.severity || '-' }}
                </el-tag>
              </div>
              <div>
                <div class="text-xs text-slate-500">CVSS v3</div>
                <div class="text-slate-200">{{ cveDetail.cvss_v3 ?? '-' }}</div>
              </div>
              <div>
                <div class="text-xs text-slate-500">描述</div>
                <div class="text-slate-300">{{ cveDetail.description || '-' }}</div>
              </div>
              <div>
                <div class="text-xs text-slate-500">发布时间</div>
                <div class="text-slate-300">{{ formatTime(cveDetail.published) }}</div>
              </div>
              <div>
                <div class="text-xs text-slate-500">参考链接</div>
                <div class="break-all text-slate-300">
                  <template v-if="Array.isArray(cveDetail.references)">
                    <div v-for="(ref, i) in cveDetail.references" :key="i" class="truncate">
                      {{ typeof ref === 'string' ? ref : ref?.url || JSON.stringify(ref) }}
                    </div>
                  </template>
                  <span v-else>-</span>
                </div>
              </div>
            </div>
            <el-empty v-else description="点击左侧记录查看详情" :image-size="80" />
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>
