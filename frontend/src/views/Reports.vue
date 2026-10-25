<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { FileText, Download, Plus, Trash2, Calendar, Clock } from '@lucide/vue'
import { taskApi, type ScanTask } from '@/api/task'
import {
  reportApi,
  type ReportFormat,
  type ReportType,
} from '@/api/system'

// 本地存储的已生成报表（服务端暂未提供报表列表接口，使用本地持久化）
interface LocalReport {
  id: string
  task_id: string
  task_name: string
  task_type: string
  type: ReportType
  format: ReportFormat
  generated_at: string
  size_bytes: number
}

const STORAGE_KEY = 'argus_generated_reports'

const tasks = ref<ScanTask[]>([])
const loading = ref(false)
const reports = ref<LocalReport[]>([])

// 生成表单
const generateDialogVisible = ref(false)
const selectedTaskId = ref('')
const reportType = ref<ReportType>('comprehensive')
const reportFormat = ref<ReportFormat>('html')
const generating = ref(false)

// 定时报表配置
const scheduleEnabled = ref(false)
const scheduleCron = ref('0 0 2 * * ?')

// 报表模板
const templates = [
  { label: '默认模板', value: 'default' },
  { label: '精简模板', value: 'simple' },
  { label: '详细模板', value: 'detailed' },
]
const selectedTemplate = ref('default')

// 报表类型选项
const reportTypeOptions: { label: string; value: ReportType }[] = [
  { label: '综合报告', value: 'comprehensive' },
  { label: '漏洞报告', value: 'vulnerability' },
  { label: '基线报告', value: 'baseline' },
  { label: '弱口令报告', value: 'weak_password' },
]

// 报表格式选项
const reportFormatOptions: { label: string; value: ReportFormat }[] = [
  { label: 'PDF', value: 'pdf' },
  { label: 'HTML', value: 'html' },
  { label: 'Excel (XLSX)', value: 'xlsx' },
  { label: 'XML', value: 'xml' },
]

// 从本地存储加载报表列表
function loadReports() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    reports.value = raw ? (JSON.parse(raw) as LocalReport[]) : []
  } catch {
    reports.value = []
  }
}

function persistReports() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(reports.value))
}

async function loadTasks() {
  loading.value = true
  try {
    const res = await taskApi.list({ page: 1, page_size: 100 })
    // 只显示已完成或有结果的任务
    tasks.value = res.items.filter(
      (t) => t.status === 'completed' || t.status === 'stopped' || t.status === 'failed',
    )
  } catch {
    // 错误已在拦截器处理
  } finally {
    loading.value = false
  }
}

function openGenerateDialog() {
  selectedTaskId.value = ''
  reportType.value = 'comprehensive'
  reportFormat.value = 'html'
  selectedTemplate.value = 'default'
  scheduleEnabled.value = false
  scheduleCron.value = '0 0 2 * * ?'
  generateDialogVisible.value = true
}

async function handleGenerate() {
  if (!selectedTaskId.value) {
    ElMessage.warning('请先选择一个任务')
    return
  }
  generating.value = true
  try {
    const blob = (await reportApi.generate({
      task_id: selectedTaskId.value,
      format: reportFormat.value,
      type: reportType.value,
    })) as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const task = tasks.value.find((t) => t.id === selectedTaskId.value)
    a.download = `report_${task?.name || selectedTaskId.value.slice(0, 8)}.${reportFormat.value}`
    a.click()
    URL.revokeObjectURL(url)

    // 记录到本地报表列表
    const newReport: LocalReport = {
      id: `${Date.now()}`,
      task_id: selectedTaskId.value,
      task_name: task?.name || '未知任务',
      task_type: task?.task_type || '',
      type: reportType.value,
      format: reportFormat.value,
      generated_at: new Date().toISOString(),
      size_bytes: blob.size,
    }
    reports.value.unshift(newReport)
    persistReports()
    ElMessage.success('报表生成成功')
    generateDialogVisible.value = false
  } catch {
    // 错误已在拦截器处理
  } finally {
    generating.value = false
  }
}

async function handleDownload(report: LocalReport) {
  try {
    const blob = (await reportApi.download(report.task_id, report.format)) as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.task_name}_${report.type}.${report.format}`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('下载成功')
  } catch {
    // 错误已在拦截器处理
  }
}

async function handleDelete(report: LocalReport) {
  try {
    await ElMessageBox.confirm(`确定删除报表「${report.task_name}」吗？`, '删除确认', {
      type: 'warning',
    })
    reports.value = reports.value.filter((r) => r.id !== report.id)
    persistReports()
    ElMessage.success('已删除')
  } catch {
    // 用户取消
  }
}

// 任务状态映射
const statusType = (status: string) => {
  const map: Record<string, string> = {
    pending: 'info',
    running: 'primary',
    paused: 'warning',
    completed: 'success',
    stopped: 'info',
    failed: 'danger',
  }
  return map[status] || 'info'
}

const statusLabel = (status: string) => {
  const map: Record<string, string> = {
    pending: '等待中',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    stopped: '已停止',
    failed: '失败',
  }
  return map[status] || status
}

const taskTypeLabel = (type: string) => {
  const map: Record<string, string> = {
    port_scan: '端口扫描',
    host_discovery: '主机发现',
    bruteforce: '弱口令猜解',
    baseline_check: '基线核查',
    system_scan: '系统扫描',
    app_scan: '应用扫描',
    db_scan: '数据库扫描',
    image_scan: '镜像扫描',
    mobile_scan: '移动扫描',
    vuln_verify: '漏洞验证',
    fingerprint: '指纹识别',
    vuln_detect: '漏洞检测',
    ics_scan: '工控扫描',
    passive_scan: '被动扫描',
  }
  return map[type] || type
}

const reportTypeLabel = (type: string) => {
  const map: Record<string, string> = {
    comprehensive: '综合报告',
    vulnerability: '漏洞报告',
    baseline: '基线报告',
    weak_password: '弱口令报告',
  }
  return map[type] || type
}

const reportFormatLabel = (format: string) => format.toUpperCase()

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let n = bytes
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(1)} ${units[i]}`
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

// 当前选中任务（用于展示信息）
const selectedTask = computed(() => tasks.value.find((t) => t.id === selectedTaskId.value))

onMounted(() => {
  loadTasks()
  loadReports()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 顶部操作栏 -->
    <div class="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <div class="flex items-center gap-2">
        <FileText class="h-5 w-5 text-cyan-400" />
        <h2 class="text-base font-medium text-slate-200">报表管理</h2>
      </div>
      <el-button type="primary" :icon="Plus" @click="openGenerateDialog">
        新建报表
      </el-button>
    </div>

    <!-- 报表列表 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <h3 class="mb-3 text-base font-medium text-slate-200">已生成报表</h3>
      <el-table :data="reports" stripe style="width: 100%">
        <el-table-column prop="task_name" label="任务名称" min-width="160" show-overflow-tooltip />
        <el-table-column prop="task_type" label="任务类型" width="120">
          <template #default="{ row }">{{ taskTypeLabel(row.task_type) }}</template>
        </el-table-column>
        <el-table-column prop="type" label="报表类型" width="120">
          <template #default="{ row }">{{ reportTypeLabel(row.type) }}</template>
        </el-table-column>
        <el-table-column prop="format" label="格式" width="80">
          <template #default="{ row }">
            <el-tag size="small">{{ reportFormatLabel(row.format) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="generated_at" label="生成时间" width="180">
          <template #default="{ row }">{{ formatTime(row.generated_at) }}</template>
        </el-table-column>
        <el-table-column prop="size_bytes" label="大小" width="100">
          <template #default="{ row }">{{ formatBytes(row.size_bytes) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="Download" @click="handleDownload(row)">
              下载
            </el-button>
            <el-button link type="danger" :icon="Trash2" @click="handleDelete(row)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <p v-if="reports.length === 0" class="py-6 text-center text-sm text-slate-500">
        暂无已生成的报表，点击「新建报表」开始生成
      </p>
    </div>

    <!-- 可用任务列表 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <h3 class="mb-3 text-base font-medium text-slate-200">可生成报表的任务</h3>
      <el-table :data="tasks" v-loading="loading" stripe style="width: 100%">
        <el-table-column prop="name" label="任务名称" min-width="160" />
        <el-table-column prop="task_type" label="类型" width="120">
          <template #default="{ row }">{{ taskTypeLabel(row.task_type) }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="80">
          <template #default="{ row }">{{ row.progress.toFixed(0) }}%</template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button
              link
              type="primary"
              :icon="FileText"
              @click="selectedTaskId = row.id; openGenerateDialog()"
            >
              生成报表
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 新建报表弹窗 -->
    <el-dialog v-model="generateDialogVisible" title="新建报表" width="600px">
      <el-form label-width="110px" label-position="right">
        <el-form-item label="选择任务" required>
          <el-select
            v-model="selectedTaskId"
            placeholder="请选择已完成或已停止的扫描任务"
            filterable
            style="width: 100%"
          >
            <el-option
              v-for="t in tasks"
              :key="t.id"
              :label="`${t.name} (${taskTypeLabel(t.task_type)})`"
              :value="t.id"
            >
              <div class="flex items-center justify-between">
                <span>{{ t.name }} ({{ taskTypeLabel(t.task_type) }})</span>
                <el-tag :type="statusType(t.status)" size="small">
                  {{ statusLabel(t.status) }}
                </el-tag>
              </div>
            </el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="报表类型">
          <el-radio-group v-model="reportType">
            <el-radio
              v-for="opt in reportTypeOptions"
              :key="opt.value"
              :value="opt.value"
            >
              {{ opt.label }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="报表格式">
          <el-radio-group v-model="reportFormat">
            <el-radio
              v-for="opt in reportFormatOptions"
              :key="opt.value"
              :value="opt.value"
            >
              {{ opt.label }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="报表模板">
          <el-select v-model="selectedTemplate" style="width: 100%">
            <el-option
              v-for="tpl in templates"
              :key="tpl.value"
              :label="tpl.label"
              :value="tpl.value"
            />
          </el-select>
        </el-form-item>

        <!-- 定时报表配置（可选） -->
        <el-divider content-position="left">
          <span class="flex items-center gap-1 text-sm">
            <Clock class="h-4 w-4" /> 定时报表（可选）
          </span>
        </el-divider>
        <el-form-item label="启用定时">
          <el-switch v-model="scheduleEnabled" />
          <span class="ml-2 text-xs text-slate-500">按计划自动生成报表</span>
        </el-form-item>
        <el-form-item v-if="scheduleEnabled" label="Cron 表达式">
          <el-input v-model="scheduleCron" placeholder="如：0 0 2 * * ?（每天凌晨2点）">
            <template #prefix>
              <Calendar class="h-4 w-4 text-slate-500" />
            </template>
          </el-input>
        </el-form-item>
      </el-form>

      <!-- 预览信息 -->
      <div v-if="selectedTask" class="mt-2 rounded-lg border border-slate-700 bg-slate-800/50 p-3 text-sm text-slate-400">
        <div class="mb-1 font-medium text-slate-300">任务信息预览</div>
        <div>任务：{{ selectedTask.name }}（{{ taskTypeLabel(selectedTask.task_type) }}）</div>
        <div>进度：{{ selectedTask.progress.toFixed(0) }}% · 状态：{{ statusLabel(selectedTask.status) }}</div>
      </div>

      <template #footer>
        <el-button @click="generateDialogVisible = false">取消</el-button>
        <el-button type="primary" :icon="Download" :loading="generating" @click="handleGenerate">
          生成并下载
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
