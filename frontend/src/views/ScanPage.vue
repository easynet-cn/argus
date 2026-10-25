<script setup lang="ts">
import { ref, computed, reactive, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import {
  Rocket,
  RefreshCw,
  Eye,
  CircleStop,
  Plus,
  Delete,
  Upload,
  Copy,
  Lock,
  Unlock,
  TrendingUp,
  Pencil,
  Play,
  Pause,
  History,
  ChevronDown,
  Download,
  FileText,
} from '@lucide/vue'
import { taskApi, type ScanTask, type TaskListQuery } from '@/api/task'
import { scanApi, type ScanTaskStatus, type ScanResultsResponse, type ScanResult, type PortTemplate, type ParamTemplate, type ScanNode, type ScanTemplateBrief } from '@/api/scan'
import { reportApi } from '@/api/system'
import { useAssetStore } from '@/stores/asset'

const route = useRoute()
const router = useRouter()
const assetStore = useAssetStore()

// ==================== 扫描类型与启动方式 ====================

type ScanKind = 'system_vuln' | 'port' | 'bruteforce' | 'baseline' | 'web' | 'database' | 'ics' | 'mobile' | 'container'

// 任务类型选项（对应后端 task_type）
const taskTypeOptions = [
  { label: '系统漏洞扫描', value: 'system_vuln' },
  { label: '端口扫描', value: 'port' },
  { label: '弱口令猜解', value: 'bruteforce' },
  { label: '基线核查', value: 'baseline' },
  { label: 'Web 应用扫描', value: 'web' },
  { label: '数据库扫描', value: 'database' },
  { label: '工控漏洞扫描', value: 'ics' },
  { label: '移动 APP 扫描', value: 'mobile' },
  { label: '容器镜像扫描', value: 'container' },
]

// 启动方式
const launchModeOptions = [
  { label: '立即执行', value: 'manual' },
  { label: '定时执行', value: 'scheduled' },
  { label: '周期执行', value: 'periodic' },
]

// 优先级
const priorityOptions = [
  { label: '低', value: 'low' },
  { label: '正常', value: 'normal' },
  { label: '高', value: 'high' },
  { label: '紧急', value: 'critical' },
]

// TCP 扫描类型
const tcpScanTypeOptions = [
  { label: 'Connect（无需 root）', value: 'connect' },
  { label: 'SYN（需 root）', value: 'syn' },
  { label: 'ACK', value: 'ack' },
  { label: 'Null', value: 'null' },
  { label: 'Xmas', value: 'xmas' },
  { label: 'Fin', value: 'fin' },
  { label: 'Window', value: 'window' },
]

// 验证方式
const verifyModeOptions = [
  { label: '主动验证', value: 'active' },
  { label: '被动验证', value: 'passive' },
]

// Web 插件类型
const webPluginTypeOptions = [
  { label: 'XSS', value: 'xss' },
  { label: 'SQL 注入', value: 'sqli' },
  { label: '文件上传', value: 'lfu' },
  { label: '文件包含', value: 'rfi' },
  { label: 'XXE', value: 'xxe' },
  { label: 'URL 跳转', value: 'redirect' },
  { label: 'CSRF', value: 'csrf' },
]

// 数据库检查项
const dbCheckItemOptions = [
  { label: '弱口令', value: 'weak_password' },
  { label: '权限提升', value: 'privilege_escalation' },
  { label: '敏感数据泄露', value: 'data_leak' },
  { label: '配置基线', value: 'config_baseline' },
  { label: '已知漏洞', value: 'known_vuln' },
]

// 移动检测项
const mobileCheckItemOptions = [
  { label: 'iOS 安全', value: 'ios' },
  { label: 'HarmonyOS 安全', value: 'harmonyos' },
  { label: '数据安全', value: 'data_security' },
  { label: '恶意行为', value: 'malicious_behavior' },
]

// 基线规则集（示例，可对接基线规则列表 API 时替换）
const baselineRuleOptions = [
  { label: '等保三级 Linux', value: 'gbt22239_l3_linux' },
  { label: '等保三级 Windows', value: 'gbt22239_l3_windows' },
  { label: '等保三级网络设备', value: 'gbt22239_l3_network' },
  { label: '等保三级安全设备', value: 'gbt22239_l3_security' },
  { label: '等保三级虚拟化', value: 'gbt22239_l3_virtualization' },
]

// 资产发现范围
const discoveryScopeOptions = [
  { label: 'IP 直连', value: 'ip' },
  { label: '子域名', value: 'subdomain' },
  { label: '流量', value: 'traffic' },
]

// 周期执行预设
const periodicPresetOptions = [
  { label: '每日 00:00', value: '0 0 * * *' },
  { label: '每日 12:00', value: '0 12 * * *' },
  { label: '每周一 00:00', value: '0 0 * * 1' },
  { label: '每月 1 日 00:00', value: '0 0 1 * *' },
  { label: '工作日 09:00', value: '0 9 * * 1-5' },
  { label: '自定义', value: '' },
]

// 任务状态选项
const statusOptions = [
  { label: '等待中', value: 'pending' },
  { label: '运行中', value: 'running' },
  { label: '已暂停', value: 'paused' },
  { label: '已完成', value: 'completed' },
  { label: '已失败', value: 'failed' },
  { label: '已停止', value: 'stopped' },
]

// ==================== 路由推断 ====================

const scanKind = computed<ScanKind>(() => {
  const name = route.name as string
  const map: Record<string, ScanKind> = {
    SystemScan: 'system_vuln',
    IcsScan: 'ics',
    WebScan: 'web',
    DatabaseScan: 'database',
    PortScan: 'port',
    Bruteforce: 'bruteforce',
    Baseline: 'baseline',
    Mobile: 'mobile',
    Container: 'container',
  }
  return map[name] || 'system_vuln'
})

const kindLabel = computed(() => {
  const map: Record<ScanKind, string> = {
    port: '端口扫描',
    system_vuln: '系统漏洞扫描',
    ics: '工控漏洞扫描',
    web: 'Web 应用扫描',
    database: '数据库扫描',
    bruteforce: '弱口令猜解',
    baseline: '基线核查',
    mobile: '移动 APP 扫描',
    container: '容器镜像扫描',
  }
  return map[scanKind.value]
})

// ==================== 任务列表 ====================

const tasks = ref<ScanTask[]>([])
const totalTasks = ref(0)
const tasksLoading = ref(false)
const taskListQuery = reactive<TaskListQuery>({
  page: 1,
  page_size: 20,
  name: '',
  status: '',
  task_type: '',
})

async function fetchTasks() {
  tasksLoading.value = true
  try {
    const params: TaskListQuery = {
      page: taskListQuery.page,
      page_size: taskListQuery.page_size,
    }
    if (taskListQuery.name) params.name = taskListQuery.name
    if (taskListQuery.status) params.status = taskListQuery.status
    if (taskListQuery.task_type) params.task_type = taskListQuery.task_type
    const res = await taskApi.list(params)
    tasks.value = res.items
    totalTasks.value = res.items.length
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
  taskListQuery.task_type = ''
  taskListQuery.page = 1
  fetchTasks()
}

// ==================== 扫描历史 ====================

const historyCollapsed = ref<string[]>(['history'])
const historyTasks = ref<ScanTask[]>([])
const historyLoading = ref(false)

async function fetchHistory() {
  historyLoading.value = true
  try {
    const res = await taskApi.list({ page: 1, page_size: 10, status: 'completed' })
    historyTasks.value = res.items
  } catch {
    // 错误已在拦截器处理
  } finally {
    historyLoading.value = false
  }
}

function handleHistoryChange(vals: string[]) {
  if (vals.includes('history')) {
    fetchHistory()
  }
}

// ==================== 模板/节点/资产组加载 ====================

const templates = ref<ScanTemplateBrief[]>([])
const portTemplates = ref<PortTemplate[]>([])
const paramTemplates = ref<ParamTemplate[]>([])
const scanNodes = ref<ScanNode[]>([])

async function loadAuxiliaryData() {
  // 资产组树
  await assetStore.fetchAssetGroupTree().catch(() => {})
  // 检测模板
  try {
    const t = await scanApi.listTemplates()
    templates.value = t.templates || []
  } catch {
    templates.value = []
  }
  // 端口模板
  try {
    const pt = await scanApi.listPortTemplates({ page: 1, page_size: 100 })
    portTemplates.value = pt.items || []
  } catch {
    portTemplates.value = []
  }
  // 参数模板
  try {
    const pp = await scanApi.listParamTemplates({ page: 1, page_size: 100 })
    paramTemplates.value = pp.items || []
  } catch {
    paramTemplates.value = []
  }
  // 扫描节点
  try {
    const n = await scanApi.listNodes()
    scanNodes.value = n.nodes || []
  } catch {
    scanNodes.value = []
  }
}

// ==================== 创建/编辑任务表单 ====================

interface TaskFormState {
  // ===== 基础选项 =====
  name: string
  task_type: ScanKind
  launch_mode: 'manual' | 'scheduled' | 'periodic'
  scheduled_at: string
  cron_expr: string
  periodic_preset: string
  targets: string
  asset_group_id: string
  priority: 'low' | 'normal' | 'high' | 'critical'
  node_id: string
  template_id: string
  port_template_id: string
  param_template_id: string
  description: string
  // ===== 高级选项 =====
  concurrency: number
  timeout_ms: number
  retry: number
  rate_limit: number
  port_range: string
  tcp_scan_type: 'connect' | 'syn' | 'ack' | 'null' | 'xmas' | 'fin' | 'window'
  deep_scan: boolean
  weak_password_all: boolean
  web_plugin_types: string[]
  db_check_items: string[]
  rule_ids: string[]
  check_items: string[]
  verify_mode: 'active' | 'passive'
  link_port_scan: boolean
  link_bruteforce: boolean
  socks5_proxy: string
  gmtls: boolean
  passive_agent: boolean
  browser_verify: boolean
  danger_dos: boolean
  discovery_scope: 'ip' | 'subdomain' | 'traffic'
}

function createDefaultForm(): TaskFormState {
  return {
    name: '',
    task_type: scanKind.value,
    launch_mode: 'manual',
    scheduled_at: '',
    cron_expr: '0 0 * * *',
    periodic_preset: '0 0 * * *',
    targets: '',
    asset_group_id: '',
    priority: 'normal',
    node_id: '',
    template_id: '',
    port_template_id: '',
    param_template_id: '',
    description: '',
    concurrency: 10,
    timeout_ms: 3000,
    retry: 2,
    rate_limit: 0,
    port_range: '1-65535',
    tcp_scan_type: 'connect',
    deep_scan: false,
    weak_password_all: false,
    web_plugin_types: [],
    db_check_items: [],
    rule_ids: [],
    check_items: [],
    verify_mode: 'active',
    link_port_scan: false,
    link_bruteforce: false,
    socks5_proxy: '',
    gmtls: false,
    passive_agent: false,
    browser_verify: false,
    danger_dos: false,
    discovery_scope: 'ip',
  }
}

const dialogVisible = ref(false)
const dialogMode = ref<'create' | 'edit'>('create')
const editingTaskId = ref('')
const formRef = ref<FormInstance | null>(null)
const taskForm = reactive<TaskFormState>(createDefaultForm())
// 折叠面板：默认只展开基础选项
const taskDialogActiveNames = ref<string[]>(['basic'])
const formRules: FormRules<TaskFormState> = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  task_type: [{ required: true, message: '请选择任务类型', trigger: 'change' }],
  launch_mode: [{ required: true, message: '请选择启动方式', trigger: 'change' }],
}

// 周期预设变化时同步 cron
function handlePeriodicPresetChange(val: string) {
  if (val !== '') {
    taskForm.cron_expr = val
  }
}

// 选择资产组时自动填充主机（基于 ip_range）
function handleAssetGroupChange(groupId: string) {
  if (!groupId) return
  const node = findGroupNode(assetStore.assetGroupTree, groupId)
  if (node?.ip_range && !taskForm.targets) {
    taskForm.targets = node.ip_range
  }
}

function findGroupNode(nodes: any[], id: string): any {
  for (const n of nodes) {
    if (n.id === id) return n
    if (n.children?.length) {
      const r = findGroupNode(n.children, id)
      if (r) return r
    }
  }
  return null
}

function openCreateDialog() {
  dialogMode.value = 'create'
  editingTaskId.value = ''
  Object.assign(taskForm, createDefaultForm())
  dialogVisible.value = true
}

function openEditDialog(row: ScanTask) {
  dialogMode.value = 'edit'
  editingTaskId.value = row.id
  const base = createDefaultForm()
  // 将任务字段映射回表单
  base.name = row.name
  base.task_type = (row.task_type as ScanKind) || scanKind.value
  base.launch_mode = (row.launch_mode as any) || 'manual'
  base.priority = (row.priority as any) || 'normal'
  base.node_id = row.node_id || ''
  base.description = row.params?.description || ''
  // 启动方式相关
  const sc = row.schedule_config || {}
  if (base.launch_mode === 'scheduled' && sc.scheduled_at) {
    base.scheduled_at = sc.scheduled_at
  }
  if (base.launch_mode === 'periodic') {
    base.cron_expr = sc.cron || sc.cron_expr || '0 0 * * *'
    base.periodic_preset = periodicPresetOptions.find(o => o.value === base.cron_expr)?.value || ''
  }
  // 目标主机
  if (Array.isArray(row.targets)) {
    base.targets = row.targets.join('\n')
  } else if (typeof row.targets === 'string') {
    base.targets = row.targets
  }
  // 参数模板/扫描模板/端口模板（如已存储）
  if (row.params?.template_id) base.template_id = row.params.template_id
  if (row.params?.port_template_id) base.port_template_id = row.params.port_template_id
  if (row.params?.param_template_id) base.param_template_id = row.params.param_template_id
  // 高级参数
  if (row.params?.concurrency) base.concurrency = row.params.concurrency
  if (row.params?.timeout_ms) base.timeout_ms = row.params.timeout_ms
  if (row.params?.retry) base.retry = row.params.retry
  if (row.params?.rate_limit) base.rate_limit = row.params.rate_limit
  if (row.params?.port_range) base.port_range = row.params.port_range
  if (row.params?.tcp_scan_type) base.tcp_scan_type = row.params.tcp_scan_type
  if (typeof row.params?.deep_scan === 'boolean') base.deep_scan = row.params.deep_scan
  if (typeof row.params?.weak_password_all === 'boolean') base.weak_password_all = row.params.weak_password_all
  if (Array.isArray(row.params?.web_plugin_types)) base.web_plugin_types = row.params.web_plugin_types
  if (Array.isArray(row.params?.db_check_items)) base.db_check_items = row.params.db_check_items
  if (Array.isArray(row.params?.rule_ids)) base.rule_ids = row.params.rule_ids
  if (Array.isArray(row.params?.check_items)) base.check_items = row.params.check_items
  if (row.params?.verify_mode) base.verify_mode = row.params.verify_mode
  if (typeof row.params?.link_port_scan === 'boolean') base.link_port_scan = row.params.link_port_scan
  if (typeof row.params?.link_bruteforce === 'boolean') base.link_bruteforce = row.params.link_bruteforce
  if (row.params?.socks5_proxy) base.socks5_proxy = row.params.socks5_proxy
  if (typeof row.params?.gmtls === 'boolean') base.gmtls = row.params.gmtls
  if (typeof row.params?.passive_agent === 'boolean') base.passive_agent = row.params.passive_agent
  if (typeof row.params?.browser_verify === 'boolean') base.browser_verify = row.params.browser_verify
  if (typeof row.params?.danger_dos === 'boolean') base.danger_dos = row.params.danger_dos
  if (row.params?.discovery_scope) base.discovery_scope = row.params.discovery_scope
  Object.assign(taskForm, base)
  dialogVisible.value = true
}

function buildPayload(): {
  name: string
  task_type: string
  launch_mode: 'manual' | 'scheduled' | 'periodic'
  targets: string[]
  priority: 'low' | 'normal' | 'high' | 'critical'
  schedule_config: any
  params: any
  node_id: string
} {
  // 解析目标主机
  const targets = (taskForm.targets || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)

  // 启动方式/调度
  let schedule_config: any = undefined
  if (taskForm.launch_mode === 'scheduled') {
    schedule_config = { scheduled_at: taskForm.scheduled_at || undefined }
  } else if (taskForm.launch_mode === 'periodic') {
    schedule_config = { cron: taskForm.cron_expr || undefined }
  }

  // 高级参数（params）：只包含非默认或必要项
  const params: any = {
    description: taskForm.description || undefined,
    concurrency: taskForm.concurrency,
    timeout_ms: taskForm.timeout_ms,
    retry: taskForm.retry,
    rate_limit: taskForm.rate_limit || undefined,
    port_range: taskForm.port_range || undefined,
    tcp_scan_type: taskForm.tcp_scan_type,
    deep_scan: taskForm.deep_scan,
    weak_password_all: taskForm.weak_password_all,
    verify_mode: taskForm.verify_mode,
    link_port_scan: taskForm.link_port_scan,
    link_bruteforce: taskForm.link_bruteforce,
    socks5_proxy: taskForm.socks5_proxy || undefined,
    gmtls: taskForm.gmtls,
    passive_agent: taskForm.passive_agent,
    browser_verify: taskForm.browser_verify,
    danger_dos: taskForm.danger_dos,
    discovery_scope: taskForm.discovery_scope,
  }
  if (taskForm.template_id) params.template_id = taskForm.template_id
  if (taskForm.port_template_id) params.port_template_id = taskForm.port_template_id
  if (taskForm.param_template_id) params.param_template_id = taskForm.param_template_id
  if (taskForm.web_plugin_types.length > 0) params.web_plugin_types = taskForm.web_plugin_types
  if (taskForm.db_check_items.length > 0) params.db_check_items = taskForm.db_check_items
  if (taskForm.rule_ids.length > 0) params.rule_ids = taskForm.rule_ids
  if (taskForm.check_items.length > 0) params.check_items = taskForm.check_items
  // 清理 undefined
  Object.keys(params).forEach((k) => params[k] === undefined && delete params[k])

  return {
    name: taskForm.name,
    task_type: taskForm.task_type,
    launch_mode: taskForm.launch_mode,
    targets,
    priority: taskForm.priority,
    schedule_config,
    params,
    node_id: taskForm.node_id || '',
  }
}

async function handleSubmitTask() {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (!valid) return
    // 校验：目标主机或资产组至少一项
    const targets = (taskForm.targets || '').split(/[\s,]+/).filter(Boolean)
    if (targets.length === 0 && !taskForm.asset_group_id) {
      ElMessage.warning('请输入目标主机或选择资产组')
      return
    }
    // 周期/定时校验
    if (taskForm.launch_mode === 'scheduled' && !taskForm.scheduled_at) {
      ElMessage.warning('请选择定时执行时间')
      return
    }
    if (taskForm.launch_mode === 'periodic' && !taskForm.cron_expr) {
      ElMessage.warning('请输入或选择 cron 表达式')
      return
    }

    try {
      const payload = buildPayload()
      if (dialogMode.value === 'create') {
        await taskApi.create(payload)
        ElMessage.success('任务已创建')
      } else {
        await taskApi.update(editingTaskId.value, payload)
        ElMessage.success('任务已更新')
      }
      dialogVisible.value = false
      await fetchTasks()
    } catch {
      // 错误已在拦截器处理
    }
  })
}

// ==================== 任务操作 ====================

async function handleStart(row: ScanTask) {
  try {
    await taskApi.start(row.id)
    ElMessage.success('任务已启动')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

async function handlePause(row: ScanTask) {
  try {
    await taskApi.pause(row.id)
    ElMessage.success('任务已暂停')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

async function handleResume(row: ScanTask) {
  try {
    await taskApi.resume(row.id)
    ElMessage.success('任务已恢复')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

async function handleStop(row: ScanTask) {
  try {
    await ElMessageBox.confirm(`确认停止任务「${row.name}」？`, '停止确认', {
      type: 'warning',
    })
    await taskApi.stop(row.id)
    ElMessage.success('任务已停止')
    await fetchTasks()
  } catch {
    // 用户取消或错误
  }
}

async function handleDelete(row: ScanTask) {
  try {
    await ElMessageBox.confirm(`确认删除任务「${row.name}」？该操作不可恢复。`, '删除确认', {
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

async function handleCopy(row: ScanTask) {
  try {
    await taskApi.copy(row.id)
    ElMessage.success('任务已复制')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

async function handleLock(row: ScanTask) {
  try {
    await taskApi.lock(row.id)
    ElMessage.success('任务已锁定')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

async function handleUnlock(row: ScanTask) {
  try {
    await taskApi.unlock(row.id)
    ElMessage.success('任务已解锁')
    await fetchTasks()
  } catch {
    // 错误已在拦截器处理
  }
}

// 任务对比：选择两个任务
const compareFirst = ref<string>('')
function handleCompare(row: ScanTask) {
  if (!compareFirst.value) {
    compareFirst.value = row.id
    ElMessage.info(`已选择第一个任务：${row.name}，请点击另一个任务的对比按钮`)
  } else {
    if (compareFirst.value === row.id) {
      ElMessage.warning('请选择不同的任务')
      return
    }
    router.push({
      name: 'Reports',
      query: { compare_a: compareFirst.value, compare_b: row.id },
    })
    compareFirst.value = ''
  }
}

function handleTrend(row: ScanTask) {
  router.push({ name: 'Reports', query: { task_id: row.id } })
}

function handleViewReport(row: ScanTask) {
  router.push({ name: 'Reports', query: { task_id: row.id } })
}

// ==================== 结果下载与报表 ====================

// 结果下载格式（后端报表下载接口支持 html / xlsx / json）
type ResultDownloadFormat = 'html' | 'xlsx' | 'json'

const downloadFormatOptions: { label: string; value: ResultDownloadFormat }[] = [
  { label: 'HTML 结果', value: 'html' },
  { label: 'Excel (XLSX)', value: 'xlsx' },
  { label: 'JSON 原始结果', value: 'json' },
]

// 判断任务是否已产生结果（已完成/已停止/已失败均有结果产物）
function hasResults(row: ScanTask): boolean {
  return ['completed', 'stopped', 'failed'].includes(row.status)
}

// 下载任务结果：通过报表下载接口获取 Blob 并以临时 <a> 下载
async function handleDownloadResult(row: ScanTask, format: ResultDownloadFormat) {
  if (!hasResults(row)) {
    ElMessage.warning('该任务暂无可用结果，请等待扫描完成')
    return
  }
  try {
    const blob = (await reportApi.download(row.id, format)) as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.name}.${format}`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('结果下载已开始')
  } catch {
    // 错误已在拦截器处理
  }
}

// el-dropdown command 类型宽松，内部收敛为下载格式
function handleDownloadCommand(row: ScanTask, cmd: string | number | object) {
  handleDownloadResult(row, String(cmd) as ResultDownloadFormat)
}

// 生成 HTML 报表并直接下载
async function handleGenerateReport(row: ScanTask) {
  if (!hasResults(row)) {
    ElMessage.warning('该任务暂无可用结果，请等待扫描完成')
    return
  }
  try {
    const blob = (await reportApi.generate({
      task_id: row.id,
      format: 'html',
      type: 'comprehensive',
    })) as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.name}_report.html`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('报表生成成功')
  } catch {
    // 错误已在拦截器处理
  }
}

// 报表下拉命令：generate 生成 HTML 报表，open 跳转报表管理页并预选任务
function handleReportCommand(row: ScanTask, cmd: string | number | object) {
  if (cmd === 'generate') {
    handleGenerateReport(row)
  } else if (cmd === 'open') {
    handleViewReport(row)
  }
}

// 导入任务（占位：暂未实现）
function handleImportTask() {
  ElMessage.info('导入任务功能尚未实现')
}

// ==================== 任务详情抽屉 ====================

const drawerVisible = ref(false)
const drawerLoading = ref(false)
const drawerTask = ref<ScanTask | null>(null)
const drawerStatus = ref<ScanTaskStatus | null>(null)
const drawerResults = ref<ScanResultsResponse | null>(null)
const activeDetailTab = ref<string>('basic')
const detailPollTimer: { value: ReturnType<typeof setInterval> | null } = { value: null }

async function openDetail(row: ScanTask) {
  drawerVisible.value = true
  drawerLoading.value = true
  activeDetailTab.value = 'basic'
  try {
    // 任务详情
    drawerTask.value = await taskApi.get(row.id)
    // 状态和结果（并行）
    const [statusRes, resultsRes] = await Promise.allSettled([
      scanApi.getStatus(row.id),
      scanApi.getResults(row.id),
    ])
    drawerStatus.value = statusRes.status === 'fulfilled' ? statusRes.value : null
    drawerResults.value = resultsRes.status === 'fulfilled' ? resultsRes.value : null
    // 如果任务还在运行，启动轮询
    stopDetailPolling()
    if (drawerStatus.value && ['pending', 'running', 'paused'].includes(drawerStatus.value.status)) {
      startDetailPolling(row.id)
    }
  } catch {
    // 错误已在拦截器处理
  } finally {
    drawerLoading.value = false
  }
}

function startDetailPolling(taskId: string, interval = 3000) {
  stopDetailPolling()
  detailPollTimer.value = setInterval(async () => {
    try {
      drawerStatus.value = await scanApi.getStatus(taskId)
      // 任务结束则停止轮询并刷新结果
      if (drawerStatus.value && !['pending', 'running', 'paused'].includes(drawerStatus.value.status)) {
        stopDetailPolling()
        try {
          drawerResults.value = await scanApi.getResults(taskId)
        } catch {
          // 忽略
        }
      }
    } catch {
      // 忽略
    }
  }, interval)
}

function stopDetailPolling() {
  if (detailPollTimer.value) {
    clearInterval(detailPollTimer.value)
    detailPollTimer.value = null
  }
}

function handleDrawerClose() {
  stopDetailPolling()
  drawerVisible.value = false
  drawerTask.value = null
  drawerStatus.value = null
  drawerResults.value = null
}

// ==================== 详情计算字段 ====================

// 主机维度统计（按主机分组）
const hostStats = computed(() => {
  const results = drawerResults.value?.results || []
  const map = new Map<string, { host: string; total: number; ports: number; vulns: number; accounts: number }>()
  for (const r of results) {
    const h = r.host || 'unknown'
    if (!map.has(h)) {
      map.set(h, { host: h, total: 0, ports: 0, vulns: 0, accounts: 0 })
    }
    const item = map.get(h)!
    item.total++
    if (r.result_type === 'PortScan' || r.result_type === 'port') item.ports++
    if (r.result_type === 'VulnDetect' || r.result_type === 'vuln') item.vulns++
    if (r.result_type === 'BruteForce' || r.result_type === 'bruteforce') item.accounts++
  }
  return Array.from(map.values())
})

// 不可达主机（state=closed 且无开放端口的）
const unreachableHosts = computed(() => {
  const results = drawerResults.value?.results || []
  const hosts = new Set<string>()
  const openHosts = new Set<string>()
  for (const r of results) {
    const h = r.host || ''
    if (!h) continue
    if (r.state === 'open' || r.success === true) {
      openHosts.add(h)
    } else {
      hosts.add(h)
    }
  }
  return Array.from(hosts).filter((h) => !openHosts.has(h))
})

// 端口列表
const portList = computed<ScanResult[]>(() => {
  const results = drawerResults.value?.results || []
  return results.filter((r) => r.result_type === 'PortScan' || r.result_type === 'port')
})

// 漏洞列表
const vulnList = computed<ScanResult[]>(() => {
  const results = drawerResults.value?.results || []
  return results.filter((r) => r.result_type === 'VulnDetect' || r.result_type === 'vuln')
})

// 脆弱账号（爆破成功）
const accountList = computed<ScanResult[]>(() => {
  const results = drawerResults.value?.results || []
  return results.filter((r) => r.result_type === 'BruteForce' || r.result_type === 'bruteforce')
})

// ==================== 工具函数 ====================

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

const launchModeLabel = (mode: string) => {
  const map: Record<string, string> = {
    manual: '立即执行',
    scheduled: '定时执行',
    periodic: '周期执行',
  }
  return map[mode] || mode || '-'
}

const taskTypeLabel = (type: string) => {
  const map: Record<string, string> = {
    system_vuln: '系统漏洞扫描',
    port: '端口扫描',
    bruteforce: '弱口令猜解',
    baseline: '基线核查',
    web: 'Web 应用扫描',
    database: '数据库扫描',
    ics: '工控漏洞扫描',
    mobile: '移动 APP 扫描',
    container: '容器镜像扫描',
    // 兼容后端历史 task_type
    port_scan: '端口扫描',
    host_discovery: '主机发现',
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

const priorityLabel = (p: string) => {
  const map: Record<string, string> = {
    low: '低',
    normal: '正常',
    high: '高',
    critical: '紧急',
  }
  return map[p] || p || '-'
}

const priorityType = (p: string) => {
  const map: Record<string, string> = {
    low: 'info',
    normal: '',
    high: 'warning',
    critical: 'danger',
  }
  return map[p] || ''
}

const formatTime = (t: string | null): string => {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN')
  } catch {
    return '-'
  }
}

// 计算耗时（毫秒）
function formatDuration(start: string | null, end: string | null): string {
  if (!start) return '-'
  const startMs = new Date(start).getTime()
  const endMs = end ? new Date(end).getTime() : Date.now()
  if (isNaN(startMs) || isNaN(endMs)) return '-'
  const diff = endMs - startMs
  if (diff < 0) return '-'
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec} 秒`
  const min = Math.floor(sec / 60)
  const remSec = sec % 60
  if (min < 60) return `${min} 分 ${remSec} 秒`
  const hr = Math.floor(min / 60)
  const remMin = min % 60
  return `${hr} 时 ${remMin} 分`
}

// 下次运行时间（基于 schedule_config 估算，简化展示）
function nextRunText(row: ScanTask): string {
  const sc = row.schedule_config
  if (!sc) return '-'
  if (row.launch_mode === 'scheduled') return sc.scheduled_at ? formatTime(sc.scheduled_at) : '-'
  if (row.launch_mode === 'periodic') return sc.cron ? `cron: ${sc.cron}` : '-'
  return '-'
}

// ==================== 生命周期 ====================

onMounted(async () => {
  await Promise.all([fetchTasks(), loadAuxiliaryData()])
})

onBeforeUnmount(() => {
  stopDetailPolling()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 顶部任务列表区 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <div class="mb-4 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <Rocket class="h-5 w-5 text-cyan-400" />
          <h2 class="text-base font-medium text-slate-200">{{ kindLabel }}任务管理</h2>
        </div>
        <div class="flex items-center gap-2">
          <el-button :icon="Plus" type="primary" @click="openCreateDialog">新建任务</el-button>
          <el-button :icon="Upload" @click="handleImportTask">导入任务</el-button>
          <el-button :icon="RefreshCw" circle size="small" @click="fetchTasks" />
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
            v-for="opt in statusOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-select
          v-model="taskListQuery.task_type"
          placeholder="按类型筛选"
          clearable
          style="width: 180px"
        >
          <el-option
            v-for="opt in taskTypeOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-button type="primary" :icon="Eye" @click="handleSearch">查询</el-button>
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
        <el-table-column prop="task_type" label="类型" width="140">
          <template #default="{ row }">{{ taskTypeLabel(row.task_type) }}</template>
        </el-table-column>
        <el-table-column prop="launch_mode" label="启动方式" width="110">
          <template #default="{ row }">{{ launchModeLabel(row.launch_mode) }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="100">
          <template #default="{ row }">{{ (row.progress || 0).toFixed(1) }}%</template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="started_at" label="开始时间" width="170">
          <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="finished_at" label="结束时间" width="170">
          <template #default="{ row }">{{ formatTime(row.finished_at) }}</template>
        </el-table-column>
        <el-table-column label="下次运行" width="160">
          <template #default="{ row }">{{ nextRunText(row) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="380" fixed="right">
          <template #default="{ row }">
            <el-tooltip content="编辑" placement="top">
              <el-button link type="primary" :icon="Pencil" @click="openEditDialog(row)" />
            </el-tooltip>
            <el-tooltip content="复制" placement="top">
              <el-button link type="primary" :icon="Copy" @click="handleCopy(row)" />
            </el-tooltip>
            <el-tooltip content="删除" placement="top">
              <el-button link type="danger" :icon="Delete" @click="handleDelete(row)" />
            </el-tooltip>
            <el-tooltip :content="row.locked ? '解锁' : '锁定'" placement="top">
              <el-button
                link
                :type="row.locked ? 'warning' : 'info'"
                :icon="row.locked ? Unlock : Lock"
                @click="row.locked ? handleUnlock(row) : handleLock(row)"
              />
            </el-tooltip>
            <el-tooltip content="趋势" placement="top">
              <el-button link type="primary" :icon="TrendingUp" @click="handleTrend(row)" />
            </el-tooltip>
            <el-tooltip content="对比" placement="top">
              <el-button
                link
                :type="compareFirst === row.id ? 'success' : 'info'"
                :icon="ChevronDown"
                @click="handleCompare(row)"
              />
            </el-tooltip>
            <!-- 下载结果：仅对已完成/已停止/已失败等有结果的任务可用 -->
            <el-tooltip :content="hasResults(row) ? '下载结果' : '任务完成后可下载结果'" placement="top">
              <el-dropdown
                :disabled="!hasResults(row)"
                @command="(cmd: string | number | object) => handleDownloadCommand(row, cmd)"
              >
                <el-button link type="primary" :icon="Download" />
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item
                      v-for="f in downloadFormatOptions"
                      :key="f.value"
                      :command="f.value"
                    >
                      {{ f.label }}
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </el-tooltip>
            <!-- 报表：生成 HTML 报表或跳转报表管理页（预选该任务） -->
            <el-tooltip :content="hasResults(row) ? '报表' : '任务完成后可生成报表'" placement="top">
              <el-dropdown
                :disabled="!hasResults(row)"
                @command="(cmd: string | number | object) => handleReportCommand(row, cmd)"
              >
                <el-button link type="primary" :icon="FileText" />
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="generate">生成 HTML 报表</el-dropdown-item>
                    <el-dropdown-item command="open">打开报表管理</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </el-tooltip>
            <el-tooltip v-if="row.status === 'running' || row.status === 'pending'" content="暂停" placement="top">
              <el-button link type="warning" :icon="Pause" @click="handlePause(row)" />
            </el-tooltip>
            <el-tooltip v-else-if="row.status === 'paused'" content="恢复" placement="top">
              <el-button link type="success" :icon="Play" @click="handleResume(row)" />
            </el-tooltip>
            <el-tooltip v-else content="启动" placement="top">
              <el-button link type="primary" :icon="Play" @click="handleStart(row)" />
            </el-tooltip>
            <el-tooltip v-if="['running', 'pending', 'paused'].includes(row.status)" content="停止" placement="top">
              <el-button link type="danger" :icon="CircleStop" @click="handleStop(row)" />
            </el-tooltip>
            <el-tooltip content="详情" placement="top">
              <el-button link type="primary" :icon="Eye" @click="openDetail(row)" />
            </el-tooltip>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 扫描历史折叠区 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <el-collapse v-model="historyCollapsed" @change="handleHistoryChange">
        <el-collapse-item name="history">
          <template #title>
            <div class="flex items-center gap-2">
              <History class="h-4 w-4 text-cyan-400" />
              <span class="text-base font-medium text-slate-200">扫描历史（已完成任务）</span>
            </div>
          </template>
          <el-table
            :data="historyTasks"
            v-loading="historyLoading"
            stripe
            style="width: 100%"
            max-height="360"
          >
            <el-table-column prop="name" label="任务名称" min-width="160" show-overflow-tooltip />
            <el-table-column prop="task_type" label="类型" width="140">
              <template #default="{ row }">{{ taskTypeLabel(row.task_type) }}</template>
            </el-table-column>
            <el-table-column prop="started_at" label="开始时间" width="170">
              <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
            </el-table-column>
            <el-table-column prop="finished_at" label="结束时间" width="170">
              <template #default="{ row }">{{ formatTime(row.finished_at) }}</template>
            </el-table-column>
            <el-table-column label="耗时" width="140">
              <template #default="{ row }">{{ formatDuration(row.started_at, row.finished_at) }}</template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="statusType(row.status)" size="small">
                  {{ statusLabel(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="160" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" :icon="Eye" @click="handleViewReport(row)">
                  查看报告
                </el-button>
                <el-button link type="info" :icon="Copy" @click="handleCopy(row)">
                  复用
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </div>

    <!-- 创建/编辑任务弹窗 -->
    <el-dialog
      v-model="dialogVisible"
      :title="dialogMode === 'create' ? '新建扫描任务' : '编辑扫描任务'"
      width="900px"
      top="5vh"
      destroy-on-close
      class="dark-dialog"
    >
      <el-form
        ref="formRef"
        :model="taskForm"
        :rules="formRules"
        label-width="120px"
        label-position="right"
      >
        <el-collapse v-model="taskDialogActiveNames">
          <el-collapse-item name="basic" title="基础选项">
            <!-- 1. 任务名称 -->
            <el-form-item label="任务名称" prop="name" required>
              <el-input v-model="taskForm.name" placeholder="请输入任务名称" maxlength="64" show-word-limit />
            </el-form-item>
            <!-- 2. 任务类型 -->
            <el-form-item label="任务类型" prop="task_type" required>
              <el-select v-model="taskForm.task_type" style="width: 100%" placeholder="请选择任务类型">
                <el-option
                  v-for="opt in taskTypeOptions"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
            </el-form-item>
            <!-- 3. 启动方式 -->
            <el-form-item label="启动方式" prop="launch_mode" required>
              <el-radio-group v-model="taskForm.launch_mode">
                <el-radio
                  v-for="opt in launchModeOptions"
                  :key="opt.value"
                  :value="opt.value"
                >
                  {{ opt.label }}
                </el-radio>
              </el-radio-group>
            </el-form-item>
            <!-- 4. 定时时间 -->
            <el-form-item v-if="taskForm.launch_mode === 'scheduled'" label="定时时间" required>
              <el-date-picker
                v-model="taskForm.scheduled_at"
                type="datetime"
                placeholder="选择定时执行时间"
                format="YYYY-MM-DD HH:mm:ss"
                value-format="YYYY-MM-DDTHH:mm:ss"
                style="width: 100%"
              />
            </el-form-item>
            <!-- 5. 周期规则 -->
            <el-form-item v-if="taskForm.launch_mode === 'periodic'" label="周期规则" required>
              <el-select
                v-model="taskForm.periodic_preset"
                placeholder="选择预设周期"
                style="width: 240px"
                @change="handlePeriodicPresetChange"
              >
                <el-option
                  v-for="opt in periodicPresetOptions"
                  :key="opt.value || 'custom'"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
              <el-input
                v-if="taskForm.periodic_preset === ''"
                v-model="taskForm.cron_expr"
                placeholder="请输入 cron 表达式，例: 0 2 * * *"
                style="width: 320px; margin-left: 8px"
              />
              <span class="ml-2 text-xs text-slate-500">5 字段 cron（分 时 日 月 周）</span>
            </el-form-item>
            <!-- 6. 目标主机 -->
            <el-form-item label="目标主机" required>
              <el-input
                v-model="taskForm.targets"
                type="textarea"
                :rows="3"
                placeholder="支持 IP / CIDR / URL，多个用逗号或换行分隔，例: 192.168.1.0/24, 10.0.0.1"
              />
            </el-form-item>
            <!-- 7. 资产组选择 -->
            <el-form-item label="资产组">
              <el-select
                v-model="taskForm.asset_group_id"
                placeholder="选择资产组后自动填充主机"
                clearable
                filterable
                style="width: 100%"
                @change="handleAssetGroupChange"
              >
                <el-option
                  v-for="g in assetStore.assetGroups"
                  :key="g.id"
                  :label="g.name"
                  :value="g.id"
                />
              </el-select>
            </el-form-item>
            <!-- 8. 优先级 -->
            <el-form-item label="优先级">
              <el-select v-model="taskForm.priority" style="width: 100%">
                <el-option
                  v-for="opt in priorityOptions"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
            </el-form-item>
            <!-- 9. 扫描节点 -->
            <el-form-item label="扫描节点">
              <el-select v-model="taskForm.node_id" clearable filterable placeholder="选择扫描节点" style="width: 100%">
                <el-option
                  v-for="n in scanNodes"
                  :key="n.id"
                  :label="`${n.name}（${n.endpoint}）`"
                  :value="n.id"
                />
              </el-select>
            </el-form-item>
            <!-- 10. 扫描模板 -->
            <el-form-item label="扫描模板">
              <el-select v-model="taskForm.template_id" clearable filterable placeholder="检测模板（YAML）" style="width: 100%">
                <el-option
                  v-for="t in templates"
                  :key="t.id"
                  :label="t.name"
                  :value="t.id"
                />
              </el-select>
            </el-form-item>
            <!-- 11. 端口模板（端口扫描时显示） -->
            <el-form-item v-if="taskForm.task_type === 'port'" label="端口模板">
              <el-select v-model="taskForm.port_template_id" clearable filterable placeholder="选择端口模板" style="width: 100%">
                <el-option
                  v-for="p in portTemplates"
                  :key="p.id"
                  :label="`${p.name}（TCP ${p.tcp_port_count || 0}）`"
                  :value="p.id"
                />
              </el-select>
            </el-form-item>
            <!-- 12. 参数模板 -->
            <el-form-item label="参数模板">
              <el-select v-model="taskForm.param_template_id" clearable filterable placeholder="选择参数模板" style="width: 100%">
                <el-option
                  v-for="p in paramTemplates"
                  :key="p.id"
                  :label="p.name"
                  :value="p.id"
                />
              </el-select>
            </el-form-item>
            <!-- 13. 描述 -->
            <el-form-item label="描述">
              <el-input
                v-model="taskForm.description"
                type="textarea"
                :rows="2"
                placeholder="任务描述"
                maxlength="256"
                show-word-limit
              />
            </el-form-item>
          </el-collapse-item>

          <el-collapse-item name="advanced" title="高级选项">
            <div class="grid grid-cols-1 gap-x-4 md:grid-cols-2">
              <!-- 1. 并发数 -->
              <el-form-item label="并发数">
                <el-input-number v-model="taskForm.concurrency" :min="1" :max="10000" />
              </el-form-item>
              <!-- 2. 超时(毫秒) -->
              <el-form-item label="超时(毫秒)">
                <el-input-number v-model="taskForm.timeout_ms" :min="100" :max="60000" />
              </el-form-item>
              <!-- 3. 重试次数 -->
              <el-form-item label="重试次数">
                <el-input-number v-model="taskForm.retry" :min="0" :max="10" />
              </el-form-item>
              <!-- 4. 扫描速率限制 -->
              <el-form-item label="速率限制">
                <el-input-number v-model="taskForm.rate_limit" :min="0" :max="100000" placeholder="0 表示不限速" />
              </el-form-item>
              <!-- 5. 端口范围 -->
              <el-form-item label="端口范围">
                <el-input v-model="taskForm.port_range" placeholder="例: 1-65535 或 22,80,443" />
              </el-form-item>
              <!-- 6. TCP 扫描类型 -->
              <el-form-item label="TCP 扫描类型">
                <el-select v-model="taskForm.tcp_scan_type" style="width: 100%">
                  <el-option
                    v-for="opt in tcpScanTypeOptions"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </el-form-item>
              <!-- 7. 深度扫描 -->
              <el-form-item label="深度扫描">
                <el-switch v-model="taskForm.deep_scan" />
              </el-form-item>
              <!-- 8. 扫描所有弱密码 -->
              <el-form-item label="扫描所有弱密码">
                <el-switch v-model="taskForm.weak_password_all" />
              </el-form-item>
              <!-- 9. Web 插件类型 -->
              <el-form-item label="Web 插件类型">
                <el-checkbox-group v-model="taskForm.web_plugin_types">
                  <el-checkbox
                    v-for="opt in webPluginTypeOptions"
                    :key="opt.value"
                    :value="opt.value"
                  >
                    {{ opt.label }}
                  </el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <!-- 10. 数据库检查项 -->
              <el-form-item label="数据库检查项">
                <el-checkbox-group v-model="taskForm.db_check_items">
                  <el-checkbox
                    v-for="opt in dbCheckItemOptions"
                    :key="opt.value"
                    :value="opt.value"
                  >
                    {{ opt.label }}
                  </el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <!-- 11. 基线规则 -->
              <el-form-item label="基线规则">
                <el-select
                  v-model="taskForm.rule_ids"
                  multiple
                  filterable
                  placeholder="选择基线规则集"
                  style="width: 100%"
                >
                  <el-option
                    v-for="opt in baselineRuleOptions"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </el-form-item>
              <!-- 12. 移动检测项 -->
              <el-form-item label="移动检测项">
                <el-checkbox-group v-model="taskForm.check_items">
                  <el-checkbox
                    v-for="opt in mobileCheckItemOptions"
                    :key="opt.value"
                    :value="opt.value"
                  >
                    {{ opt.label }}
                  </el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <!-- 13. 验证方式 -->
              <el-form-item label="验证方式">
                <el-radio-group v-model="taskForm.verify_mode">
                  <el-radio
                    v-for="opt in verifyModeOptions"
                    :key="opt.value"
                    :value="opt.value"
                  >
                    {{ opt.label }}
                  </el-radio>
                </el-radio-group>
              </el-form-item>
              <!-- 14. 联动端口扫描 -->
              <el-form-item label="联动端口扫描">
                <el-switch v-model="taskForm.link_port_scan" />
              </el-form-item>
              <!-- 15. 联动爆破 -->
              <el-form-item label="联动爆破">
                <el-switch v-model="taskForm.link_bruteforce" />
              </el-form-item>
              <!-- 16. SOCKS5 代理 -->
              <el-form-item label="SOCKS5 代理">
                <el-input v-model="taskForm.socks5_proxy" placeholder="例: socks5://127.0.0.1:1080" />
              </el-form-item>
              <!-- 17. 国密 TLS -->
              <el-form-item label="国密 TLS">
                <el-switch v-model="taskForm.gmtls" />
              </el-form-item>
              <!-- 18. Agent 被动扫描 -->
              <el-form-item label="Agent 被动扫描">
                <el-switch v-model="taskForm.passive_agent" />
              </el-form-item>
              <!-- 19. 浏览器验证 -->
              <el-form-item label="浏览器验证">
                <el-switch v-model="taskForm.browser_verify" />
              </el-form-item>
              <!-- 20. 危险插件 DoS -->
              <el-form-item label="危险插件 DoS">
                <el-switch v-model="taskForm.danger_dos" />
              </el-form-item>
              <!-- 21. 资产发现范围 -->
              <el-form-item label="资产发现范围">
                <el-radio-group v-model="taskForm.discovery_scope">
                  <el-radio
                    v-for="opt in discoveryScopeOptions"
                    :key="opt.value"
                    :value="opt.value"
                  >
                    {{ opt.label }}
                  </el-radio>
                </el-radio-group>
              </el-form-item>
            </div>
          </el-collapse-item>
        </el-collapse>
      </el-form>

      <template #footer>
        <div class="flex justify-end gap-2">
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" @click="handleSubmitTask">
            {{ dialogMode === 'create' ? '创建' : '保存' }}
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 任务详情抽屉 -->
    <el-drawer
      v-model="drawerVisible"
      :title="drawerTask ? `任务详情：${drawerTask.name}` : '任务详情'"
      direction="rtl"
      size="60%"
      :before-close="(done: () => void) => { handleDrawerClose(); done() }"
    >
      <div v-loading="drawerLoading">
        <el-tabs v-model="activeDetailTab">
          <!-- 1. 基础信息 -->
          <el-tab-pane label="基础信息" name="basic">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="任务名称">{{ drawerTask?.name || '-' }}</el-descriptions-item>
              <el-descriptions-item label="任务类型">{{ drawerTask ? taskTypeLabel(drawerTask.task_type) : '-' }}</el-descriptions-item>
              <el-descriptions-item label="状态">
                <el-tag v-if="drawerStatus" :type="statusType(drawerStatus.status)" size="small">
                  {{ statusLabel(drawerStatus.status) }}
                </el-tag>
                <span v-else>-</span>
              </el-descriptions-item>
              <el-descriptions-item label="进度">{{ drawerStatus ? drawerStatus.progress.toFixed(1) + '%' : '-' }}</el-descriptions-item>
              <el-descriptions-item label="优先级">
                <el-tag v-if="drawerTask" :type="priorityType(drawerTask.priority)" size="small">
                  {{ priorityLabel(drawerTask.priority) }}
                </el-tag>
                <span v-else>-</span>
              </el-descriptions-item>
              <el-descriptions-item label="启动方式">{{ drawerTask ? launchModeLabel(drawerTask.launch_mode) : '-' }}</el-descriptions-item>
              <el-descriptions-item label="创建时间">{{ formatTime(drawerTask?.created_at || null) }}</el-descriptions-item>
              <el-descriptions-item label="开始时间">{{ formatTime(drawerTask?.started_at || null) }}</el-descriptions-item>
              <el-descriptions-item label="结束时间">{{ formatTime(drawerTask?.finished_at || null) }}</el-descriptions-item>
              <el-descriptions-item label="扫描节点">{{ drawerTask?.node_id || '-' }}</el-descriptions-item>
              <el-descriptions-item label="结果数">{{ drawerStatus?.result_count ?? '-' }}</el-descriptions-item>
              <el-descriptions-item label="开放端口">{{ drawerStatus?.open_port_count ?? '-' }}</el-descriptions-item>
              <el-descriptions-item label="成功数">{{ drawerStatus?.success_count ?? '-' }}</el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>

          <!-- 2. 主机维度 -->
          <el-tab-pane :label="`主机维度（${hostStats.length}）`" name="hosts">
            <el-table :data="hostStats" stripe max-height="480">
              <el-table-column prop="host" label="主机" min-width="160" />
              <el-table-column prop="total" label="总结果" width="100" />
              <el-table-column prop="ports" label="端口数" width="100" />
              <el-table-column prop="vulns" label="漏洞数" width="100" />
              <el-table-column prop="accounts" label="弱账号" width="100" />
            </el-table>
          </el-tab-pane>

          <!-- 3. 不可达主机 -->
          <el-tab-pane :label="`不可达主机（${unreachableHosts.length}）`" name="unreachable">
            <el-table :data="unreachableHosts.map((h) => ({ host: h }))" stripe max-height="480">
              <el-table-column prop="host" label="主机" />
            </el-table>
            <el-empty v-if="unreachableHosts.length === 0" description="无不可达主机" />
          </el-tab-pane>

          <!-- 4. 端口列表 -->
          <el-tab-pane :label="`端口列表（${portList.length}）`" name="ports">
            <el-table :data="portList" stripe max-height="480">
              <el-table-column prop="host" label="主机" width="160" />
              <el-table-column prop="port" label="端口" width="80" />
              <el-table-column prop="protocol" label="协议" width="80" />
              <el-table-column prop="state" label="状态" width="80">
                <template #default="{ row }">
                  <el-tag v-if="row.state === 'open'" type="success" size="small">open</el-tag>
                  <el-tag v-else type="info" size="small">{{ row.state || '-' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="service" label="服务" width="120" show-overflow-tooltip />
              <el-table-column prop="product" label="产品" width="140" show-overflow-tooltip />
              <el-table-column prop="version" label="版本" width="120" show-overflow-tooltip />
            </el-table>
          </el-tab-pane>

          <!-- 5. 漏洞维度（统计） -->
          <el-tab-pane label="漏洞维度" name="vuln-summary">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="漏洞总数">{{ vulnList.length }}</el-descriptions-item>
              <el-descriptions-item label="严重">{{ vulnList.filter(v => v.detail?.severity === 'critical' || v.detail?.severity === '严重').length }}</el-descriptions-item>
              <el-descriptions-item label="高危">{{ vulnList.filter(v => v.detail?.severity === 'high' || v.detail?.severity === '高危').length }}</el-descriptions-item>
              <el-descriptions-item label="中危">{{ vulnList.filter(v => v.detail?.severity === 'medium' || v.detail?.severity === '中危').length }}</el-descriptions-item>
              <el-descriptions-item label="低危">{{ vulnList.filter(v => v.detail?.severity === 'low' || v.detail?.severity === '低危').length }}</el-descriptions-item>
              <el-descriptions-item label="信息">{{ vulnList.filter(v => v.detail?.severity === 'info' || v.detail?.severity === '信息').length }}</el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>

          <!-- 6. 漏洞列表 -->
          <el-tab-pane :label="`漏洞列表（${vulnList.length}）`" name="vulns">
            <el-table :data="vulnList" stripe max-height="480">
              <el-table-column prop="host" label="主机" width="140" />
              <el-table-column label="漏洞" min-width="200" show-overflow-tooltip>
                <template #default="{ row }">{{ row.detail?.name || row.detail?.title || row.detail?.vuln_name || '-' }}</template>
              </el-table-column>
              <el-table-column label="等级" width="100">
                <template #default="{ row }">
                  <el-tag :type="row.detail?.severity === 'critical' || row.detail?.severity === '严重' ? 'danger' : row.detail?.severity === 'high' || row.detail?.severity === '高危' ? 'danger' : row.detail?.severity === 'medium' || row.detail?.severity === '中危' ? 'warning' : 'info'" size="small">
                    {{ row.detail?.severity || '-' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="CVE" width="140" show-overflow-tooltip>
                <template #default="{ row }">{{ row.detail?.cve || row.detail?.cve_id || '-' }}</template>
              </el-table-column>
              <el-table-column label="时间" width="170">
                <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- 7. 脆弱账号 -->
          <el-tab-pane :label="`脆弱账号（${accountList.length}）`" name="accounts">
            <el-table :data="accountList" stripe max-height="480">
              <el-table-column prop="host" label="主机" width="140" />
              <el-table-column prop="port" label="端口" width="80" />
              <el-table-column label="协议" width="100">
                <template #default="{ row }">{{ row.protocol || row.detail?.protocol || '-' }}</template>
              </el-table-column>
              <el-table-column label="用户名" width="140">
                <template #default="{ row }">{{ row.detail?.username || '-' }}</template>
              </el-table-column>
              <el-table-column label="密码" width="140" show-overflow-tooltip>
                <template #default="{ row }">{{ row.detail?.password || '-' }}</template>
              </el-table-column>
              <el-table-column label="成功" width="80">
                <template #default="{ row }">
                  <el-tag v-if="row.success === true" type="success" size="small">是</el-tag>
                  <el-tag v-else type="info" size="small">否</el-tag>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- 8. 任务参数 -->
          <el-tab-pane label="任务参数" name="params">
            <pre class="max-h-[480px] overflow-auto rounded bg-slate-950/60 p-3 text-xs text-slate-300">{{ JSON.stringify(drawerTask?.params || {}, null, 2) }}</pre>
          </el-tab-pane>

          <!-- 9. 日志输出 -->
          <el-tab-pane label="日志输出" name="logs">
            <div v-if="drawerStatus" class="space-y-2 text-sm text-slate-300">
              <div>任务 ID：{{ drawerStatus.task_id }}</div>
              <div>类型：{{ taskTypeLabel(drawerStatus.task_type) }}</div>
              <div>状态：{{ statusLabel(drawerStatus.status) }}</div>
              <div>进度：{{ drawerStatus.progress.toFixed(1) }}%</div>
              <div>结果数：{{ drawerStatus.result_count }}</div>
              <div>开放端口：{{ drawerStatus.open_port_count }}</div>
              <div>成功数：{{ drawerStatus.success_count }}</div>
              <el-progress
                v-if="drawerStatus.status === 'running'"
                :percentage="Math.round(drawerStatus.progress)"
                :stroke-width="6"
                color="#06b6d4"
              />
            </div>
            <el-empty v-else description="暂无日志信息" />
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped>
.dark-dialog :deep(.el-dialog__body) {
  background-color: rgb(15 23 42 / 0.6);
  max-height: 70vh;
  overflow-y: auto;
}
</style>
