<script setup lang="ts">
import { ref, onMounted, computed, type Component } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Plus,
  Download,
  RefreshCw,
  Trash2,
  Pencil,
  ChevronDown,
  ChevronUp,
  Upload,
  Search,
  Radar,
  ScanLine,
  TrendingUp,
  Network,
  AppWindow,
  Database,
  KeyRound,
  Bug,
  FolderPlus,
  FolderTree,
  ShieldCheck,
} from '@lucide/vue'
import { useAssetStore } from '@/stores/asset'
import {
  networkAssetApi,
  applicationAssetApi,
  databaseAssetApi,
  assetGroupApi,
  credentialApi,
  type NetworkAsset,
  type ApplicationAsset,
  type DatabaseAsset,
  type AssetKind,
  type AssetGroupNode,
  type Credential,
} from '@/api/asset'
import { taskApi } from '@/api/task'
import { dashboardApi } from '@/api/dashboard'
import { riskApi } from '@/api/risk'

const store = useAssetStore()
const router = useRouter()

// ==================== Tab 与分页 ====================
const activeTab = ref<AssetKind>('network')
const page = ref(1)
const pageSize = ref(20)

const assetKindOptions = [
  { label: '网络资产', value: 'network' as AssetKind },
  { label: '应用资产', value: 'application' as AssetKind },
  { label: '数据库资产', value: 'database' as AssetKind },
]

// 多选
const selectedNetwork = ref<string[]>([])
const selectedApplication = ref<string[]>([])
const selectedDatabase = ref<string[]>([])

const currentSelected = computed(() => {
  if (activeTab.value === 'network') return selectedNetwork.value
  if (activeTab.value === 'application') return selectedApplication.value
  return selectedDatabase.value
})

// ==================== 资产组树 ====================
const assetGroupTree = ref<AssetGroupNode[]>([])
const selectedGroupId = ref<string>('')
const groupLoading = ref(false)
const groupDialogVisible = ref(false)
const groupDialogMode = ref<'create' | 'edit'>('create')
const groupLoadingSubmit = ref(false)

// 资产组表单
const groupForm = ref({
  id: '',
  name: '',
  parent_id: '' as string | null,
  owner: '',
  contact: '',
  email: '',
  location: '',
  ip_range: '',
})

const treeProps = {
  label: 'name',
  children: 'children',
}

// 扁平化资产组（用于资产表单 el-select）
const flatGroups = computed(() => {
  const result: { id: string; name: string }[] = []
  const walk = (nodes: AssetGroupNode[], prefix = '') => {
    for (const n of nodes) {
      result.push({ id: n.id, name: prefix + n.name })
      if (n.children?.length) walk(n.children, prefix + '  /  ')
    }
  }
  walk(assetGroupTree.value)
  return result
})

// 加载资产组树
async function loadAssetGroupTree() {
  groupLoading.value = true
  try {
    const res = await assetGroupApi.tree()
    assetGroupTree.value = res.items
  } catch {
    // 错误已由拦截器处理
  } finally {
    groupLoading.value = false
  }
}

// 点击树节点筛选
function handleNodeClick(data: AssetGroupNode) {
  selectedGroupId.value = selectedGroupId.value === data.id ? '' : data.id
  page.value = 1
  loadData()
}

// 打开资产组新增弹窗（同级）
function openGroupCreateSibling(data: AssetGroupNode | null) {
  groupDialogMode.value = 'create'
  groupForm.value = {
    id: '',
    name: '',
    parent_id: data?.parent_id ?? null,
    owner: '',
    contact: '',
    email: '',
    location: '',
    ip_range: '',
  }
  groupDialogVisible.value = true
}

// 打开资产组新增弹窗（下级）
function openGroupCreateChild(data: AssetGroupNode) {
  groupDialogMode.value = 'create'
  groupForm.value = {
    id: '',
    name: '',
    parent_id: data.id,
    owner: '',
    contact: '',
    email: '',
    location: '',
    ip_range: '',
  }
  groupDialogVisible.value = true
}

// 打开资产组编辑弹窗
function openGroupEdit(data: AssetGroupNode) {
  groupDialogMode.value = 'edit'
  groupForm.value = {
    id: data.id,
    name: data.name,
    parent_id: data.parent_id,
    owner: data.owner ?? '',
    contact: data.contact ?? '',
    email: data.email ?? '',
    location: data.location ?? '',
    ip_range: data.ip_range ?? '',
  }
  groupDialogVisible.value = true
}

// 提交资产组表单
async function handleGroupSubmit() {
  if (!groupForm.value.name.trim()) {
    ElMessage.warning('请输入资产组名称')
    return
  }
  groupLoadingSubmit.value = true
  try {
    const payload = {
      name: groupForm.value.name.trim(),
      parent_id: groupForm.value.parent_id || undefined,
      owner: groupForm.value.owner || undefined,
      contact: groupForm.value.contact || undefined,
      email: groupForm.value.email || undefined,
      location: groupForm.value.location || undefined,
      ip_range: groupForm.value.ip_range || undefined,
    }
    if (groupDialogMode.value === 'create') {
      await store.createAssetGroup(payload)
      ElMessage.success('资产组创建成功')
    } else {
      await store.updateAssetGroup(groupForm.value.id, payload)
      ElMessage.success('资产组更新成功')
    }
    groupDialogVisible.value = false
    await loadAssetGroupTree()
  } catch {
    // 错误已由拦截器处理
  } finally {
    groupLoadingSubmit.value = false
  }
}

// 删除资产组
async function handleGroupDelete(data: AssetGroupNode) {
  await ElMessageBox.confirm(`确认删除资产组 "${data.name}" 吗？子组也会一并删除。`, '删除确认', {
    type: 'warning',
  })
  try {
    await store.deleteAssetGroup(data.id)
    ElMessage.success('删除成功')
    if (selectedGroupId.value === data.id) selectedGroupId.value = ''
    await loadAssetGroupTree()
  } catch {
    // 错误已由拦截器处理
  }
}

// ==================== 资产组快捷扫描 ====================
// 资产组树每个节点的快捷扫描操作：系统扫描 / 应用扫描 / 数据库扫描 / 基线核查
interface GroupScanOption {
  /// 任务类型（与后端 TaskType 枚举 string_value 一致）
  type: string
  /// 展示名称
  label: string
  /// 图标
  icon: Component
  /// 创建任务后跳转的扫描页路由
  route: string
}

const groupScanOptions: GroupScanOption[] = [
  { type: 'system_scan', label: '系统扫描', icon: Radar, route: '/scan/system' },
  { type: 'app_scan', label: '应用扫描', icon: AppWindow, route: '/scan/web' },
  { type: 'db_scan', label: '数据库扫描', icon: Database, route: '/scan/database' },
  { type: 'baseline_check', label: '基线核查', icon: ShieldCheck, route: '/baseline' },
]

// 资产组快捷扫描：取该组下资产 IP 创建对应类型任务并跳转
async function handleGroupScan(opt: GroupScanOption, data: AssetGroupNode) {
  try {
    await ElMessageBox.confirm(`确认对资产组 "${data.name}" 发起${opt.label}吗？`, '扫描确认', {
      type: 'warning',
    })
  } catch {
    // 用户取消
    return
  }
  try {
    // 分页取该资产组下全部网络资产（page_size 取大以尽量拿到全部）
    const res = await assetGroupApi.listAssets(data.id, { page: 1, page_size: 1000 })
    const ips = (res.items ?? []).map((a) => a.ip).filter((ip) => !!ip)
    if (!ips.length) {
      ElMessage.warning('该资产组内无资产')
      return
    }
    await taskApi.create({
      name: `资产组-${data.name}-${opt.label}`,
      task_type: opt.type,
      targets: ips,
      launch_mode: 'manual',
    })
    ElMessage.success(`${opt.label}任务创建成功`)
    router.push(opt.route)
  } catch {
    // 错误已由拦截器处理
  }
}

// ==================== 顶部统计卡片 ====================
const stats = ref({
  networkCount: 0,
  appCount: 0,
  dbCount: 0,
  weakPwdTotal: 0,
  vulnTotal: 0,
  vulnNew: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
})

// 今日新增（简化：基于 vuln_trend 最近一天）
const todayNewVulns = computed(() => stats.value.vulnNew)

async function loadStats() {
  try {
    const [overview, summary] = await Promise.all([
      dashboardApi.overview({ days: 1 }).catch(() => null),
      riskApi.summary().catch(() => null),
    ])
    if (overview) {
      stats.value.networkCount = overview.assets.network
      stats.value.appCount = overview.assets.application
      stats.value.dbCount = overview.assets.database
      stats.value.vulnTotal = overview.vulns.total
      const trend = overview.vuln_trend
      stats.value.vulnNew = trend?.length ? trend[trend.length - 1]?.count ?? 0 : 0
      const sevMap: Record<string, number> = {}
      for (const s of overview.vulns.by_severity) sevMap[s.key?.toLowerCase()] = s.count
      stats.value.critical = sevMap['critical'] ?? 0
      stats.value.high = sevMap['high'] ?? 0
      stats.value.medium = sevMap['medium'] ?? 0
      stats.value.low = sevMap['low'] ?? 0
      stats.value.info = sevMap['info'] ?? 0
    }
    if (summary) {
      stats.value.weakPwdTotal = summary.weak_passwords.total
    }
  } catch {
    // 忽略统计加载错误
  }
}

// ==================== 多维度筛选 ====================
const filter = ref({
  name: '',
  ip: '',
  mac: '',
  risk_level: '',
  os: '',
  tags: '',
  weight: '',
  host_type: '',
  config_spec: '',
  owner: '',
  contact: '',
  email: '',
})
const filterExpanded = ref(false)

const riskLevelOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
]

function toggleFilterExpand() {
  filterExpanded.value = !filterExpanded.value
}

function handleSearch() {
  page.value = 1
  loadData()
}

function handleResetFilter() {
  filter.value = {
    name: '', ip: '', mac: '', risk_level: '', os: '', tags: '',
    weight: '', host_type: '', config_spec: '', owner: '', contact: '', email: '',
  }
  selectedGroupId.value = ''
  page.value = 1
  loadData()
}

// ==================== 凭证 ====================
const credentials = ref<Credential[]>([])

async function loadCredentials() {
  try {
    const res = await credentialApi.list({ page: 1, page_size: 200 })
    credentials.value = res.items
  } catch {
    // 忽略凭证加载错误
  }
}

// ==================== 资产表单 ====================
const dialogVisible = ref(false)
const dialogMode = ref<'create' | 'edit'>('create')
const dialogLoading = ref(false)
const editingId = ref<string>('')

// 网络资产表单（补齐字段）
const networkForm = ref({
  name: '',
  ip: '',
  mac: '',
  os: '',
  asset_group_id: '' as string | undefined,
  owner: '',
  contact: '',
  email: '',
  location: '',
  description: '',
  is_industrial: false,
  trusted_device: false,
  tags: [] as string[],
  // 补齐字段
  device_no: '',
  network_zone: '',
  business_system: '',
  asset_type: 'network' as AssetKind,
  credential_id: '' as string | undefined,
  auto_identify: false,
  config_spec: '',
  industrial_device_type: '',
  industrial_vendor: '',
  industrial_model: '',
  industrial_version: '',
  weight: '',
  protection_level: '',
  confidentiality: '',
  integrity: '',
  availability: '',
  importance: '',
  // 标签输入
  tagInput: '',
})

// 应用资产表单（补齐字段）
const appForm = ref({
  name: '',
  url: '',
  title: '',
  ip: '',
  asset_group_id: '' as string | undefined,
  owner: '',
  contact: '',
  email: '',
  description: '',
  auto_fetch: false,
  trusted_device: false,
  tags: [] as string[],
  device_no: '',
  network_zone: '',
  business_system: '',
  asset_type: 'application' as AssetKind,
  credential_id: '' as string | undefined,
  auto_identify: false,
  config_spec: '',
  tech_stack: '',
  weight: '',
  protection_level: '',
  confidentiality: '',
  integrity: '',
  availability: '',
  importance: '',
  tagInput: '',
})

// 数据库资产表单（补齐字段）
const dbForm = ref({
  name: '',
  ip: '',
  db_type: 'mysql',
  port: 3306,
  username: '',
  password: '',
  db_name: '',
  enable_ssl: false,
  execute_login_scan: false,
  trusted_device: false,
  asset_group_id: '' as string | undefined,
  owner: '',
  contact: '',
  email: '',
  description: '',
  tags: [] as string[],
  device_no: '',
  network_zone: '',
  business_system: '',
  asset_type: 'database' as AssetKind,
  credential_id: '' as string | undefined,
  auto_identify: false,
  config_spec: '',
  db_version: '',
  connection_string: '',
  weight: '',
  protection_level: '',
  confidentiality: '',
  integrity: '',
  availability: '',
  importance: '',
  tagInput: '',
})

const networkZoneOptions = [
  { label: 'Server', value: 'Server' },
  { label: 'Office', value: 'office' },
  { label: 'DMZ', value: 'DMZ' },
]

const protectionLevelOptions = [
  { label: '一级', value: '1' },
  { label: '二级', value: '2' },
  { label: '三级', value: '3' },
  { label: '四级', value: '4' },
]

const ciaOptions = [
  { label: '高', value: '高' },
  { label: '中', value: '中' },
  { label: '低', value: '低' },
]

const dbTypeOptions = [
  { label: 'MySQL', value: 'mysql' },
  { label: 'PostgreSQL', value: 'postgresql' },
  { label: 'Oracle', value: 'oracle' },
  { label: 'SQL Server', value: 'sqlserver' },
  { label: 'Redis', value: 'redis' },
  { label: 'MongoDB', value: 'mongodb' },
  { label: 'DamengDB', value: 'dameng' },
  { label: 'Kingbase', value: 'kingbase' },
]

// ==================== 数据加载 ====================
async function loadData() {
  const params: Record<string, any> = {
    page: page.value,
    page_size: pageSize.value,
  }
  // 注入筛选参数
  if (filter.value.name) params.name = filter.value.name
  if (filter.value.ip) params.ip = filter.value.ip
  if (filter.value.mac) params.mac = filter.value.mac
  if (filter.value.risk_level) params.risk_level = filter.value.risk_level
  if (filter.value.os) params.os = filter.value.os
  if (filter.value.tags) params.tags = filter.value.tags
  if (filter.value.weight) params.weight = filter.value.weight
  if (filter.value.host_type) params.host_type = filter.value.host_type
  if (filter.value.config_spec) params.config_spec = filter.value.config_spec
  if (filter.value.owner) params.owner = filter.value.owner
  if (filter.value.contact) params.contact = filter.value.contact
  if (filter.value.email) params.email = filter.value.email
  // 资产组筛选
  if (selectedGroupId.value) params.asset_group_id = selectedGroupId.value

  if (activeTab.value === 'network') {
    await store.fetchNetworkAssets(params)
  } else if (activeTab.value === 'application') {
    await store.fetchApplicationAssets(params)
  } else if (activeTab.value === 'database') {
    await store.fetchDatabaseAssets(params)
  }
}

function handleTabChange() {
  page.value = 1
  loadData()
}

// ==================== 资产 CRUD ====================
function openCreateDialog() {
  dialogMode.value = 'create'
  editingId.value = ''
  resetForms()
  // 默认带入当前选中的资产组
  if (selectedGroupId.value) {
    networkForm.value.asset_group_id = selectedGroupId.value
    appForm.value.asset_group_id = selectedGroupId.value
    dbForm.value.asset_group_id = selectedGroupId.value
  }
  dialogVisible.value = true
}

function openEditDialog(row: any) {
  dialogMode.value = 'edit'
  editingId.value = row.id
  if (activeTab.value === 'network') {
    const a = row as NetworkAsset
    networkForm.value = {
      name: a.name,
      ip: a.ip,
      mac: a.mac ?? '',
      os: a.os ?? '',
      asset_group_id: a.asset_group_id ?? undefined,
      owner: a.owner ?? '',
      contact: a.contact ?? '',
      email: a.email ?? '',
      location: a.location ?? '',
      description: a.description ?? '',
      is_industrial: a.is_industrial,
      trusted_device: a.trusted_device,
      tags: Array.isArray(a.tags) ? (a.tags as string[]) : [],
      device_no: a.device_no ?? '',
      network_zone: a.network_zone ?? '',
      business_system: a.business_system ?? '',
      asset_type: a.asset_type ?? 'network',
      credential_id: undefined,
      auto_identify: false,
      config_spec: '',
      industrial_device_type: a.industrial_device_type ?? '',
      industrial_vendor: a.industrial_vendor ?? '',
      industrial_model: a.industrial_model ?? '',
      industrial_version: a.industrial_version ?? '',
      weight: a.weight ?? '',
      protection_level: a.protection_level ?? '',
      confidentiality: a.confidentiality ?? '',
      integrity: a.integrity ?? '',
      availability: a.availability ?? '',
      importance: a.importance ?? '',
      tagInput: '',
    }
  } else if (activeTab.value === 'application') {
    const a = row as ApplicationAsset
    appForm.value = {
      name: a.name,
      url: a.url,
      title: a.title ?? '',
      ip: a.ip ?? '',
      asset_group_id: a.asset_group_id ?? undefined,
      owner: a.owner ?? '',
      contact: a.contact ?? '',
      email: a.email ?? '',
      description: a.description ?? '',
      auto_fetch: a.auto_fetch,
      trusted_device: a.trusted_device,
      tags: Array.isArray(a.tags) ? (a.tags as string[]) : [],
      device_no: a.device_no ?? '',
      network_zone: '',
      business_system: a.business_system ?? '',
      asset_type: (a.asset_type as AssetKind) ?? 'application',
      credential_id: undefined,
      auto_identify: false,
      config_spec: '',
      tech_stack: '',
      weight: a.weight ?? '',
      protection_level: a.protection_level ?? '',
      confidentiality: a.confidentiality ?? '',
      integrity: a.integrity ?? '',
      availability: a.availability ?? '',
      importance: a.importance ?? '',
      tagInput: '',
    }
  } else if (activeTab.value === 'database') {
    const a = row as DatabaseAsset
    dbForm.value = {
      name: a.name,
      ip: a.ip,
      db_type: a.db_type,
      port: a.port,
      username: a.username ?? '',
      password: a.password ?? '',
      db_name: a.db_name ?? '',
      enable_ssl: a.enable_ssl,
      execute_login_scan: a.execute_login_scan,
      trusted_device: a.trusted_device,
      asset_group_id: a.asset_group_id ?? undefined,
      owner: a.owner ?? '',
      contact: a.contact ?? '',
      email: a.email ?? '',
      description: a.description ?? '',
      tags: Array.isArray(a.tags) ? (a.tags as string[]) : [],
      device_no: a.device_no ?? '',
      network_zone: '',
      business_system: a.business_system ?? '',
      asset_type: (a.asset_type as AssetKind) ?? 'database',
      credential_id: undefined,
      auto_identify: false,
      config_spec: '',
      db_version: '',
      connection_string: '',
      weight: a.weight ?? '',
      protection_level: a.protection_level ?? '',
      confidentiality: a.confidentiality ?? '',
      integrity: a.integrity ?? '',
      availability: a.availability ?? '',
      importance: a.importance ?? '',
      tagInput: '',
    }
  }
  dialogVisible.value = true
}

function resetForms() {
  const presetGroupId = selectedGroupId.value || undefined
  networkForm.value = {
    name: '', ip: '', mac: '', os: '',
    asset_group_id: presetGroupId,
    owner: '', contact: '', email: '', location: '', description: '',
    is_industrial: false, trusted_device: false, tags: [],
    device_no: '', network_zone: '', business_system: '',
    asset_type: 'network',
    credential_id: undefined, auto_identify: false, config_spec: '',
    industrial_device_type: '', industrial_vendor: '', industrial_model: '', industrial_version: '',
    weight: '',
    protection_level: '', confidentiality: '', integrity: '', availability: '', importance: '',
    tagInput: '',
  }
  appForm.value = {
    name: '', url: '', title: '', ip: '',
    asset_group_id: presetGroupId,
    owner: '', contact: '', email: '', description: '',
    auto_fetch: false, trusted_device: false, tags: [],
    device_no: '', network_zone: '', business_system: '',
    asset_type: 'application',
    credential_id: undefined, auto_identify: false, config_spec: '',
    tech_stack: '',
    weight: '',
    protection_level: '', confidentiality: '', integrity: '', availability: '', importance: '',
    tagInput: '',
  }
  dbForm.value = {
    name: '', ip: '', db_type: 'mysql', port: 3306,
    username: '', password: '', db_name: '',
    enable_ssl: false, execute_login_scan: false, trusted_device: false,
    asset_group_id: presetGroupId,
    owner: '', contact: '', email: '', description: '',
    tags: [],
    device_no: '', network_zone: '', business_system: '',
    asset_type: 'database',
    credential_id: undefined, auto_identify: false, config_spec: '',
    db_version: '', connection_string: '',
    weight: '',
    protection_level: '', confidentiality: '', integrity: '', availability: '', importance: '',
    tagInput: '',
  }
}

// 标签添加
function addNetworkTag() {
  const v = networkForm.value.tagInput.trim()
  if (v && !networkForm.value.tags.includes(v)) {
    networkForm.value.tags.push(v)
  }
  networkForm.value.tagInput = ''
}
function addAppTag() {
  const v = appForm.value.tagInput.trim()
  if (v && !appForm.value.tags.includes(v)) {
    appForm.value.tags.push(v)
  }
  appForm.value.tagInput = ''
}
function addDbTag() {
  const v = dbForm.value.tagInput.trim()
  if (v && !dbForm.value.tags.includes(v)) {
    dbForm.value.tags.push(v)
  }
  dbForm.value.tagInput = ''
}

// 清空空字符串字段
function cleanPayload(data: Record<string, any>) {
  const out: Record<string, any> = { ...data }
  Object.keys(out).forEach((k) => {
    if (out[k] === '' || out[k] === null) delete out[k]
  })
  // tagInput 不传后端
  delete out.tagInput
  return out
}

async function handleSubmit() {
  if (dialogLoading.value) return
  dialogLoading.value = true
  try {
    if (activeTab.value === 'network') {
      const data = cleanPayload({ ...networkForm.value }) as any
      if (dialogMode.value === 'create') {
        await store.createNetworkAsset(data)
        ElMessage.success('网络资产创建成功')
      } else {
        await store.updateNetworkAsset(editingId.value, data)
        ElMessage.success('网络资产更新成功')
      }
    } else if (activeTab.value === 'application') {
      const data = cleanPayload({ ...appForm.value }) as any
      if (dialogMode.value === 'create') {
        await store.createApplicationAsset(data)
        ElMessage.success('应用资产创建成功')
      } else {
        await store.updateApplicationAsset(editingId.value, data)
        ElMessage.success('应用资产更新成功')
      }
    } else if (activeTab.value === 'database') {
      const data = cleanPayload({ ...dbForm.value }) as any
      if (dialogMode.value === 'create') {
        await store.createDatabaseAsset(data)
        ElMessage.success('数据库资产创建成功')
      } else {
        await store.updateDatabaseAsset(editingId.value, data)
        ElMessage.success('数据库资产更新成功')
      }
    }
    dialogVisible.value = false
    await loadData()
    await loadStats()
  } catch {
    // 错误已由拦截器处理
  } finally {
    dialogLoading.value = false
  }
}

async function handleDelete(row: any) {
  await ElMessageBox.confirm(`确认删除资产 "${row.name}" 吗？`, '删除确认', {
    type: 'warning',
  })
  try {
    if (activeTab.value === 'network') {
      await store.deleteNetworkAsset(row.id)
    } else if (activeTab.value === 'application') {
      await store.deleteApplicationAsset(row.id)
    } else if (activeTab.value === 'database') {
      await store.deleteDatabaseAsset(row.id)
    }
    ElMessage.success('删除成功')
    await loadData()
    await loadStats()
  } catch {
    // 错误已由拦截器处理
  }
}

async function handleBatchDelete() {
  if (currentSelected.value.length === 0) {
    ElMessage.warning('请先选择要删除的资产')
    return
  }
  await ElMessageBox.confirm(`确认删除选中的 ${currentSelected.value.length} 项资产吗？`, '批量删除', {
    type: 'warning',
  })
  try {
    if (activeTab.value === 'network') {
      await store.batchDeleteNetworkAssets(selectedNetwork.value)
      selectedNetwork.value = []
    } else if (activeTab.value === 'application') {
      await store.batchDeleteApplicationAssets(selectedApplication.value)
      selectedApplication.value = []
    } else if (activeTab.value === 'database') {
      await store.batchDeleteDatabaseAssets(selectedDatabase.value)
      selectedDatabase.value = []
    }
    ElMessage.success('批量删除成功')
    await loadData()
    await loadStats()
  } catch {
    // 错误已由拦截器处理
  }
}

function handleSelectionChange(selection: any[]) {
  const ids = selection.map((item) => item.id)
  if (activeTab.value === 'network') {
    selectedNetwork.value = ids
  } else if (activeTab.value === 'application') {
    selectedApplication.value = ids
  } else {
    selectedDatabase.value = ids
  }
}

// ==================== 导入 / 导出 / 资产发现 ====================
async function handleExport() {
  try {
    let blob: Blob
    if (activeTab.value === 'network') {
      blob = await networkAssetApi.export() as unknown as Blob
    } else if (activeTab.value === 'application') {
      blob = await applicationAssetApi.export() as unknown as Blob
    } else {
      blob = await databaseAssetApi.export() as unknown as Blob
    }
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${activeTab.value}-assets.xlsx`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    // 错误已由拦截器处理
  }
}

async function handleDownloadTemplate() {
  try {
    let blob: Blob
    if (activeTab.value === 'network') {
      blob = await networkAssetApi.template() as unknown as Blob
    } else if (activeTab.value === 'application') {
      blob = await applicationAssetApi.template() as unknown as Blob
    } else {
      blob = await databaseAssetApi.template() as unknown as Blob
    }
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${activeTab.value}-template.xlsx`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('模板下载成功')
  } catch {
    // 错误已由拦截器处理
  }
}

// el-upload 自定义上传
async function handleImport(options: any) {
  const file = options.file as File
  try {
    let res: { success: number; failed: number; errors: string[] }
    if (activeTab.value === 'network') {
      res = await networkAssetApi.importFile(file)
    } else if (activeTab.value === 'application') {
      res = await applicationAssetApi.importFile(file)
    } else {
      res = await databaseAssetApi.importFile(file)
    }
    ElMessage.success(`导入完成：成功 ${res.success} 项，失败 ${res.failed} 项`)
    await loadData()
    await loadStats()
  } catch {
    // 错误已由拦截器处理
  }
}

// 资产发现一键入口
function goDiscovery() {
  router.push('/scan/port')
}

// ==================== 操作列快捷入口 ====================
function goScan(row: any) {
  const host = row.ip || row.name
  router.push(`/scan/system_vuln?host=${encodeURIComponent(host)}`)
}

function goTrend(row: any) {
  const host = row.ip || row.name
  router.push(`/risk?vuln_host=${encodeURIComponent(host)}`)
}

// ==================== 状态映射 ====================
const statusType = (status: string) => {
  const map: Record<string, string> = {
    active: 'success',
    inactive: 'danger',
    unknown: 'info',
  }
  return map[status] || 'info'
}
const statusLabel = (status: string) => {
  const map: Record<string, string> = {
    active: '在线',
    inactive: '离线',
    unknown: '未知',
  }
  return map[status] || status
}

// 资产类型标签
const assetTypeLabel = (t: string) => {
  const map: Record<string, string> = {
    network: '网络',
    application: '应用',
    database: '数据库',
  }
  return map[t] || t || '-'
}

// 标签数组安全转换
function toTagArray(tags: any): string[] {
  if (Array.isArray(tags)) return tags as string[]
  if (typeof tags === 'string' && tags) return tags.split(',').map((s) => s.trim()).filter(Boolean)
  return []
}

// 总数
const currentTotal = computed(() => {
  if (activeTab.value === 'network') return store.networkTotal
  if (activeTab.value === 'application') return store.applicationTotal
  return store.databaseTotal
})

onMounted(() => {
  loadData()
  loadAssetGroupTree()
  loadStats()
  loadCredentials()
})
</script>

<template>
  <div class="flex h-full gap-3">
    <!-- 左侧：资产组树形导航 -->
    <div class="flex w-60 shrink-0 flex-col rounded-xl border border-slate-800 bg-slate-900/50">
      <div class="flex items-center justify-between border-b border-slate-800 px-3 py-2.5">
        <div class="flex items-center gap-1.5 text-sm font-medium text-slate-200">
          <FolderTree class="h-4 w-4 text-cyan-400" />
          资产组
        </div>
        <el-button
          link
          type="primary"
          size="small"
          :icon="FolderPlus"
          @click="openGroupCreateSibling(null)"
        >
          新增
        </el-button>
      </div>
      <div v-loading="groupLoading" class="flex-1 overflow-auto px-2 py-2">
        <el-tree
          :data="assetGroupTree"
          :props="treeProps"
          node-key="id"
          :default-expand-all="true"
          :current-node-key="selectedGroupId"
          @node-click="handleNodeClick"
          empty-text="暂无资产组"
        >
          <template #default="{ data }">
            <div class="group relative flex flex-1 items-center py-0.5">
              <span
                class="truncate text-sm"
                :class="selectedGroupId === data.id ? 'text-cyan-400 font-medium' : 'text-slate-200'"
              >
                {{ data.name }}
              </span>
              <!-- 节点操作：hover 时显示，绝对定位覆盖，避免图标挤压节点名称 -->
              <span
                class="absolute right-0 top-1/2 z-10 hidden -translate-y-1/2 items-center gap-1 rounded bg-slate-900/95 pl-1 group-hover:flex"
              >
                <!-- 快捷扫描图标 -->
                <el-tooltip
                  v-for="opt in groupScanOptions"
                  :key="opt.type"
                  :content="`对该资产组发起${opt.label}`"
                  placement="top"
                >
                  <el-button link type="primary" size="small" @click.stop="handleGroupScan(opt, data)">
                    <component :is="opt.icon" class="h-3.5 w-3.5" />
                  </el-button>
                </el-tooltip>
                <span class="mx-0.5 h-3.5 w-px bg-slate-700"></span>
                <el-button link type="primary" size="small" title="添加同级" @click.stop="openGroupCreateSibling(data)">
                  <Plus class="h-3.5 w-3.5" />
                </el-button>
                <el-button link type="primary" size="small" title="添加下级" @click.stop="openGroupCreateChild(data)">
                  <FolderPlus class="h-3.5 w-3.5" />
                </el-button>
                <el-button link type="primary" size="small" title="编辑" @click.stop="openGroupEdit(data)">
                  <Pencil class="h-3.5 w-3.5" />
                </el-button>
                <el-button link type="danger" size="small" title="删除" @click.stop="handleGroupDelete(data)">
                  <Trash2 class="h-3.5 w-3.5" />
                </el-button>
              </span>
            </div>
          </template>
        </el-tree>
      </div>
    </div>

    <!-- 右侧：主内容区 -->
    <div class="flex flex-1 flex-col gap-3 overflow-auto">
      <!-- 顶部统计卡片 -->
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <!-- 网络资产数 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-400">网络资产</p>
              <p class="mt-1 text-2xl font-bold text-white">{{ stats.networkCount }}</p>
            </div>
            <Network class="h-8 w-8 text-cyan-400 opacity-80" />
          </div>
        </div>
        <!-- 应用资产数 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-400">应用资产</p>
              <p class="mt-1 text-2xl font-bold text-white">{{ stats.appCount }}</p>
            </div>
            <AppWindow class="h-8 w-8 text-violet-400 opacity-80" />
          </div>
        </div>
        <!-- 数据库资产数 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-400">数据库资产</p>
              <p class="mt-1 text-2xl font-bold text-white">{{ stats.dbCount }}</p>
            </div>
            <Database class="h-8 w-8 text-pink-400 opacity-80" />
          </div>
        </div>
        <!-- 弱密码数 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-400">弱密码</p>
              <p class="mt-1 text-2xl font-bold text-white">{{ stats.weakPwdTotal }}</p>
            </div>
            <KeyRound class="h-8 w-8 text-amber-400 opacity-80" />
          </div>
        </div>
        <!-- 漏洞总数 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-400">漏洞总数</p>
              <p class="mt-1 text-2xl font-bold text-white">
                {{ stats.vulnTotal }}
                <span class="ml-1 text-xs text-rose-400">+{{ todayNewVulns }}</span>
              </p>
            </div>
            <Bug class="h-8 w-8 text-rose-400 opacity-80" />
          </div>
        </div>
        <!-- 各等级数量 -->
        <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <p class="text-xs text-slate-400">漏洞等级分布</p>
          <div class="mt-2 grid grid-cols-5 gap-1 text-center text-xs">
            <div>
              <div class="font-bold text-rose-500">{{ stats.critical }}</div>
              <div class="text-slate-500">严重</div>
            </div>
            <div>
              <div class="font-bold text-orange-500">{{ stats.high }}</div>
              <div class="text-slate-500">高危</div>
            </div>
            <div>
              <div class="font-bold text-amber-400">{{ stats.medium }}</div>
              <div class="text-slate-500">中危</div>
            </div>
            <div>
              <div class="font-bold text-cyan-400">{{ stats.low }}</div>
              <div class="text-slate-500">低危</div>
            </div>
            <div>
              <div class="font-bold text-slate-400">{{ stats.info }}</div>
              <div class="text-slate-500">信息</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 筛选区 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
        <el-form :inline="true" :model="filter" class="flex flex-wrap items-center gap-x-4 gap-y-2">
          <el-form-item label="资产名" class="mb-0">
            <el-input v-model="filter.name" placeholder="资产名称" clearable size="default" style="width: 160px" />
          </el-form-item>
          <el-form-item label="IP" class="mb-0">
            <el-input v-model="filter.ip" placeholder="IP 地址" clearable size="default" style="width: 160px" />
          </el-form-item>
          <el-form-item label="MAC" class="mb-0">
            <el-input v-model="filter.mac" placeholder="MAC 地址" clearable size="default" style="width: 160px" />
          </el-form-item>
          <el-form-item label="风险等级" class="mb-0">
            <el-select v-model="filter.risk_level" placeholder="请选择" clearable size="default" style="width: 130px">
              <el-option v-for="opt in riskLevelOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="操作系统" class="mb-0">
            <el-input v-model="filter.os" placeholder="操作系统" clearable size="default" style="width: 140px" />
          </el-form-item>
          <el-form-item label="标签" class="mb-0">
            <el-input v-model="filter.tags" placeholder="标签" clearable size="default" style="width: 140px" />
          </el-form-item>
          <template v-if="filterExpanded">
            <el-form-item label="权重" class="mb-0">
              <el-input v-model="filter.weight" placeholder="权重" clearable size="default" style="width: 120px" />
            </el-form-item>
            <el-form-item label="主机类型" class="mb-0">
              <el-input v-model="filter.host_type" placeholder="主机类型" clearable size="default" style="width: 140px" />
            </el-form-item>
            <el-form-item label="配置规范" class="mb-0">
              <el-input v-model="filter.config_spec" placeholder="配置规范" clearable size="default" style="width: 140px" />
            </el-form-item>
            <el-form-item label="负责人" class="mb-0">
              <el-input v-model="filter.owner" placeholder="负责人" clearable size="default" style="width: 140px" />
            </el-form-item>
            <el-form-item label="联系方式" class="mb-0">
              <el-input v-model="filter.contact" placeholder="联系方式" clearable size="default" style="width: 140px" />
            </el-form-item>
            <el-form-item label="邮箱" class="mb-0">
              <el-input v-model="filter.email" placeholder="邮箱" clearable size="default" style="width: 160px" />
            </el-form-item>
          </template>
          <el-form-item class="mb-0">
            <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
            <el-button :icon="RefreshCw" @click="handleResetFilter">重置</el-button>
            <el-button link type="primary" @click="toggleFilterExpand">
              {{ filterExpanded ? '收起' : '展开' }}
              <component :is="filterExpanded ? ChevronUp : ChevronDown" class="h-4 w-4" />
            </el-button>
          </el-form-item>
        </el-form>
      </div>

      <!-- Tab 与操作栏 -->
      <div class="flex items-center justify-between">
        <el-tabs v-model="activeTab" @tab-change="handleTabChange" class="flex-1">
          <el-tab-pane
            v-for="opt in assetKindOptions"
            :key="opt.value"
            :label="opt.label"
            :name="opt.value"
          />
        </el-tabs>
        <div class="flex items-center gap-2">
          <el-button :icon="Radar" @click="goDiscovery">资产发现</el-button>
          <el-button :icon="Download" @click="handleDownloadTemplate">下载模板</el-button>
          <el-upload
            :show-file-list="false"
            :http-request="handleImport"
            :accept="'.xlsx,.xls'"
          >
            <el-button :icon="Upload">上传导入</el-button>
          </el-upload>
          <el-button :icon="Download" @click="handleExport">导出</el-button>
          <el-button :icon="RefreshCw" circle @click="loadData" />
          <el-button
            v-if="currentSelected.length > 0"
            type="danger"
            :icon="Trash2"
            @click="handleBatchDelete"
          >
            批量删除 ({{ currentSelected.length }})
          </el-button>
          <el-button type="primary" :icon="Plus" @click="openCreateDialog">
            新增{{ assetKindOptions.find((o) => o.value === activeTab)?.label }}
          </el-button>
        </div>
      </div>

      <!-- 网络资产表格 -->
      <el-table
        v-show="activeTab === 'network'"
        :data="store.networkAssets"
        v-loading="store.networkLoading"
        @selection-change="handleSelectionChange"
        stripe
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="name" label="资产名称" min-width="140" />
        <el-table-column prop="ip" label="IP 地址" width="130" />
        <el-table-column label="资产类型" width="90">
          <template #default="{ row }">
            <el-tag size="small">{{ assetTypeLabel(row.asset_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="标签" width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <template v-if="toTagArray(row.tags).length">
              <el-tag
                v-for="t in toTagArray(row.tags)"
                :key="t"
                size="small"
                class="mr-1"
                type="info"
              >{{ t }}</el-tag>
            </template>
            <span v-else class="text-slate-500">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="weight" label="权重" width="70">
          <template #default="{ row }">{{ row.weight || '-' }}</template>
        </el-table-column>
        <el-table-column label="端口数" width="70">
          <template #default><span class="text-slate-500">-</span></template>
        </el-table-column>
        <el-table-column label="风险端口" width="80">
          <template #default><span class="text-slate-500">-</span></template>
        </el-table-column>
        <el-table-column label="弱密码" width="70">
          <template #default><span class="text-slate-500">-</span></template>
        </el-table-column>
        <el-table-column label="漏洞数（严/高/中/低/信）" width="170">
          <template #default>
            <span class="text-slate-500">- / - / - / - / -</span>
          </template>
        </el-table-column>
        <el-table-column prop="mac" label="MAC" width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.mac || '-' }}</template>
        </el-table-column>
        <el-table-column prop="os" label="操作系统" width="120" show-overflow-tooltip>
          <template #default="{ row }">{{ row.os || '-' }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="risk_score" label="风险评分" width="85">
          <template #default="{ row }">{{ row.risk_score?.toFixed(1) ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="is_industrial" label="工控" width="65">
          <template #default="{ row }">
            <el-tag v-if="row.is_industrial" type="warning" size="small">是</el-tag>
            <span v-else class="text-slate-500">否</span>
          </template>
        </el-table-column>
        <el-table-column prop="owner" label="负责人" width="100" show-overflow-tooltip>
          <template #default="{ row }">{{ row.owner || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="ScanLine" @click="goScan(row)">扫描</el-button>
            <el-button link type="primary" :icon="TrendingUp" @click="goTrend(row)">趋势</el-button>
            <el-button link type="primary" :icon="Pencil" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" :icon="Trash2" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 应用资产表格 -->
      <el-table
        v-show="activeTab === 'application'"
        :data="store.applicationAssets"
        v-loading="store.applicationLoading"
        @selection-change="handleSelectionChange"
        stripe
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="name" label="资产名称" min-width="140" />
        <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
        <el-table-column label="资产类型" width="90">
          <template #default>
            <el-tag size="small" type="success">应用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="标签" width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <template v-if="toTagArray(row.tags).length">
              <el-tag v-for="t in toTagArray(row.tags)" :key="t" size="small" class="mr-1" type="info">{{ t }}</el-tag>
            </template>
            <span v-else class="text-slate-500">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="weight" label="权重" width="70">
          <template #default="{ row }">{{ row.weight || '-' }}</template>
        </el-table-column>
        <el-table-column prop="title" label="站点标题" width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.title || '-' }}</template>
        </el-table-column>
        <el-table-column prop="ip" label="IP" width="130">
          <template #default="{ row }">{{ row.ip || '-' }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="risk_score" label="风险评分" width="85">
          <template #default="{ row }">{{ row.risk_score?.toFixed(1) ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="owner" label="负责人" width="100" show-overflow-tooltip>
          <template #default="{ row }">{{ row.owner || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="ScanLine" @click="goScan(row)">扫描</el-button>
            <el-button link type="primary" :icon="TrendingUp" @click="goTrend(row)">趋势</el-button>
            <el-button link type="primary" :icon="Pencil" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" :icon="Trash2" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 数据库资产表格 -->
      <el-table
        v-show="activeTab === 'database'"
        :data="store.databaseAssets"
        v-loading="store.databaseLoading"
        @selection-change="handleSelectionChange"
        stripe
        style="width: 100%"
      >
        <el-table-column type="selection" width="42" />
        <el-table-column prop="name" label="资产名称" min-width="140" />
        <el-table-column prop="ip" label="IP" width="130" />
        <el-table-column prop="db_type" label="数据库类型" width="110" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="db_name" label="库名" width="120" show-overflow-tooltip>
          <template #default="{ row }">{{ row.db_name || '-' }}</template>
        </el-table-column>
        <el-table-column label="标签" width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <template v-if="toTagArray(row.tags).length">
              <el-tag v-for="t in toTagArray(row.tags)" :key="t" size="small" class="mr-1" type="info">{{ t }}</el-tag>
            </template>
            <span v-else class="text-slate-500">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="weight" label="权重" width="70">
          <template #default="{ row }">{{ row.weight || '-' }}</template>
        </el-table-column>
        <el-table-column prop="enable_ssl" label="SSL" width="65">
          <template #default="{ row }">
            <el-tag v-if="row.enable_ssl" type="success" size="small">是</el-tag>
            <span v-else class="text-slate-500">否</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="risk_score" label="风险评分" width="85">
          <template #default="{ row }">{{ row.risk_score?.toFixed(1) ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="owner" label="负责人" width="100" show-overflow-tooltip>
          <template #default="{ row }">{{ row.owner || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :icon="ScanLine" @click="goScan(row)">扫描</el-button>
            <el-button link type="primary" :icon="TrendingUp" @click="goTrend(row)">趋势</el-button>
            <el-button link type="primary" :icon="Pencil" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" :icon="Trash2" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="flex justify-end pt-2">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="currentTotal"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadData"
          @size-change="loadData"
        />
      </div>

      <!-- 新增/编辑弹窗 -->
      <el-dialog
        v-model="dialogVisible"
        :title="dialogMode === 'create' ? '新增资产' : '编辑资产'"
        width="780px"
        :close-on-click-modal="false"
      >
        <!-- 网络资产表单 -->
        <el-form v-if="activeTab === 'network'" :model="networkForm" label-width="110px" label-position="right">
          <div class="grid grid-cols-2 gap-x-3">
            <el-form-item label="资产名称" required>
              <el-input v-model="networkForm.name" placeholder="请输入资产名称" />
            </el-form-item>
            <el-form-item label="IP 地址" required>
              <el-input v-model="networkForm.ip" placeholder="例: 192.168.1.10" />
            </el-form-item>
            <el-form-item label="MAC 地址">
              <el-input v-model="networkForm.mac" placeholder="可选" />
            </el-form-item>
            <el-form-item label="操作系统">
              <el-input v-model="networkForm.os" placeholder="可选" />
            </el-form-item>
            <el-form-item label="设备编号">
              <el-input v-model="networkForm.device_no" placeholder="可选" />
            </el-form-item>
            <el-form-item label="网络区域">
              <el-select v-model="networkForm.network_zone" placeholder="选择网络区域" clearable>
                <el-option v-for="opt in networkZoneOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="所属业务系统">
              <el-input v-model="networkForm.business_system" placeholder="可选" />
            </el-form-item>
            <el-form-item label="资产组">
              <el-select v-model="networkForm.asset_group_id" placeholder="选择资产组" clearable filterable>
                <el-option v-for="g in flatGroups" :key="g.id" :label="g.name" :value="g.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="登录凭证">
              <el-select v-model="networkForm.credential_id" placeholder="选择凭证" clearable filterable>
                <el-option v-for="c in credentials" :key="c.id" :label="`${c.name} (${c.username})`" :value="c.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="配置规范">
              <el-input v-model="networkForm.config_spec" placeholder="可选" />
            </el-form-item>
            <el-form-item label="等级保护级别">
              <el-select v-model="networkForm.protection_level" placeholder="选择级别" clearable>
                <el-option v-for="opt in protectionLevelOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="权重">
              <el-input v-model="networkForm.weight" placeholder="可选" />
            </el-form-item>
            <el-form-item label="负责人">
              <el-input v-model="networkForm.owner" placeholder="可选" />
            </el-form-item>
            <el-form-item label="联系方式">
              <el-input v-model="networkForm.contact" placeholder="可选" />
            </el-form-item>
            <el-form-item label="邮箱">
              <el-input v-model="networkForm.email" placeholder="可选" />
            </el-form-item>
            <el-form-item label="位置">
              <el-input v-model="networkForm.location" placeholder="可选" />
            </el-form-item>
          </div>

          <el-form-item label="标签">
            <div class="flex flex-wrap items-center gap-2">
              <el-tag v-for="t in networkForm.tags" :key="t" closable @close="networkForm.tags = networkForm.tags.filter(x => x !== t)">{{ t }}</el-tag>
              <el-input v-model="networkForm.tagInput" placeholder="输入标签回车添加" style="width: 180px" @keyup.enter="addNetworkTag" />
            </div>
          </el-form-item>

          <el-form-item label="机密性">
            <el-select v-model="networkForm.confidentiality" placeholder="选择" clearable>
              <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="完整性">
            <el-select v-model="networkForm.integrity" placeholder="选择" clearable>
              <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="可用性">
            <el-select v-model="networkForm.availability" placeholder="选择" clearable>
              <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="重要性">
            <el-select v-model="networkForm.importance" placeholder="选择" clearable>
              <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
          </el-form-item>

          <el-form-item label="目标自动识别">
            <el-switch v-model="networkForm.auto_identify" />
          </el-form-item>
          <el-form-item label="工控设备">
            <el-switch v-model="networkForm.is_industrial" />
          </el-form-item>
          <el-form-item label="可信设备">
            <el-switch v-model="networkForm.trusted_device" />
          </el-form-item>

          <!-- 工控字段（仅工控资产显示） -->
          <template v-if="networkForm.is_industrial">
            <div class="grid grid-cols-2 gap-x-3">
              <el-form-item label="工控设备类型">
                <el-input v-model="networkForm.industrial_device_type" placeholder="可选" />
              </el-form-item>
              <el-form-item label="工控厂商">
                <el-input v-model="networkForm.industrial_vendor" placeholder="可选" />
              </el-form-item>
              <el-form-item label="工控型号">
                <el-input v-model="networkForm.industrial_model" placeholder="可选" />
              </el-form-item>
              <el-form-item label="工控版本">
                <el-input v-model="networkForm.industrial_version" placeholder="可选" />
              </el-form-item>
            </div>
          </template>

          <el-form-item label="描述">
            <el-input v-model="networkForm.description" type="textarea" :rows="2" placeholder="可选" />
          </el-form-item>
        </el-form>

        <!-- 应用资产表单 -->
        <el-form v-else-if="activeTab === 'application'" :model="appForm" label-width="110px" label-position="right">
          <div class="grid grid-cols-2 gap-x-3">
            <el-form-item label="资产名称" required>
              <el-input v-model="appForm.name" placeholder="请输入资产名称" />
            </el-form-item>
            <el-form-item label="URL" required>
              <el-input v-model="appForm.url" placeholder="https://example.com" />
            </el-form-item>
            <el-form-item label="站点标题">
              <el-input v-model="appForm.title" placeholder="可选" />
            </el-form-item>
            <el-form-item label="IP 地址">
              <el-input v-model="appForm.ip" placeholder="可选" />
            </el-form-item>
            <el-form-item label="设备编号">
              <el-input v-model="appForm.device_no" placeholder="可选" />
            </el-form-item>
            <el-form-item label="网络区域">
              <el-select v-model="appForm.network_zone" placeholder="选择网络区域" clearable>
                <el-option v-for="opt in networkZoneOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="所属业务系统">
              <el-input v-model="appForm.business_system" placeholder="可选" />
            </el-form-item>
            <el-form-item label="技术栈">
              <el-input v-model="appForm.tech_stack" placeholder="可选，如 Nginx+PHP+MySQL" />
            </el-form-item>
            <el-form-item label="资产组">
              <el-select v-model="appForm.asset_group_id" placeholder="选择资产组" clearable filterable>
                <el-option v-for="g in flatGroups" :key="g.id" :label="g.name" :value="g.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="登录凭证">
              <el-select v-model="appForm.credential_id" placeholder="选择凭证" clearable filterable>
                <el-option v-for="c in credentials" :key="c.id" :label="`${c.name} (${c.username})`" :value="c.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="配置规范">
              <el-input v-model="appForm.config_spec" placeholder="可选" />
            </el-form-item>
            <el-form-item label="等级保护级别">
              <el-select v-model="appForm.protection_level" placeholder="选择级别" clearable>
                <el-option v-for="opt in protectionLevelOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="负责人">
              <el-input v-model="appForm.owner" placeholder="可选" />
            </el-form-item>
            <el-form-item label="联系方式">
              <el-input v-model="appForm.contact" placeholder="可选" />
            </el-form-item>
            <el-form-item label="邮箱">
              <el-input v-model="appForm.email" placeholder="可选" />
            </el-form-item>
          </div>

          <el-form-item label="标签">
            <div class="flex flex-wrap items-center gap-2">
              <el-tag v-for="t in appForm.tags" :key="t" closable @close="appForm.tags = appForm.tags.filter(x => x !== t)">{{ t }}</el-tag>
              <el-input v-model="appForm.tagInput" placeholder="输入标签回车添加" style="width: 180px" @keyup.enter="addAppTag" />
            </div>
          </el-form-item>

          <div class="grid grid-cols-2 gap-x-3">
            <el-form-item label="机密性">
              <el-select v-model="appForm.confidentiality" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="完整性">
              <el-select v-model="appForm.integrity" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="可用性">
              <el-select v-model="appForm.availability" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="重要性">
              <el-select v-model="appForm.importance" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
          </div>

          <el-form-item label="目标自动识别">
            <el-switch v-model="appForm.auto_identify" />
          </el-form-item>
          <el-form-item label="自动抓取">
            <el-switch v-model="appForm.auto_fetch" />
          </el-form-item>
          <el-form-item label="可信设备">
            <el-switch v-model="appForm.trusted_device" />
          </el-form-item>
          <el-form-item label="描述">
            <el-input v-model="appForm.description" type="textarea" :rows="2" placeholder="可选" />
          </el-form-item>
        </el-form>

        <!-- 数据库资产表单 -->
        <el-form v-else :model="dbForm" label-width="110px" label-position="right">
          <div class="grid grid-cols-2 gap-x-3">
            <el-form-item label="资产名称" required>
              <el-input v-model="dbForm.name" placeholder="请输入资产名称" />
            </el-form-item>
            <el-form-item label="IP 地址" required>
              <el-input v-model="dbForm.ip" placeholder="例: 192.168.1.20" />
            </el-form-item>
            <el-form-item label="数据库类型" required>
              <el-select v-model="dbForm.db_type" placeholder="选择数据库类型">
                <el-option v-for="opt in dbTypeOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="端口" required>
              <el-input-number v-model="dbForm.port" :min="1" :max="65535" />
            </el-form-item>
            <el-form-item label="数据库版本">
              <el-input v-model="dbForm.db_version" placeholder="可选，如 8.0.32" />
            </el-form-item>
            <el-form-item label="库名">
              <el-input v-model="dbForm.db_name" placeholder="可选" />
            </el-form-item>
            <el-form-item label="用户名">
              <el-input v-model="dbForm.username" placeholder="可选" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="dbForm.password" type="password" show-password placeholder="可选" />
            </el-form-item>
            <el-form-item label="连接串">
              <el-input v-model="dbForm.connection_string" placeholder="可选，如 mysql://host:3306/db" />
            </el-form-item>
            <el-form-item label="登录凭证">
              <el-select v-model="dbForm.credential_id" placeholder="选择凭证" clearable filterable>
                <el-option v-for="c in credentials" :key="c.id" :label="`${c.name} (${c.username})`" :value="c.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="设备编号">
              <el-input v-model="dbForm.device_no" placeholder="可选" />
            </el-form-item>
            <el-form-item label="网络区域">
              <el-select v-model="dbForm.network_zone" placeholder="选择网络区域" clearable>
                <el-option v-for="opt in networkZoneOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="所属业务系统">
              <el-input v-model="dbForm.business_system" placeholder="可选" />
            </el-form-item>
            <el-form-item label="资产组">
              <el-select v-model="dbForm.asset_group_id" placeholder="选择资产组" clearable filterable>
                <el-option v-for="g in flatGroups" :key="g.id" :label="g.name" :value="g.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="配置规范">
              <el-input v-model="dbForm.config_spec" placeholder="可选" />
            </el-form-item>
            <el-form-item label="等级保护级别">
              <el-select v-model="dbForm.protection_level" placeholder="选择级别" clearable>
                <el-option v-for="opt in protectionLevelOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="负责人">
              <el-input v-model="dbForm.owner" placeholder="可选" />
            </el-form-item>
            <el-form-item label="联系方式">
              <el-input v-model="dbForm.contact" placeholder="可选" />
            </el-form-item>
            <el-form-item label="邮箱">
              <el-input v-model="dbForm.email" placeholder="可选" />
            </el-form-item>
          </div>

          <el-form-item label="标签">
            <div class="flex flex-wrap items-center gap-2">
              <el-tag v-for="t in dbForm.tags" :key="t" closable @close="dbForm.tags = dbForm.tags.filter(x => x !== t)">{{ t }}</el-tag>
              <el-input v-model="dbForm.tagInput" placeholder="输入标签回车添加" style="width: 180px" @keyup.enter="addDbTag" />
            </div>
          </el-form-item>

          <div class="grid grid-cols-2 gap-x-3">
            <el-form-item label="机密性">
              <el-select v-model="dbForm.confidentiality" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="完整性">
              <el-select v-model="dbForm.integrity" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="可用性">
              <el-select v-model="dbForm.availability" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
            <el-form-item label="重要性">
              <el-select v-model="dbForm.importance" placeholder="选择" clearable>
                <el-option v-for="opt in ciaOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
            </el-form-item>
          </div>

          <el-form-item label="目标自动识别">
            <el-switch v-model="dbForm.auto_identify" />
          </el-form-item>
          <el-form-item label="启用 SSL">
            <el-switch v-model="dbForm.enable_ssl" />
          </el-form-item>
          <el-form-item label="登录扫描">
            <el-switch v-model="dbForm.execute_login_scan" />
          </el-form-item>
          <el-form-item label="可信设备">
            <el-switch v-model="dbForm.trusted_device" />
          </el-form-item>
          <el-form-item label="描述">
            <el-input v-model="dbForm.description" type="textarea" :rows="2" placeholder="可选" />
          </el-form-item>
        </el-form>

        <template #footer>
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="dialogLoading" @click="handleSubmit">
            {{ dialogMode === 'create' ? '创建' : '保存' }}
          </el-button>
        </template>
      </el-dialog>

      <!-- 资产组新增/编辑弹窗 -->
      <el-dialog
        v-model="groupDialogVisible"
        :title="groupDialogMode === 'create' ? '新增资产组' : '编辑资产组'"
        width="520px"
        :close-on-click-modal="false"
      >
        <el-form :model="groupForm" label-width="100px" label-position="right">
          <el-form-item label="名称" required>
            <el-input v-model="groupForm.name" placeholder="请输入资产组名称" />
          </el-form-item>
          <el-form-item label="负责人">
            <el-input v-model="groupForm.owner" placeholder="可选" />
          </el-form-item>
          <el-form-item label="联系方式">
            <el-input v-model="groupForm.contact" placeholder="可选" />
          </el-form-item>
          <el-form-item label="邮箱">
            <el-input v-model="groupForm.email" placeholder="可选" />
          </el-form-item>
          <el-form-item label="位置">
            <el-input v-model="groupForm.location" placeholder="可选" />
          </el-form-item>
          <el-form-item label="资产范围">
            <el-input v-model="groupForm.ip_range" placeholder="IP/掩码，如 192.168.1.0/24" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="groupDialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="groupLoadingSubmit" @click="handleGroupSubmit">
            {{ groupDialogMode === 'create' ? '创建' : '保存' }}
          </el-button>
        </template>
      </el-dialog>
    </div>
  </div>
</template>
