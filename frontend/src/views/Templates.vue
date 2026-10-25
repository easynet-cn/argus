<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Plus,
  RefreshCw,
  Trash2,
  Copy,
  Download,
  Upload,
  Check,
  FileJson,
  Layers,
  KeyRound,
  ShieldCheck,
  Settings,
  AlertTriangle,
  Server,
  Scan,
} from '@lucide/vue'
import {
  scanTemplateApi,
  portTemplateApi,
  dictionaryApi,
  comboDictionaryApi,
  certificateApi,
  paramTemplateApi,
  configTemplateApi,
  serviceRiskApi,
  portViolationApi,
  fingerprintRuleApi,
  type ScanTemplate,
  type PortTemplate,
  type Dictionary,
  type ComboDictionary,
  type Certificate,
  type ParamTemplate,
  type ConfigTemplate,
  type ServiceRisk,
  type PortViolation,
  type FingerprintRule,
  type ParamSchema,
} from '@/api/template'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
// 用于上传时携带 token 到请求头
const uploadHeaders = computed(() => ({
  Authorization: `Bearer ${authStore.token}`,
}))

// 主 tab 与风险子 tab
const activeTab = ref('scan')
const riskSubTab = ref('port-violation')

// ==================== 通用分页处理 ====================
const pageSize = 20

// ==================== 1. 扫描模板 ====================
const scanTemplateList = ref<ScanTemplate[]>([])
const scanTemplateLoading = ref(false)
const scanTemplatePage = ref(1)
const scanTemplateTotal = ref(0)
const scanTemplateDialogVisible = ref(false)
const scanTemplateSubmitting = ref(false)
const scanTemplateForm = reactive({
  id: '',
  name: '',
  type: '',
  description: '',
  content: '{}',
})

const scanTemplateTypes = [
  'port',
  'vuln',
  'baseline',
  'bruteforce',
  'ics',
  'web',
  'database',
  'system',
]

async function loadScanTemplates() {
  scanTemplateLoading.value = true
  try {
    const res = await scanTemplateApi.list({
      page: scanTemplatePage.value,
      page_size: pageSize,
    })
    scanTemplateList.value = res.items
    scanTemplateTotal.value = res.total ?? res.items.length
  } finally {
    scanTemplateLoading.value = false
  }
}

function openScanTemplateDialog() {
  scanTemplateForm.id = ''
  scanTemplateForm.name = ''
  scanTemplateForm.type = ''
  scanTemplateForm.description = ''
  scanTemplateForm.content = '{}'
  scanTemplateDialogVisible.value = true
}

async function submitScanTemplate() {
  if (!scanTemplateForm.name || !scanTemplateForm.type) {
    ElMessage.warning('请填写名称和类型')
    return
  }
  let content: any
  try {
    content = JSON.parse(scanTemplateForm.content)
  } catch {
    ElMessage.error('内容必须是合法的 JSON')
    return
  }
  scanTemplateSubmitting.value = true
  try {
    await scanTemplateApi.create({
      name: scanTemplateForm.name,
      type: scanTemplateForm.type,
      description: scanTemplateForm.description,
      content,
    })
    ElMessage.success('扫描模板创建成功')
    scanTemplateDialogVisible.value = false
    await loadScanTemplates()
  } finally {
    scanTemplateSubmitting.value = false
  }
}

async function validateScanTemplate() {
  let content: any
  try {
    content = JSON.parse(scanTemplateForm.content)
  } catch {
    ElMessage.error('内容必须是合法的 JSON')
    return
  }
  try {
    const res = await scanTemplateApi.validate(content)
    if (res.valid) {
      ElMessage.success('模板 JSON 校验通过')
    } else {
      ElMessage.error(`校验失败：${res.message}`)
    }
  } catch {
    // 拦截器已处理
  }
}

function formatTime(s?: string) {
  if (!s) return '-'
  return s.replace('T', ' ').slice(0, 19)
}

// ==================== 2. 端口模板 ====================
const portTemplateList = ref<PortTemplate[]>([])
const portTemplateLoading = ref(false)
const portTemplatePage = ref(1)
const portTemplateTotal = ref(0)
const portTemplateDialogVisible = ref(false)
const portTemplateSubmitting = ref(false)
const portTemplateForm = reactive({
  id: '',
  name: '',
  port_range: '',
  description: '',
})

async function loadPortTemplates() {
  portTemplateLoading.value = true
  try {
    const res = await portTemplateApi.list({
      page: portTemplatePage.value,
      page_size: pageSize,
    })
    portTemplateList.value = res.items
    portTemplateTotal.value = res.total ?? res.items.length
  } finally {
    portTemplateLoading.value = false
  }
}

function openPortTemplateDialog() {
  portTemplateForm.id = ''
  portTemplateForm.name = ''
  portTemplateForm.port_range = ''
  portTemplateForm.description = ''
  portTemplateDialogVisible.value = true
}

async function submitPortTemplate() {
  if (!portTemplateForm.name || !portTemplateForm.port_range) {
    ElMessage.warning('请填写名称和端口范围')
    return
  }
  portTemplateSubmitting.value = true
  try {
    await portTemplateApi.create({
      name: portTemplateForm.name,
      port_range: portTemplateForm.port_range,
      description: portTemplateForm.description,
    })
    ElMessage.success('端口模板创建成功')
    portTemplateDialogVisible.value = false
    await loadPortTemplates()
  } finally {
    portTemplateSubmitting.value = false
  }
}

async function copyPortTemplate(row: PortTemplate) {
  try {
    await portTemplateApi.copy(row.id)
    ElMessage.success('端口模板已复制')
    await loadPortTemplates()
  } catch {
    // ignore
  }
}

async function deletePortTemplate(row: PortTemplate) {
  try {
    await ElMessageBox.confirm(`确定删除端口模板「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await portTemplateApi.remove(row.id)
    ElMessage.success('已删除')
    await loadPortTemplates()
  } catch {
    // 取消或失败
  }
}

// ==================== 3. 字典管理 ====================
const dictionaryList = ref<Dictionary[]>([])
const dictionaryLoading = ref(false)
const dictionaryPage = ref(1)
const dictionaryTotal = ref(0)
const dictionaryDialogVisible = ref(false)
const dictionarySubmitting = ref(false)
const dictionaryForm = reactive({
  id: '',
  name: '',
  type: 'username',
  description: '',
  entries: '',
})
// 社工字典生成
const socialDialogVisible = ref(false)
const socialSubmitting = ref(false)
const socialForm = reactive({
  name: '',
  keywords: '',
})

const dictionaryTypes = [
  { label: '用户名字典', value: 'username' },
  { label: '密码字典', value: 'password' },
  { label: '端口字典', value: 'port' },
  { label: '路径字典', value: 'path' },
  { label: '自定义', value: 'custom' },
]

async function loadDictionaries() {
  dictionaryLoading.value = true
  try {
    const res = await dictionaryApi.list({
      page: dictionaryPage.value,
      page_size: pageSize,
    })
    dictionaryList.value = res.items
    dictionaryTotal.value = res.total ?? res.items.length
  } finally {
    dictionaryLoading.value = false
  }
}

function openDictionaryDialog() {
  dictionaryForm.id = ''
  dictionaryForm.name = ''
  dictionaryForm.type = 'username'
  dictionaryForm.description = ''
  dictionaryForm.entries = ''
  dictionaryDialogVisible.value = true
}

async function submitDictionary() {
  if (!dictionaryForm.name) {
    ElMessage.warning('请填写字典名称')
    return
  }
  const entries = dictionaryForm.entries
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  dictionarySubmitting.value = true
  try {
    await dictionaryApi.create({
      name: dictionaryForm.name,
      type: dictionaryForm.type,
      description: dictionaryForm.description,
      entries: entries.length ? entries : undefined,
    })
    ElMessage.success('字典创建成功')
    dictionaryDialogVisible.value = false
    await loadDictionaries()
  } finally {
    dictionarySubmitting.value = false
  }
}

async function deleteDictionary(row: Dictionary) {
  try {
    await ElMessageBox.confirm(`确定删除字典「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await dictionaryApi.remove(row.id)
    ElMessage.success('已删除')
    await loadDictionaries()
  } catch {
    // ignore
  }
}

async function downloadDictionary(row: Dictionary) {
  try {
    const blob: any = await dictionaryApi.download(row.id)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.name}.txt`
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    // ignore
  }
}

// 字典上传
async function handleDictionaryUploadSuccess(_response: any) {
  ElMessage.success('字典文件上传成功')
  await loadDictionaries()
}

function handleDictionaryUploadError() {
  ElMessage.error('字典文件上传失败')
}

// 社工字典
function openSocialDialog() {
  socialForm.name = ''
  socialForm.keywords = ''
  socialDialogVisible.value = true
}

async function submitSocialEngineer() {
  if (!socialForm.name || !socialForm.keywords.trim()) {
    ElMessage.warning('请填写字典名称和关键词')
    return
  }
  const keywords = socialForm.keywords
    .split(/[\s,，;；]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  socialSubmitting.value = true
  try {
    await dictionaryApi.socialEngineer({
      name: socialForm.name,
      keywords,
    })
    ElMessage.success('社工字典生成成功')
    socialDialogVisible.value = false
    await loadDictionaries()
  } finally {
    socialSubmitting.value = false
  }
}

// ==================== 4. 组合字典 ====================
const comboList = ref<ComboDictionary[]>([])
const comboLoading = ref(false)
const comboPage = ref(1)
const comboTotal = ref(0)
const comboDialogVisible = ref(false)
const comboSubmitting = ref(false)
const comboForm = reactive({
  id: '',
  name: '',
  username_dict_id: '',
  password_dict_id: '',
  description: '',
})
// 可选字典列表（用户名字典 / 密码字典）
const dictOptions = ref<{ id: string; name: string; type: string }[]>([])

async function loadComboDicts() {
  comboLoading.value = true
  try {
    const res = await comboDictionaryApi.list({
      page: comboPage.value,
      page_size: pageSize,
    })
    comboList.value = res.items
    comboTotal.value = res.total ?? res.items.length
  } finally {
    comboLoading.value = false
  }
}

async function loadDictOptions() {
  try {
    const res = await dictionaryApi.list({ page: 1, page_size: 1000 })
    dictOptions.value = res.items.map((d) => ({
      id: d.id,
      name: d.name,
      type: d.type,
    }))
  } catch {
    // ignore
  }
}

function openComboDialog() {
  comboForm.id = ''
  comboForm.name = ''
  comboForm.username_dict_id = ''
  comboForm.password_dict_id = ''
  comboForm.description = ''
  comboDialogVisible.value = true
  loadDictOptions()
}

const usernameDictOptions = computed(() =>
  dictOptions.value.filter((d) => d.type === 'username' || d.type === 'custom'),
)
const passwordDictOptions = computed(() =>
  dictOptions.value.filter((d) => d.type === 'password' || d.type === 'custom'),
)

async function submitCombo() {
  if (!comboForm.name || !comboForm.username_dict_id || !comboForm.password_dict_id) {
    ElMessage.warning('请填写名称并选择用户名字典和密码字典')
    return
  }
  comboSubmitting.value = true
  try {
    await comboDictionaryApi.create({
      name: comboForm.name,
      username_dict_id: comboForm.username_dict_id,
      password_dict_id: comboForm.password_dict_id,
      description: comboForm.description,
    })
    ElMessage.success('组合字典创建成功')
    comboDialogVisible.value = false
    await loadComboDicts()
  } finally {
    comboSubmitting.value = false
  }
}

async function deleteCombo(row: ComboDictionary) {
  try {
    await ElMessageBox.confirm(`确定删除组合字典「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await comboDictionaryApi.remove(row.id)
    ElMessage.success('已删除')
    await loadComboDicts()
  } catch {
    // ignore
  }
}

// ==================== 5. 证书管理 ====================
const certList = ref<Certificate[]>([])
const certLoading = ref(false)
const certPage = ref(1)
const certTotal = ref(0)
const certDialogVisible = ref(false)
const certSubmitting = ref(false)
const certForm = reactive({
  id: '',
  name: '',
  type: 'pem',
  content: '',
  expires_at: '',
  description: '',
})

const certTypes = [
  { label: 'PEM', value: 'pem' },
  { label: 'DER', value: 'der' },
  { label: 'PKCS12', value: 'pkcs12' },
  { label: 'JKS', value: 'jks' },
]

async function loadCertificates() {
  certLoading.value = true
  try {
    const res = await certificateApi.list({
      page: certPage.value,
      page_size: pageSize,
    })
    certList.value = res.items
    certTotal.value = res.total ?? res.items.length
  } finally {
    certLoading.value = false
  }
}

function openCertDialog() {
  certForm.id = ''
  certForm.name = ''
  certForm.type = 'pem'
  certForm.content = ''
  certForm.expires_at = ''
  certForm.description = ''
  certDialogVisible.value = true
}

async function submitCert() {
  if (!certForm.name) {
    ElMessage.warning('请填写证书名称')
    return
  }
  certSubmitting.value = true
  try {
    await certificateApi.create({
      name: certForm.name,
      type: certForm.type,
      content: certForm.content || undefined,
      expires_at: certForm.expires_at || undefined,
      description: certForm.description,
    })
    ElMessage.success('证书创建成功')
    certDialogVisible.value = false
    await loadCertificates()
  } finally {
    certSubmitting.value = false
  }
}

async function deleteCert(row: Certificate) {
  try {
    await ElMessageBox.confirm(`确定删除证书「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await certificateApi.remove(row.id)
    ElMessage.success('已删除')
    await loadCertificates()
  } catch {
    // ignore
  }
}

async function downloadCert(row: Certificate) {
  try {
    const blob: any = await certificateApi.download(row.id)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.name}.${row.type}`
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    // ignore
  }
}

// ==================== 6. 参数模板 ====================
const paramList = ref<ParamTemplate[]>([])
const paramLoading = ref(false)
const paramPage = ref(1)
const paramTotal = ref(0)
const paramDialogVisible = ref(false)
const paramSubmitting = ref(false)
const paramForm = reactive({
  id: '',
  name: '',
  scan_type: '',
  description: '',
  content: {} as Record<string, any>,
})
const paramSchema = ref<ParamSchema | null>(null)
const paramSchemaLoading = ref(false)
// 导入
const importDialogVisible = ref(false)
const importContent = ref('')
const importSubmitting = ref(false)

const scanTypeOptions = [
  'port',
  'vuln',
  'baseline',
  'bruteforce',
  'ics',
  'web',
  'database',
  'system',
  'passive',
  'container',
]

async function loadParams() {
  paramLoading.value = true
  try {
    const res = await paramTemplateApi.list({
      page: paramPage.value,
      page_size: pageSize,
    })
    paramList.value = res.items
    paramTotal.value = res.total ?? res.items.length
  } finally {
    paramLoading.value = false
  }
}

async function loadParamSchema(scanType: string) {
  paramSchemaLoading.value = true
  try {
    paramSchema.value = await paramTemplateApi.schema(scanType)
    // 初始化 content 默认值
    const content: Record<string, any> = {}
    for (const f of paramSchema.value.fields) {
      content[f.key] = f.default ?? (f.type === 'boolean' ? false : '')
    }
    paramForm.content = content
  } catch {
    paramSchema.value = null
  } finally {
    paramSchemaLoading.value = false
  }
}

watch(
  () => paramForm.scan_type,
  (v) => {
    if (v) loadParamSchema(v)
    else paramSchema.value = null
  },
)

function openParamDialog() {
  paramForm.id = ''
  paramForm.name = ''
  paramForm.scan_type = ''
  paramForm.description = ''
  paramForm.content = {}
  paramSchema.value = null
  paramDialogVisible.value = true
}

async function submitParam() {
  if (!paramForm.name || !paramForm.scan_type) {
    ElMessage.warning('请填写名称和扫描类型')
    return
  }
  paramSubmitting.value = true
  try {
    await paramTemplateApi.create({
      name: paramForm.name,
      scan_type: paramForm.scan_type,
      content: paramForm.content,
      description: paramForm.description,
    })
    ElMessage.success('参数模板创建成功')
    paramDialogVisible.value = false
    await loadParams()
  } finally {
    paramSubmitting.value = false
  }
}

async function setParamDefault(row: ParamTemplate) {
  try {
    await paramTemplateApi.setDefault(row.id)
    ElMessage.success('已设为默认参数模板')
    await loadParams()
  } catch {
    // ignore
  }
}

async function copyParam(row: ParamTemplate) {
  try {
    await paramTemplateApi.copy(row.id)
    ElMessage.success('参数模板已复制')
    await loadParams()
  } catch {
    // ignore
  }
}

async function exportParam(row: ParamTemplate) {
  try {
    const blob: any = await paramTemplateApi.export(row.id)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.name}.json`
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    // ignore
  }
}

async function deleteParam(row: ParamTemplate) {
  try {
    await ElMessageBox.confirm(`确定删除参数模板「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await paramTemplateApi.remove(row.id)
    ElMessage.success('已删除')
    await loadParams()
  } catch {
    // ignore
  }
}

// 导入参数模板
function openImportDialog() {
  importContent.value = ''
  importDialogVisible.value = true
}

async function submitImportParam() {
  let data: any
  try {
    data = JSON.parse(importContent.value)
  } catch {
    ElMessage.error('请输入合法的 JSON 内容')
    return
  }
  importSubmitting.value = true
  try {
    await paramTemplateApi.importTemplate(data)
    ElMessage.success('参数模板导入成功')
    importDialogVisible.value = false
    await loadParams()
  } finally {
    importSubmitting.value = false
  }
}

// ==================== 7. 配置模板（基线） ====================
const configList = ref<ConfigTemplate[]>([])
const configLoading = ref(false)
const configPage = ref(1)
const configTotal = ref(0)
const configDialogVisible = ref(false)
const configSubmitting = ref(false)
const configForm = reactive({
  id: '',
  name: '',
  description: '',
  content: '{}',
})

async function loadConfigs() {
  configLoading.value = true
  try {
    const res = await configTemplateApi.list({
      page: configPage.value,
      page_size: pageSize,
    })
    configList.value = res.items
    configTotal.value = res.total ?? res.items.length
  } finally {
    configLoading.value = false
  }
}

function openConfigDialog() {
  configForm.id = ''
  configForm.name = ''
  configForm.description = ''
  configForm.content = '{}'
  configDialogVisible.value = true
}

async function submitConfig() {
  if (!configForm.name) {
    ElMessage.warning('请填写配置模板名称')
    return
  }
  let content: any
  try {
    content = JSON.parse(configForm.content)
  } catch {
    ElMessage.error('内容必须是合法的 JSON')
    return
  }
  configSubmitting.value = true
  try {
    await configTemplateApi.create({
      name: configForm.name,
      description: configForm.description,
      content,
    })
    ElMessage.success('配置模板创建成功')
    configDialogVisible.value = false
    await loadConfigs()
  } finally {
    configSubmitting.value = false
  }
}

async function deleteConfig(row: ConfigTemplate) {
  try {
    await ElMessageBox.confirm(`确定删除配置模板「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await configTemplateApi.remove(row.id)
    ElMessage.success('已删除')
    await loadConfigs()
  } catch {
    // ignore
  }
}

// ==================== 8. 端口违规 / 服务风险 ====================
// 8.1 端口违规
const portViolationList = ref<PortViolation[]>([])
const portViolationLoading = ref(false)
const portViolationPage = ref(1)
const portViolationTotal = ref(0)
const portViolationDialogVisible = ref(false)
const portViolationSubmitting = ref(false)
const portViolationForm = reactive({
  id: '',
  port: 0,
  protocol: 'tcp',
  risk_level: 'high' as 'low' | 'medium' | 'high' | 'critical',
  description: '',
})

// 8.2 服务风险
const serviceRiskList = ref<ServiceRisk[]>([])
const serviceRiskLoading = ref(false)
const serviceRiskPage = ref(1)
const serviceRiskTotal = ref(0)
const serviceRiskDialogVisible = ref(false)
const serviceRiskSubmitting = ref(false)
const serviceRiskForm = reactive({
  id: '',
  service: '',
  risk_level: 'medium' as 'low' | 'medium' | 'high' | 'critical',
  description: '',
})

const riskLevelOptions = [
  { label: '低危', value: 'low' },
  { label: '中危', value: 'medium' },
  { label: '高危', value: 'high' },
  { label: '严重', value: 'critical' },
]

const riskLevelTag: Record<string, string> = {
  low: 'success',
  medium: 'warning',
  high: 'danger',
  critical: 'danger',
}
const riskLevelLabel: Record<string, string> = {
  low: '低危',
  medium: '中危',
  high: '高危',
  critical: '严重',
}

const protocolOptions = ['tcp', 'udp', 'icmp']

async function loadPortViolations() {
  portViolationLoading.value = true
  try {
    const res = await portViolationApi.list({
      page: portViolationPage.value,
      page_size: pageSize,
    })
    portViolationList.value = res.items
    portViolationTotal.value = res.total ?? res.items.length
  } finally {
    portViolationLoading.value = false
  }
}

async function loadServiceRisks() {
  serviceRiskLoading.value = true
  try {
    const res = await serviceRiskApi.list({
      page: serviceRiskPage.value,
      page_size: pageSize,
    })
    serviceRiskList.value = res.items
    serviceRiskTotal.value = res.total ?? res.items.length
  } finally {
    serviceRiskLoading.value = false
  }
}

function openPortViolationDialog() {
  portViolationForm.id = ''
  portViolationForm.port = 0
  portViolationForm.protocol = 'tcp'
  portViolationForm.risk_level = 'high'
  portViolationForm.description = ''
  portViolationDialogVisible.value = true
}

async function submitPortViolation() {
  if (!portViolationForm.port) {
    ElMessage.warning('请填写端口号')
    return
  }
  portViolationSubmitting.value = true
  try {
    await portViolationApi.create({
      port: portViolationForm.port,
      protocol: portViolationForm.protocol,
      risk_level: portViolationForm.risk_level,
      description: portViolationForm.description,
    })
    ElMessage.success('端口违规配置创建成功')
    portViolationDialogVisible.value = false
    await loadPortViolations()
  } finally {
    portViolationSubmitting.value = false
  }
}

async function togglePortViolation(row: PortViolation) {
  try {
    await portViolationApi.toggle(row.id)
    ElMessage.success(row.enabled ? '已禁用' : '已启用')
    await loadPortViolations()
  } catch {
    // ignore
  }
}

async function deletePortViolation(row: PortViolation) {
  try {
    await ElMessageBox.confirm(`确定删除端口违规配置吗？`, '删除确认', {
      type: 'warning',
    })
    await portViolationApi.remove(row.id)
    ElMessage.success('已删除')
    await loadPortViolations()
  } catch {
    // ignore
  }
}

function openServiceRiskDialog() {
  serviceRiskForm.id = ''
  serviceRiskForm.service = ''
  serviceRiskForm.risk_level = 'medium'
  serviceRiskForm.description = ''
  serviceRiskDialogVisible.value = true
}

async function submitServiceRisk() {
  if (!serviceRiskForm.service) {
    ElMessage.warning('请填写服务名称')
    return
  }
  serviceRiskSubmitting.value = true
  try {
    await serviceRiskApi.create({
      service: serviceRiskForm.service,
      risk_level: serviceRiskForm.risk_level,
      description: serviceRiskForm.description,
    })
    ElMessage.success('服务风险创建成功')
    serviceRiskDialogVisible.value = false
    await loadServiceRisks()
  } finally {
    serviceRiskSubmitting.value = false
  }
}

async function deleteServiceRisk(row: ServiceRisk) {
  try {
    await ElMessageBox.confirm(`确定删除服务风险「${row.service}」吗？`, '删除确认', {
      type: 'warning',
    })
    await serviceRiskApi.remove(row.id)
    ElMessage.success('已删除')
    await loadServiceRisks()
  } catch {
    // ignore
  }
}

// ==================== 9. 指纹规则 ====================
const fpList = ref<FingerprintRule[]>([])
const fpLoading = ref(false)
const fpPage = ref(1)
const fpTotal = ref(0)
const fpDialogVisible = ref(false)
const fpSubmitting = ref(false)
const fpForm = reactive({
  id: '',
  name: '',
  service: '',
  port: 0,
  pattern: '',
  description: '',
})

async function loadFingerprints() {
  fpLoading.value = true
  try {
    const res = await fingerprintRuleApi.list({
      page: fpPage.value,
      page_size: pageSize,
    })
    fpList.value = res.items
    fpTotal.value = res.total ?? res.items.length
  } finally {
    fpLoading.value = false
  }
}

function openFpDialog() {
  fpForm.id = ''
  fpForm.name = ''
  fpForm.service = ''
  fpForm.port = 0
  fpForm.pattern = ''
  fpForm.description = ''
  fpDialogVisible.value = true
}

async function submitFp() {
  if (!fpForm.name || !fpForm.pattern) {
    ElMessage.warning('请填写规则名称和匹配规则')
    return
  }
  fpSubmitting.value = true
  try {
    await fingerprintRuleApi.create({
      name: fpForm.name,
      service: fpForm.service || undefined,
      port: fpForm.port || undefined,
      pattern: fpForm.pattern,
      description: fpForm.description,
    })
    ElMessage.success('指纹规则创建成功')
    fpDialogVisible.value = false
    await loadFingerprints()
  } finally {
    fpSubmitting.value = false
  }
}

async function toggleFp(row: FingerprintRule) {
  try {
    await fingerprintRuleApi.toggle(row.id)
    ElMessage.success(row.enabled ? '已禁用' : '已启用')
    await loadFingerprints()
  } catch {
    // ignore
  }
}

async function deleteFp(row: FingerprintRule) {
  try {
    await ElMessageBox.confirm(`确定删除指纹规则「${row.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await fingerprintRuleApi.remove(row.id)
    ElMessage.success('已删除')
    await loadFingerprints()
  } catch {
    // ignore
  }
}

// ==================== 初始化 ====================
onMounted(() => {
  loadScanTemplates()
  loadPortTemplates()
  loadDictionaries()
  loadComboDicts()
  loadCertificates()
  loadParams()
  loadConfigs()
  loadPortViolations()
  loadServiceRisks()
  loadFingerprints()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold text-slate-100">模板管理</h2>
        <p class="mt-1 text-sm text-slate-500">
          管理扫描模板、端口模板、字典、证书、参数模板、配置基线及违规风险规则
        </p>
      </div>
    </div>

    <!-- 主 Tabs -->
    <el-tabs v-model="activeTab" class="templates-tabs">
      <!-- 1. 扫描模板 -->
      <el-tab-pane name="scan">
        <template #label>
          <span class="flex items-center gap-1.5">
            <FileJson class="h-4 w-4" />
            扫描模板
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">扫描模板列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadScanTemplates">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openScanTemplateDialog">新建扫描模板</el-button>
          </div>
        </div>
        <el-table
          :data="scanTemplateList"
          v-loading="scanTemplateLoading"
          stripe
          class="dark-table"
          empty-text="暂无扫描模板"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="type" label="类型" width="110" />
          <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
          <el-table-column label="创建时间" width="170">
            <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="160" fixed="right">
            <template #default>
              <el-button link type="primary" size="small" @click="validateScanTemplate">校验 JSON</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 2. 端口模板 -->
      <el-tab-pane name="port">
        <template #label>
          <span class="flex items-center gap-1.5">
            <Server class="h-4 w-4" />
            端口模板
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">端口模板列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadPortTemplates">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openPortTemplateDialog">新建端口模板</el-button>
          </div>
        </div>
        <el-table
          :data="portTemplateList"
          v-loading="portTemplateLoading"
          stripe
          class="dark-table"
          empty-text="暂无端口模板"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="port_range" label="端口范围" min-width="160" show-overflow-tooltip />
          <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="200" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" :icon="Copy" @click="copyPortTemplate(row)">复制</el-button>
              <el-button link type="danger" size="small" :icon="Trash2" @click="deletePortTemplate(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 3. 字典管理 -->
      <el-tab-pane name="dict">
        <template #label>
          <span class="flex items-center gap-1.5">
            <KeyRound class="h-4 w-4" />
            字典管理
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">字典列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadDictionaries">刷新</el-button>
            <el-upload
              :action="dictionaryApi.uploadUrl"
              :headers="uploadHeaders"
              :show-file-list="false"
              :before-upload="() => true"
              :on-success="handleDictionaryUploadSuccess"
              :on-error="handleDictionaryUploadError"
              accept=".txt,.dict,.csv"
            >
              <el-button size="small" :icon="Upload">上传字典文件</el-button>
            </el-upload>
            <el-button size="small" :icon="AlertTriangle" @click="openSocialDialog">生成社工字典</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openDictionaryDialog">新建字典</el-button>
          </div>
        </div>
        <el-table
          :data="dictionaryList"
          v-loading="dictionaryLoading"
          stripe
          class="dark-table"
          empty-text="暂无字典"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="type" label="类型" width="110" />
          <el-table-column prop="entry_count" label="条目数" width="100" align="center" />
          <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="180" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" :icon="Download" @click="downloadDictionary(row)">下载</el-button>
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteDictionary(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 4. 组合字典 -->
      <el-tab-pane name="combo">
        <template #label>
          <span class="flex items-center gap-1.5">
            <Layers class="h-4 w-4" />
            组合字典
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">组合字典列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadComboDicts">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openComboDialog">新建组合字典</el-button>
          </div>
        </div>
        <el-table
          :data="comboList"
          v-loading="comboLoading"
          stripe
          class="dark-table"
          empty-text="暂无组合字典"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="username_dict_name" label="用户名字典" min-width="140" show-overflow-tooltip>
            <template #default="{ row }">{{ row.username_dict_name || row.username_dict_id }}</template>
          </el-table-column>
          <el-table-column prop="password_dict_name" label="密码字典" min-width="140" show-overflow-tooltip>
            <template #default="{ row }">{{ row.password_dict_name || row.password_dict_id }}</template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{ row }">
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteCombo(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 5. 证书管理 -->
      <el-tab-pane name="cert">
        <template #label>
          <span class="flex items-center gap-1.5">
            <ShieldCheck class="h-4 w-4" />
            证书管理
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">证书列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadCertificates">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openCertDialog">新建证书</el-button>
          </div>
        </div>
        <el-table
          :data="certList"
          v-loading="certLoading"
          stripe
          class="dark-table"
          empty-text="暂无证书"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="type" label="类型" width="100" />
          <el-table-column label="过期时间" width="170">
            <template #default="{ row }">{{ formatTime(row.expires_at) }}</template>
          </el-table-column>
          <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="180" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" :icon="Download" @click="downloadCert(row)">下载</el-button>
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteCert(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 6. 参数模板 -->
      <el-tab-pane name="param">
        <template #label>
          <span class="flex items-center gap-1.5">
            <Settings class="h-4 w-4" />
            参数模板
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">参数模板列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadParams">刷新</el-button>
            <el-button size="small" :icon="Upload" @click="openImportDialog">导入</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openParamDialog">新建参数模板</el-button>
          </div>
        </div>
        <el-table
          :data="paramList"
          v-loading="paramLoading"
          stripe
          class="dark-table"
          empty-text="暂无参数模板"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="scan_type" label="扫描类型" width="120" />
          <el-table-column label="是否默认" width="100" align="center">
            <template #default="{ row }">
              <el-tag v-if="row.is_default" type="success" size="small">默认</el-tag>
              <span v-else class="text-slate-500">-</span>
            </template>
          </el-table-column>
          <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="setParamDefault(row)">设为默认</el-button>
              <el-button link type="primary" size="small" :icon="Copy" @click="copyParam(row)">复制</el-button>
              <el-button link type="primary" size="small" :icon="Download" @click="exportParam(row)">导出</el-button>
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteParam(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 7. 配置模板（基线） -->
      <el-tab-pane name="config">
        <template #label>
          <span class="flex items-center gap-1.5">
            <Settings class="h-4 w-4" />
            配置模板（基线）
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">配置模板列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadConfigs">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openConfigDialog">新建配置模板</el-button>
          </div>
        </div>
        <el-table
          :data="configList"
          v-loading="configLoading"
          stripe
          class="dark-table"
          empty-text="暂无配置模板"
        >
          <el-table-column prop="name" label="名称" min-width="160" />
          <el-table-column prop="rule_count" label="规则数" width="100" align="center" />
          <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{ row }">
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteConfig(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 8. 端口违规 / 服务风险 -->
      <el-tab-pane name="risk">
        <template #label>
          <span class="flex items-center gap-1.5">
            <AlertTriangle class="h-4 w-4" />
            端口违规 / 服务风险
          </span>
        </template>
        <el-tabs v-model="riskSubTab" type="card" class="risk-sub-tabs">
          <!-- 端口违规 -->
          <el-tab-pane name="port-violation" label="端口违规配置">
            <div class="mb-3 flex items-center justify-between">
              <div class="text-sm text-slate-400">端口违规配置列表</div>
              <div class="flex gap-2">
                <el-button size="small" :icon="RefreshCw" @click="loadPortViolations">刷新</el-button>
                <el-button type="primary" size="small" :icon="Plus" @click="openPortViolationDialog">新建端口违规</el-button>
              </div>
            </div>
            <el-table
              :data="portViolationList"
              v-loading="portViolationLoading"
              stripe
              class="dark-table"
              empty-text="暂无端口违规配置"
            >
              <el-table-column prop="port" label="端口" width="100" align="center" />
              <el-table-column prop="protocol" label="协议" width="100" align="center" />
              <el-table-column label="风险等级" width="110" align="center">
                <template #default="{ row }">
                  <el-tag :type="riskLevelTag[row.risk_level]" size="small">{{ riskLevelLabel[row.risk_level] }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="启用状态" width="110" align="center">
                <template #default="{ row }">
                  <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                    {{ row.enabled ? '启用' : '禁用' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
              <el-table-column label="操作" width="200" fixed="right">
                <template #default="{ row }">
                  <el-button link type="primary" size="small" @click="togglePortViolation(row)">
                    {{ row.enabled ? '禁用' : '启用' }}
                  </el-button>
                  <el-button link type="danger" size="small" :icon="Trash2" @click="deletePortViolation(row)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- 服务风险 -->
          <el-tab-pane name="service-risk" label="服务风险等级">
            <div class="mb-3 flex items-center justify-between">
              <div class="text-sm text-slate-400">服务风险等级列表</div>
              <div class="flex gap-2">
                <el-button size="small" :icon="RefreshCw" @click="loadServiceRisks">刷新</el-button>
                <el-button type="primary" size="small" :icon="Plus" @click="openServiceRiskDialog">新建服务风险</el-button>
              </div>
            </div>
            <el-table
              :data="serviceRiskList"
              v-loading="serviceRiskLoading"
              stripe
              class="dark-table"
              empty-text="暂无服务风险"
            >
              <el-table-column prop="service" label="服务" min-width="140" />
              <el-table-column label="风险等级" width="110" align="center">
                <template #default="{ row }">
                  <el-tag :type="riskLevelTag[row.risk_level]" size="small">{{ riskLevelLabel[row.risk_level] }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
              <el-table-column label="操作" width="120" fixed="right">
                <template #default="{ row }">
                  <el-button link type="danger" size="small" :icon="Trash2" @click="deleteServiceRisk(row)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </el-tab-pane>

      <!-- 9. 指纹规则 -->
      <el-tab-pane name="fingerprint">
        <template #label>
          <span class="flex items-center gap-1.5">
            <Scan class="h-4 w-4" />
            指纹规则
          </span>
        </template>
        <div class="mb-3 flex items-center justify-between">
          <div class="text-sm text-slate-400">指纹规则列表</div>
          <div class="flex gap-2">
            <el-button size="small" :icon="RefreshCw" @click="loadFingerprints">刷新</el-button>
            <el-button type="primary" size="small" :icon="Plus" @click="openFpDialog">新建指纹规则</el-button>
          </div>
        </div>
        <el-table
          :data="fpList"
          v-loading="fpLoading"
          stripe
          class="dark-table"
          empty-text="暂无指纹规则"
        >
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="service" label="服务" width="120" />
          <el-table-column prop="port" label="端口" width="100" align="center" />
          <el-table-column prop="pattern" label="匹配规则" min-width="200" show-overflow-tooltip />
          <el-table-column label="启用" width="80" align="center">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '是' : '否' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="200" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="toggleFp(row)">
                {{ row.enabled ? '禁用' : '启用' }}
              </el-button>
              <el-button link type="danger" size="small" :icon="Trash2" @click="deleteFp(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- ==================== 弹窗 ==================== -->

    <!-- 扫描模板弹窗 -->
    <el-dialog
      v-model="scanTemplateDialogVisible"
      title="新建扫描模板"
      width="640px"
      class="dark-dialog"
    >
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="scanTemplateForm.name" placeholder="请输入模板名称" />
        </el-form-item>
        <el-form-item label="类型" required>
          <el-select v-model="scanTemplateForm.type" placeholder="请选择模板类型" class="w-full">
            <el-option v-for="t in scanTemplateTypes" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="scanTemplateForm.description" placeholder="请输入描述" />
        </el-form-item>
        <el-form-item label="内容">
          <el-input
            v-model="scanTemplateForm.content"
            type="textarea"
            :rows="10"
            placeholder="请输入 JSON 内容"
            class="font-mono text-xs"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="scanTemplateDialogVisible = false">取消</el-button>
        <el-button :icon="Check" @click="validateScanTemplate">校验 JSON</el-button>
        <el-button type="primary" :loading="scanTemplateSubmitting" @click="submitScanTemplate">确定</el-button>
      </template>
    </el-dialog>

    <!-- 端口模板弹窗 -->
    <el-dialog v-model="portTemplateDialogVisible" title="新建端口模板" width="520px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="portTemplateForm.name" placeholder="请输入模板名称" />
        </el-form-item>
        <el-form-item label="端口范围" required>
          <el-input v-model="portTemplateForm.port_range" placeholder="如：1-65535 或 22,80,443" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="portTemplateForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="portTemplateDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="portTemplateSubmitting" @click="submitPortTemplate">确定</el-button>
      </template>
    </el-dialog>

    <!-- 字典弹窗 -->
    <el-dialog v-model="dictionaryDialogVisible" title="新建字典" width="600px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="dictionaryForm.name" placeholder="请输入字典名称" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="dictionaryForm.type" class="w-full">
            <el-option v-for="t in dictionaryTypes" :key="t.value" :label="t.label" :value="t.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="dictionaryForm.description" placeholder="请输入描述" />
        </el-form-item>
        <el-form-item label="条目">
          <el-input
            v-model="dictionaryForm.entries"
            type="textarea"
            :rows="8"
            placeholder="每行一个条目"
            class="font-mono text-xs"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dictionaryDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="dictionarySubmitting" @click="submitDictionary">确定</el-button>
      </template>
    </el-dialog>

    <!-- 社工字典弹窗 -->
    <el-dialog v-model="socialDialogVisible" title="生成社工字典" width="520px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="字典名称" required>
          <el-input v-model="socialForm.name" placeholder="请输入字典名称" />
        </el-form-item>
        <el-form-item label="关键词" required>
          <el-input
            v-model="socialForm.keywords"
            type="textarea"
            :rows="4"
            placeholder="请输入关键词，用空格或逗号分隔"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="socialDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="socialSubmitting" @click="submitSocialEngineer">生成</el-button>
      </template>
    </el-dialog>

    <!-- 组合字典弹窗 -->
    <el-dialog v-model="comboDialogVisible" title="新建组合字典" width="560px" class="dark-dialog">
      <el-form label-width="100px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="comboForm.name" placeholder="请输入组合字典名称" />
        </el-form-item>
        <el-form-item label="用户名字典" required>
          <el-select v-model="comboForm.username_dict_id" class="w-full" filterable placeholder="请选择用户名字典">
            <el-option v-for="d in usernameDictOptions" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="密码字典" required>
          <el-select v-model="comboForm.password_dict_id" class="w-full" filterable placeholder="请选择密码字典">
            <el-option v-for="d in passwordDictOptions" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="comboForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="comboDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="comboSubmitting" @click="submitCombo">确定</el-button>
      </template>
    </el-dialog>

    <!-- 证书弹窗 -->
    <el-dialog v-model="certDialogVisible" title="新建证书" width="600px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="certForm.name" placeholder="请输入证书名称" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="certForm.type" class="w-full">
            <el-option v-for="t in certTypes" :key="t.value" :label="t.label" :value="t.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="certForm.expires_at" type="datetime" class="w-full" value-format="YYYY-MM-DD HH:mm:ss" />
        </el-form-item>
        <el-form-item label="证书内容">
          <el-input
            v-model="certForm.content"
            type="textarea"
            :rows="6"
            placeholder="请粘贴证书内容（可选）"
            class="font-mono text-xs"
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="certForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="certDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="certSubmitting" @click="submitCert">确定</el-button>
      </template>
    </el-dialog>

    <!-- 参数模板弹窗 -->
    <el-dialog v-model="paramDialogVisible" title="新建参数模板" width="640px" class="dark-dialog">
      <el-form label-width="110px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="paramForm.name" placeholder="请输入参数模板名称" />
        </el-form-item>
        <el-form-item label="扫描类型" required>
          <el-select v-model="paramForm.scan_type" class="w-full" placeholder="请选择扫描类型">
            <el-option v-for="t in scanTypeOptions" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="paramForm.description" placeholder="请输入描述" />
        </el-form-item>
        <el-divider content-position="left">参数配置（根据扫描类型动态生成）</el-divider>
        <div v-if="paramSchemaLoading" class="py-4 text-center text-sm text-slate-500">加载 schema 中...</div>
        <div v-else-if="paramSchema" class="space-y-4">
          <template v-for="f in paramSchema.fields" :key="f.key">
            <el-form-item :label="f.label" :required="f.required">
              <el-input
                v-if="f.type === 'string'"
                v-model="paramForm.content[f.key]"
                :placeholder="f.placeholder || ''"
              />
              <el-input
                v-else-if="f.type === 'textarea'"
                v-model="paramForm.content[f.key]"
                type="textarea"
                :rows="4"
                :placeholder="f.placeholder || ''"
              />
              <el-input-number
                v-else-if="f.type === 'number'"
                v-model="paramForm.content[f.key]"
                :min="f.min"
                :max="f.max"
                class="w-full"
              />
              <el-switch v-else-if="f.type === 'boolean'" v-model="paramForm.content[f.key]" />
              <el-select v-else-if="f.type === 'select'" v-model="paramForm.content[f.key]" class="w-full">
                <el-option v-for="o in f.options" :key="o.value" :label="o.label" :value="o.value" />
              </el-select>
            </el-form-item>
          </template>
        </div>
        <div v-else class="py-4 text-center text-sm text-slate-500">请先选择扫描类型</div>
      </el-form>
      <template #footer>
        <el-button @click="paramDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="paramSubmitting" @click="submitParam">确定</el-button>
      </template>
    </el-dialog>

    <!-- 参数模板导入弹窗 -->
    <el-dialog v-model="importDialogVisible" title="导入参数模板" width="560px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="JSON 内容">
          <el-input
            v-model="importContent"
            type="textarea"
            :rows="12"
            placeholder="请粘贴参数模板 JSON 内容"
            class="font-mono text-xs"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="importDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="importSubmitting" @click="submitImportParam">导入</el-button>
      </template>
    </el-dialog>

    <!-- 配置模板弹窗 -->
    <el-dialog v-model="configDialogVisible" title="新建配置模板" width="600px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="configForm.name" placeholder="请输入配置模板名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="configForm.description" placeholder="请输入描述" />
        </el-form-item>
        <el-form-item label="内容">
          <el-input
            v-model="configForm.content"
            type="textarea"
            :rows="10"
            placeholder="请输入 JSON 内容"
            class="font-mono text-xs"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="configDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="configSubmitting" @click="submitConfig">确定</el-button>
      </template>
    </el-dialog>

    <!-- 端口违规弹窗 -->
    <el-dialog v-model="portViolationDialogVisible" title="新建端口违规配置" width="520px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="端口" required>
          <el-input-number v-model="portViolationForm.port" :min="1" :max="65535" class="w-full" />
        </el-form-item>
        <el-form-item label="协议" required>
          <el-select v-model="portViolationForm.protocol" class="w-full">
            <el-option v-for="p in protocolOptions" :key="p" :label="p" :value="p" />
          </el-select>
        </el-form-item>
        <el-form-item label="风险等级" required>
          <el-select v-model="portViolationForm.risk_level" class="w-full">
            <el-option v-for="r in riskLevelOptions" :key="r.value" :label="r.label" :value="r.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="portViolationForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="portViolationDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="portViolationSubmitting" @click="submitPortViolation">确定</el-button>
      </template>
    </el-dialog>

    <!-- 服务风险弹窗 -->
    <el-dialog v-model="serviceRiskDialogVisible" title="新建服务风险" width="520px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="服务名称" required>
          <el-input v-model="serviceRiskForm.service" placeholder="如 ssh、mysql" />
        </el-form-item>
        <el-form-item label="风险等级" required>
          <el-select v-model="serviceRiskForm.risk_level" class="w-full">
            <el-option v-for="r in riskLevelOptions" :key="r.value" :label="r.label" :value="r.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="serviceRiskForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="serviceRiskDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="serviceRiskSubmitting" @click="submitServiceRisk">确定</el-button>
      </template>
    </el-dialog>

    <!-- 指纹规则弹窗 -->
    <el-dialog v-model="fpDialogVisible" title="新建指纹规则" width="560px" class="dark-dialog">
      <el-form label-width="90px" class="dark-form">
        <el-form-item label="名称" required>
          <el-input v-model="fpForm.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="服务">
          <el-input v-model="fpForm.service" placeholder="如 http、ssh（可选）" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="fpForm.port" :min="0" :max="65535" class="w-full" />
        </el-form-item>
        <el-form-item label="匹配规则" required>
          <el-input
            v-model="fpForm.pattern"
            type="textarea"
            :rows="4"
            placeholder="请输入匹配规则（正则或字符串）"
            class="font-mono text-xs"
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="fpForm.description" placeholder="请输入描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="fpDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="fpSubmitting" @click="submitFp">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.templates-tabs :deep(.el-tabs__item) {
  color: #94a3b8;
}
.templates-tabs :deep(.el-tabs__item.is-active) {
  color: #06b6d4;
}
.templates-tabs :deep(.el-tabs__active-bar) {
  background-color: #06b6d4;
}
.risk-sub-tabs :deep(.el-tabs__item) {
  color: #94a3b8;
}
.risk-sub-tabs :deep(.el-tabs__item.is-active) {
  color: #06b6d4;
}
.dark-table :deep(.el-table) {
  --el-table-bg-color: transparent;
  --el-table-tr-bg-color: transparent;
  --el-table-header-bg-color: rgba(15, 23, 42, 0.6);
  --el-table-border-color: #1e293b;
  --el-table-text-color: #e2e8f0;
  --el-table-header-text-color: #cbd5e1;
  background-color: transparent;
}
.dark-table :deep(.el-table th.el-table__cell) {
  background-color: rgba(15, 23, 42, 0.6) !important;
}
.dark-dialog :deep(.el-dialog) {
  background-color: #0f172a;
  border: 1px solid #1e293b;
}
.dark-dialog :deep(.el-dialog__title) {
  color: #e2e8f0;
}
.dark-form :deep(.el-form-item__label) {
  color: #94a3b8;
}
</style>
