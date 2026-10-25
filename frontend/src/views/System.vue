<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  RefreshCw,
  Settings,
  Cpu,
  Network,
  Server,
  KeyRound,
  Users,
  Shield,
  SlidersHorizontal,
  Plus,
  Edit,
  Trash2,
  Lock,
  Unlock,
  Copy,
  Eye,
} from '@lucide/vue'
import {
  systemApi,
  adminApi,
  type PasswordPolicy,
  type SystemMonitor,
  type NetworkInterface,
  type ServiceInfo,
  type ApiKey,
  type CreateApiKeyRequest,
  type AdminUser,
  type CreateUserRequest,
  type UpdateUserRequest,
  type Role,
} from '@/api/system'

type TabName =
  | 'users'
  | 'roles'
  | 'settings'
  | 'policy'
  | 'api-keys'
  | 'task-settings'
  | 'network'
  | 'services'
  | 'monitor'

const activeTab = ref<TabName>('users')

// ==================== 辅助工具 ====================
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

function formatUptime(seconds: number): string {
  if (!seconds) return '-'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}天 ${hours}小时`
  if (hours > 0) return `${hours}小时 ${mins}分`
  return `${mins}分钟`
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

// ==================== 1. 用户管理 ====================
const users = ref<AdminUser[]>([])
const usersLoading = ref(false)
const userPage = ref(1)
const userPageSize = ref(20)
const userTotal = ref(0)
const userKeyword = ref('')

const userDialogVisible = ref(false)
const userDialogMode = ref<'create' | 'edit'>('create')
const editingUserId = ref('')
const userForm = ref<CreateUserRequest & UpdateUserRequest>({
  username: '',
  password: '',
  email: '',
  role_id: '',
})

const roleOptions = ref<{ label: string; value: string }[]>([])

async function loadUsers() {
  usersLoading.value = true
  try {
    const res = await adminApi.listUsers({
      page: userPage.value,
      page_size: userPageSize.value,
      keyword: userKeyword.value || undefined,
    })
    users.value = res.items
    userTotal.value = res.total
  } catch {
    // 错误已在拦截器处理
  } finally {
    usersLoading.value = false
  }
}

async function loadRolesForSelect() {
  try {
    const res = await adminApi.listRoles()
    roleOptions.value = (res.items || []).map((r) => ({ label: r.name, value: r.id }))
  } catch {
    // 错误已在拦截器处理
  }
}

function openCreateUser() {
  userDialogMode.value = 'create'
  userForm.value = { username: '', password: '', email: '', role_id: '' }
  userDialogVisible.value = true
}

function openEditUser(user: AdminUser) {
  userDialogMode.value = 'edit'
  editingUserId.value = user.id
  userForm.value = {
    username: user.username,
    password: '',
    email: user.email || '',
    role_id: user.role_id || '',
  }
  userDialogVisible.value = true
}

async function saveUser() {
  if (!userForm.value.username) {
    ElMessage.warning('请输入用户名')
    return
  }
  if (userDialogMode.value === 'create' && !userForm.value.password) {
    ElMessage.warning('请输入密码')
    return
  }
  try {
    if (userDialogMode.value === 'create') {
      const data: CreateUserRequest = {
        username: userForm.value.username,
        password: userForm.value.password,
        email: userForm.value.email || undefined,
        role_id: userForm.value.role_id || undefined,
      }
      await adminApi.createUser(data)
      ElMessage.success('用户创建成功')
    } else {
      const data: UpdateUserRequest = {
        email: userForm.value.email || undefined,
        role_id: userForm.value.role_id || undefined,
      }
      if (userForm.value.password) data.password = userForm.value.password
      await adminApi.updateUser(editingUserId.value, data)
      ElMessage.success('用户更新成功')
    }
    userDialogVisible.value = false
    await loadUsers()
  } catch {
    // 错误已在拦截器处理
  }
}

async function deleteUser(user: AdminUser) {
  try {
    await ElMessageBox.confirm(`确定删除用户「${user.username}」吗？`, '删除确认', {
      type: 'warning',
    })
    await adminApi.deleteUser(user.id)
    ElMessage.success('已删除')
    await loadUsers()
  } catch {
    // 用户取消
  }
}

async function lockUser(user: AdminUser) {
  try {
    await adminApi.lockUser(user.id)
    ElMessage.success(`已锁定用户 ${user.username}`)
    await loadUsers()
  } catch {
    // 错误已在拦截器处理
  }
}

async function unlockUser(user: AdminUser) {
  try {
    await adminApi.unlockUser(user.id)
    ElMessage.success(`已解锁用户 ${user.username}`)
    await loadUsers()
  } catch {
    // 错误已在拦截器处理
  }
}

const userStatusType = (user: AdminUser) => {
  if (user.locked) return 'danger'
  return user.status === 'active' ? 'success' : 'info'
}
const userStatusLabel = (user: AdminUser) => {
  if (user.locked) return '已锁定'
  return user.status === 'active' ? '正常' : user.status
}

// ==================== 2. 角色管理 ====================
const roles = ref<Role[]>([])
const rolesLoading = ref(false)
const rolePermDialogVisible = ref(false)
const editingRole = ref<Role | null>(null)
const rolePermissions = ref<string[]>([])
const allPermissions = ref<string[]>([
  'asset:read', 'asset:write',
  'task:read', 'task:write', 'task:execute',
  'vuln:read', 'vuln:write',
  'report:read', 'report:write',
  'log:read', 'log:write',
  'system:read', 'system:write',
  'user:read', 'user:write',
  'role:read', 'role:write',
])

async function loadRoles() {
  rolesLoading.value = true
  try {
    const res = await adminApi.listRoles()
    roles.value = res.items || []
  } catch {
    // 错误已在拦截器处理
  } finally {
    rolesLoading.value = false
  }
}

async function openRolePermissions(role: Role) {
  editingRole.value = role
  try {
    const res = await adminApi.getRolePermissions(role.id)
    rolePermissions.value = res.permissions || []
  } catch {
    rolePermissions.value = role.permissions || []
  }
  rolePermDialogVisible.value = true
}

function togglePermission(perm: string) {
  const idx = rolePermissions.value.indexOf(perm)
  if (idx >= 0) rolePermissions.value.splice(idx, 1)
  else rolePermissions.value.push(perm)
}

// ==================== 3. 系统配置 ====================
const settings = ref<Record<string, any>>({})
const settingsLoading = ref(false)
const editingKey = ref('')
const editingValue = ref('')
const settingsDialogVisible = ref(false)

async function loadSettings() {
  settingsLoading.value = true
  try {
    const res = await systemApi.listSettings()
    settings.value = res.settings || {}
  } catch {
    // 错误已在拦截器处理
  } finally {
    settingsLoading.value = false
  }
}

function openEditSetting(key: string) {
  editingKey.value = key
  const v = settings.value[key]
  editingValue.value = typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)
  settingsDialogVisible.value = true
}

async function saveSetting() {
  try {
    let value: any = editingValue.value
    try {
      value = JSON.parse(editingValue.value)
    } catch {
      // 非 JSON，保持字符串
    }
    await systemApi.updateSetting(editingKey.value, value)
    ElMessage.success('配置保存成功')
    settingsDialogVisible.value = false
    await loadSettings()
  } catch {
    // 错误已在拦截器处理
  }
}

// ==================== 4. 密码策略 ====================
const policy = ref<PasswordPolicy>({
  min_length: 8,
  require_complexity: true,
  require_special_char: false,
  expiry_days: 90,
  history_count: 5,
  lockout_threshold: 5,
  lockout_duration_minutes: 30,
})
const policyLoading = ref(false)
const policySaving = ref(false)

async function loadPolicy() {
  policyLoading.value = true
  try {
    policy.value = await systemApi.getPasswordPolicy()
  } catch {
    // 错误已在拦截器处理
  } finally {
    policyLoading.value = false
  }
}

async function savePolicy() {
  policySaving.value = true
  try {
    await systemApi.updatePasswordPolicy(policy.value)
    ElMessage.success('密码策略保存成功')
  } catch {
    // 错误已在拦截器处理
  } finally {
    policySaving.value = false
  }
}

// ==================== 5. API Key 管理 ====================
const apiKeys = ref<ApiKey[]>([])
const apiKeysLoading = ref(false)
const apiKeyDialogVisible = ref(false)
const apiKeyForm = ref<CreateApiKeyRequest>({
  name: '',
  permissions: [],
  expires_at: null,
})
const createdKey = ref<ApiKey | null>(null)
const showKey = ref(false)

async function loadApiKeys() {
  apiKeysLoading.value = true
  try {
    const res = await systemApi.listApiKeys()
    apiKeys.value = res.items || []
  } catch {
    // 错误已在拦截器处理
  } finally {
    apiKeysLoading.value = false
  }
}

function openCreateApiKey() {
  apiKeyForm.value = { name: '', permissions: [], expires_at: null }
  createdKey.value = null
  showKey.value = false
  apiKeyDialogVisible.value = true
}

async function saveApiKey() {
  if (!apiKeyForm.value.name) {
    ElMessage.warning('请输入 Key 名称')
    return
  }
  try {
    const key = await systemApi.createApiKey(apiKeyForm.value)
    createdKey.value = key
    showKey.value = true
    ElMessage.success('API Key 创建成功')
    await loadApiKeys()
  } catch {
    // 错误已在拦截器处理
  }
}

function copyKey(text: string) {
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制到剪贴板')
}

async function deleteApiKey(key: ApiKey) {
  try {
    await ElMessageBox.confirm(`确定删除 API Key「${key.name}」吗？`, '删除确认', {
      type: 'warning',
    })
    await systemApi.deleteApiKey(key.id)
    ElMessage.success('已删除')
    await loadApiKeys()
  } catch {
    // 用户取消
  }
}

// ==================== 6. 任务设置 ====================
const taskSettings = ref<Record<string, any>>({})
const taskSettingsLoading = ref(false)
const taskSettingDialogVisible = ref(false)
const editingTaskKey = ref('')
const editingTaskValue = ref('')

async function loadTaskSettings() {
  taskSettingsLoading.value = true
  try {
    const res = await systemApi.listTaskSettings()
    taskSettings.value = res.settings || {}
  } catch {
    // 错误已在拦截器处理
  } finally {
    taskSettingsLoading.value = false
  }
}

function openEditTaskSetting(key: string) {
  editingTaskKey.value = key
  const v = taskSettings.value[key]
  editingTaskValue.value = typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)
  taskSettingDialogVisible.value = true
}

async function saveTaskSetting() {
  try {
    let value: any = editingTaskValue.value
    try {
      value = JSON.parse(editingTaskValue.value)
    } catch {
      // 非 JSON，保持字符串
    }
    await systemApi.updateTaskSetting(editingTaskKey.value, value)
    ElMessage.success('任务设置保存成功')
    taskSettingDialogVisible.value = false
    await loadTaskSettings()
  } catch {
    // 错误已在拦截器处理
  }
}

// ==================== 7. 网络配置 ====================
const interfaces = ref<NetworkInterface[]>([])
const hostsContent = ref('')
const networkLoading = ref(false)
const hostsSaving = ref(false)

async function loadNetwork() {
  networkLoading.value = true
  try {
    const res = await systemApi.getNetworkConfig()
    interfaces.value = res.interfaces || []
    hostsContent.value = res.hosts || ''
  } catch {
    // 错误已在拦截器处理
  } finally {
    networkLoading.value = false
  }
}

async function saveHosts() {
  hostsSaving.value = true
  try {
    await systemApi.updateHosts(hostsContent.value)
    ElMessage.success('hosts 已更新')
  } catch {
    // 错误已在拦截器处理
  } finally {
    hostsSaving.value = false
  }
}

// ==================== 8. 服务管理 ====================
const services = ref<ServiceInfo[]>([])
const serviceLoading = ref(false)

async function loadServices() {
  serviceLoading.value = true
  try {
    const res = await systemApi.listServices()
    services.value = res.services || []
  } catch {
    // 错误已在拦截器处理
  } finally {
    serviceLoading.value = false
  }
}

async function handleServiceAction(action: string, name: string) {
  try {
    await systemApi.manageService(action, name)
    const actionLabel = action === 'start' ? '启动' : action === 'stop' ? '停止' : '重启'
    ElMessage.success(`服务 ${name} ${actionLabel}操作已执行`)
    await loadServices()
  } catch {
    // 错误已在拦截器处理
  }
}

// ==================== 系统监控（保留） ====================
const monitor = ref<SystemMonitor | null>(null)
const monitorLoading = ref(false)

async function loadMonitor() {
  monitorLoading.value = true
  try {
    monitor.value = await systemApi.monitor()
  } catch {
    // 错误已在拦截器处理
  } finally {
    monitorLoading.value = false
  }
}

// ==================== Tab 切换懒加载 ====================
function handleTabChange() {
  switch (activeTab.value) {
    case 'users':
      if (users.value.length === 0) {
        loadUsers()
        loadRolesForSelect()
      }
      break
    case 'roles':
      if (roles.value.length === 0) loadRoles()
      break
    case 'settings':
      if (Object.keys(settings.value).length === 0) loadSettings()
      break
    case 'policy':
      if (!policy.value.min_length) loadPolicy()
      break
    case 'api-keys':
      if (apiKeys.value.length === 0) loadApiKeys()
      break
    case 'task-settings':
      if (Object.keys(taskSettings.value).length === 0) loadTaskSettings()
      break
    case 'network':
      if (interfaces.value.length === 0) loadNetwork()
      break
    case 'services':
      if (services.value.length === 0) loadServices()
      break
    case 'monitor':
      if (!monitor.value) loadMonitor()
      break
  }
}

onMounted(() => {
  loadUsers()
  loadRolesForSelect()
})
</script>

<template>
  <div class="space-y-4">
    <el-tabs v-model="activeTab" @tab-change="handleTabChange">
      <!-- 1. 用户管理 -->
      <el-tab-pane name="users">
        <template #label>
          <span class="flex items-center gap-1.5"><Users class="h-4 w-4" />用户管理</span>
        </template>
        <div v-loading="usersLoading">
          <div class="mb-3 flex items-center gap-2">
            <el-input
              v-model="userKeyword"
              placeholder="搜索用户名"
              style="width: 200px"
              clearable
              @keyup.enter="userPage = 1; loadUsers()"
            />
            <el-button type="primary" :icon="Plus" @click="openCreateUser">新建用户</el-button>
            <el-button :icon="RefreshCw" circle size="small" @click="loadUsers" />
          </div>
          <el-table :data="users" stripe style="width: 100%">
            <el-table-column prop="username" label="用户名" width="140" />
            <el-table-column prop="email" label="邮箱" min-width="180">
              <template #default="{ row }">{{ row.email || '-' }}</template>
            </el-table-column>
            <el-table-column prop="role" label="角色" width="120" />
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="userStatusType(row)" size="small">
                  {{ userStatusLabel(row) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="created_at" label="创建时间" width="170">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <el-table-column prop="last_login_at" label="最后登录" width="170">
              <template #default="{ row }">{{ formatTime(row.last_login_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="240" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" :icon="Edit" @click="openEditUser(row)">编辑</el-button>
                <el-button
                  v-if="!row.locked"
                  link
                  type="warning"
                  :icon="Lock"
                  @click="lockUser(row)"
                >
                  锁定
                </el-button>
                <el-button
                  v-else
                  link
                  type="success"
                  :icon="Unlock"
                  @click="unlockUser(row)"
                >
                  解锁
                </el-button>
                <el-button link type="danger" :icon="Trash2" @click="deleteUser(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="mt-3 flex justify-end">
            <el-pagination
              v-model:current-page="userPage"
              v-model:page-size="userPageSize"
              :total="userTotal"
              :page-sizes="[10, 20, 50]"
              layout="total, sizes, prev, pager, next"
              @current-change="loadUsers"
              @size-change="loadUsers"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 2. 角色管理 -->
      <el-tab-pane name="roles">
        <template #label>
          <span class="flex items-center gap-1.5"><Shield class="h-4 w-4" />角色管理</span>
        </template>
        <div v-loading="rolesLoading">
          <div class="mb-3 flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadRoles" />
          </div>
          <el-table :data="roles" stripe style="width: 100%">
            <el-table-column prop="name" label="角色名" width="160" />
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip>
              <template #default="{ row }">{{ row.description || '-' }}</template>
            </el-table-column>
            <el-table-column prop="permissions" label="权限数" width="100">
              <template #default="{ row }">{{ (row.permissions || []).length }}</template>
            </el-table-column>
            <el-table-column prop="created_at" label="创建时间" width="170">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openRolePermissions(row)">权限配置</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 3. 系统配置 -->
      <el-tab-pane name="settings">
        <template #label>
          <span class="flex items-center gap-1.5"><Settings class="h-4 w-4" />系统配置</span>
        </template>
        <div v-loading="settingsLoading">
          <div class="mb-3 flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadSettings" />
          </div>
          <el-table
            :data="Object.entries(settings).map(([k, v]) => ({ key: k, value: v }))"
            stripe
          >
            <el-table-column prop="key" label="配置项" width="220" />
            <el-table-column label="值">
              <template #default="{ row }">
                <pre class="max-h-24 overflow-auto text-xs">{{
                  typeof row.value === 'object'
                    ? JSON.stringify(row.value, null, 2)
                    : row.value
                }}</pre>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openEditSetting(row.key)">编辑</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 4. 密码策略 -->
      <el-tab-pane name="policy">
        <template #label>
          <span class="flex items-center gap-1.5"><SlidersHorizontal class="h-4 w-4" />密码策略</span>
        </template>
        <div v-loading="policyLoading" class="max-w-2xl">
          <el-form :model="policy" label-width="160px" label-position="right">
            <el-form-item label="密码最小长度">
              <el-input-number v-model="policy.min_length" :min="4" :max="32" />
            </el-form-item>
            <el-form-item label="要求复杂度">
              <el-switch v-model="policy.require_complexity" />
              <span class="ml-2 text-xs text-slate-500">数字/大写/小写/特殊字符至少 3 种</span>
            </el-form-item>
            <el-form-item label="必须含特殊字符">
              <el-switch v-model="policy.require_special_char" />
            </el-form-item>
            <el-form-item label="密码过期天数">
              <el-input-number v-model="policy.expiry_days" :min="0" :max="365" />
              <span class="ml-2 text-xs text-slate-500">0 = 不过期</span>
            </el-form-item>
            <el-form-item label="历史密码记录数">
              <el-input-number v-model="policy.history_count" :min="0" :max="20" />
              <span class="ml-2 text-xs text-slate-500">0 = 不校验历史</span>
            </el-form-item>
            <el-form-item label="连续失败锁定次数">
              <el-input-number v-model="policy.lockout_threshold" :min="1" :max="10" />
            </el-form-item>
            <el-form-item label="锁定时长（分钟）">
              <el-input-number v-model="policy.lockout_duration_minutes" :min="1" :max="1440" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="policySaving" @click="savePolicy">保存策略</el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <!-- 5. API Key 管理 -->
      <el-tab-pane name="api-keys">
        <template #label>
          <span class="flex items-center gap-1.5"><KeyRound class="h-4 w-4" />API Key 管理</span>
        </template>
        <div v-loading="apiKeysLoading">
          <div class="mb-3 flex items-center justify-between">
            <el-button type="primary" :icon="Plus" @click="openCreateApiKey">创建 API Key</el-button>
            <el-button :icon="RefreshCw" circle size="small" @click="loadApiKeys" />
          </div>
          <el-table :data="apiKeys" stripe style="width: 100%">
            <el-table-column prop="name" label="名称" width="160" />
            <el-table-column prop="key" label="Key" min-width="280">
              <template #default="{ row }">
                <span class="font-mono text-sm">{{ row.key ? row.key.slice(0, 12) + '...' : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="permissions" label="权限" width="120">
              <template #default="{ row }">{{ (row.permissions || []).length }} 项</template>
            </el-table-column>
            <el-table-column prop="expires_at" label="过期时间" width="170">
              <template #default="{ row }">{{ formatTime(row.expires_at) }}</template>
            </el-table-column>
            <el-table-column prop="enabled" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                  {{ row.enabled ? '启用' : '禁用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button link type="danger" :icon="Trash2" @click="deleteApiKey(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 6. 任务设置 -->
      <el-tab-pane name="task-settings">
        <template #label>
          <span class="flex items-center gap-1.5"><SlidersHorizontal class="h-4 w-4" />任务设置</span>
        </template>
        <div v-loading="taskSettingsLoading">
          <div class="mb-3 flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadTaskSettings" />
          </div>
          <el-table
            :data="Object.entries(taskSettings).map(([k, v]) => ({ key: k, value: v }))"
            stripe
          >
            <el-table-column prop="key" label="设置项" width="220" />
            <el-table-column label="值">
              <template #default="{ row }">
                <span class="text-sm">{{
                  typeof row.value === 'object'
                    ? JSON.stringify(row.value, null, 2)
                    : row.value
                }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="100" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openEditTaskSetting(row.key)">编辑</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 7. 网络配置 -->
      <el-tab-pane name="network">
        <template #label>
          <span class="flex items-center gap-1.5"><Network class="h-4 w-4" />网络配置</span>
        </template>
        <div v-loading="networkLoading" class="space-y-4">
          <div class="flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadNetwork" />
          </div>

          <!-- 网口信息 -->
          <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
            <h3 class="mb-3 text-base font-medium text-slate-200">网口信息</h3>
            <el-table :data="interfaces" stripe style="width: 100%">
              <el-table-column prop="name" label="接口名" width="150" />
              <el-table-column label="地址列表">
                <template #default="{ row }">
                  <div v-for="(addr, idx) in row.addresses" :key="idx" class="text-sm">
                    <el-tag
                      :type="addr.family === 'inet' ? 'primary' : 'info'"
                      size="small"
                      class="mr-2"
                    >
                      {{ addr.family }}
                    </el-tag>
                    {{ addr.address }}/{{ addr.prefixlen }}
                  </div>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <!-- hosts 编辑 -->
          <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
            <div class="mb-3 flex items-center justify-between">
              <h3 class="text-base font-medium text-slate-200">Hosts 文件</h3>
              <el-button type="primary" :loading="hostsSaving" @click="saveHosts">保存 hosts</el-button>
            </div>
            <el-input
              v-model="hostsContent"
              type="textarea"
              :rows="10"
              placeholder="# 请输入 hosts 内容，每行一条"
              spellcheck="false"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 8. 服务管理 -->
      <el-tab-pane name="services">
        <template #label>
          <span class="flex items-center gap-1.5"><Server class="h-4 w-4" />服务管理</span>
        </template>
        <div v-loading="serviceLoading">
          <div class="mb-3 flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadServices" />
          </div>
          <el-table :data="services" stripe style="width: 100%">
            <el-table-column prop="name" label="服务名" width="200" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'running' ? 'success' : 'info'" size="small">
                  {{ row.status === 'running' ? '运行中' : '已停止' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="enabled" label="开机自启" width="100">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                  {{ row.enabled ? '是' : '否' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip>
              <template #default="{ row }">{{ row.description || '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="180" fixed="right">
              <template #default="{ row }">
                <el-button
                  v-if="row.status !== 'running'"
                  link
                  type="success"
                  @click="handleServiceAction('start', row.name)"
                >
                  启动
                </el-button>
                <el-button
                  v-else
                  link
                  type="warning"
                  @click="handleServiceAction('stop', row.name)"
                >
                  停止
                </el-button>
                <el-button link type="primary" @click="handleServiceAction('restart', row.name)">
                  重启
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <p v-if="services.length === 0" class="py-4 text-center text-sm text-slate-500">
            仅 Linux 平台支持服务管理
          </p>
        </div>
      </el-tab-pane>

      <!-- 系统监控（保留） -->
      <el-tab-pane name="monitor">
        <template #label>
          <span class="flex items-center gap-1.5"><Cpu class="h-4 w-4" />系统监控</span>
        </template>
        <div v-loading="monitorLoading" class="space-y-4">
          <div class="flex justify-end">
            <el-button :icon="RefreshCw" circle size="small" @click="loadMonitor" />
          </div>
          <div v-if="monitor" class="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
              <h3 class="mb-3 flex items-center gap-2 text-base font-medium text-slate-200">
                <Cpu class="h-5 w-5 text-cyan-400" /> CPU
              </h3>
              <div class="space-y-2">
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">使用率</span>
                  <span class="text-slate-200">{{ monitor.cpu.usage_percent.toFixed(1) }}%</span>
                </div>
                <el-progress :percentage="Math.round(monitor.cpu.usage_percent)" :color="'#06b6d4'" />
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">核心数</span>
                  <span class="text-slate-200">{{ monitor.cpu.cores }}</span>
                </div>
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">型号</span>
                  <span class="text-slate-200">{{ monitor.cpu.brand || '-' }}</span>
                </div>
              </div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
              <h3 class="mb-3 flex items-center gap-2 text-base font-medium text-slate-200">
                <Settings class="h-5 w-5 text-violet-400" /> 内存
              </h3>
              <div class="space-y-2">
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">使用率</span>
                  <span class="text-slate-200">{{ monitor.memory.usage_percent.toFixed(1) }}%</span>
                </div>
                <el-progress :percentage="Math.round(monitor.memory.usage_percent)" :color="'#8b5cf6'" />
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">已用/总量</span>
                  <span class="text-slate-200">
                    {{ formatBytes(monitor.memory.used_bytes) }} / {{ formatBytes(monitor.memory.total_bytes) }}
                  </span>
                </div>
                <div class="flex justify-between text-sm">
                  <span class="text-slate-400">Swap</span>
                  <span class="text-slate-200">
                    {{ formatBytes(monitor.swap.used_bytes) }} / {{ formatBytes(monitor.swap.total_bytes) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5 md:col-span-2">
              <h3 class="mb-3 text-base font-medium text-slate-200">磁盘使用</h3>
              <div v-for="(disk, idx) in monitor.disks" :key="idx" class="mb-3">
                <div class="mb-1 flex justify-between text-sm">
                  <span class="text-slate-300">{{ disk.mount_point || disk.name }}</span>
                  <span class="text-slate-400">
                    {{ formatBytes(disk.used_bytes) }} / {{ formatBytes(disk.total_bytes) }}
                  </span>
                </div>
                <el-progress
                  :percentage="Math.round(disk.usage_percent)"
                  :color="disk.usage_percent > 90 ? '#dc2626' : '#f59e0b'"
                  :stroke-width="6"
                />
              </div>
              <div class="mt-3 flex justify-between border-t border-slate-800 pt-2 text-sm">
                <span class="text-slate-400">系统运行时间</span>
                <span class="text-slate-300">{{ formatUptime(monitor.uptime_seconds) }}</span>
              </div>
            </div>
          </div>
          <div v-else class="flex h-40 items-center justify-center text-slate-500">
            暂无监控数据
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 用户创建/编辑弹窗 -->
    <el-dialog
      v-model="userDialogVisible"
      :title="userDialogMode === 'create' ? '新建用户' : '编辑用户'"
      width="500px"
    >
      <el-form :model="userForm" label-width="100px" label-position="right">
        <el-form-item label="用户名">
          <el-input v-model="userForm.username" :disabled="userDialogMode === 'edit'" />
        </el-form-item>
        <el-form-item :label="userDialogMode === 'create' ? '密码' : '新密码'">
          <el-input
            v-model="userForm.password"
            type="password"
            show-password
            :placeholder="userDialogMode === 'edit' ? '不修改请留空' : '请输入密码'"
          />
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="userForm.email" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="userForm.role_id" style="width: 100%" clearable>
            <el-option
              v-for="r in roleOptions"
              :key="r.value"
              :label="r.label"
              :value="r.value"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveUser">保存</el-button>
      </template>
    </el-dialog>

    <!-- 角色权限配置弹窗 -->
    <el-dialog v-model="rolePermDialogVisible" title="权限配置" width="520px">
      <div class="mb-3 text-sm text-slate-400">
        角色：<span class="font-medium text-slate-200">{{ editingRole?.name }}</span>
      </div>
      <div class="grid grid-cols-2 gap-2">
        <div
          v-for="perm in allPermissions"
          :key="perm"
          class="flex cursor-pointer items-center gap-2 rounded border border-slate-700 bg-slate-800/50 px-3 py-2 hover:border-cyan-600"
          @click="togglePermission(perm)"
        >
          <el-checkbox :model-value="rolePermissions.includes(perm)" />
          <span class="font-mono text-sm">{{ perm }}</span>
        </div>
      </div>
      <div class="mt-3 text-xs text-slate-500">
        已选 {{ rolePermissions.length }} / {{ allPermissions.length }} 项权限
      </div>
      <template #footer>
        <el-button @click="rolePermDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- 系统配置编辑弹窗 -->
    <el-dialog v-model="settingsDialogVisible" title="编辑系统配置" width="560px">
      <el-form label-width="100px">
        <el-form-item label="配置项">
          <el-input v-model="editingKey" disabled />
        </el-form-item>
        <el-form-item label="值">
          <el-input
            v-model="editingValue"
            type="textarea"
            :rows="6"
            placeholder="支持 JSON 格式"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="settingsDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveSetting">保存</el-button>
      </template>
    </el-dialog>

    <!-- API Key 创建弹窗 -->
    <el-dialog v-model="apiKeyDialogVisible" title="创建 API Key" width="560px">
      <el-form v-if="!createdKey" :model="apiKeyForm" label-width="100px" label-position="right">
        <el-form-item label="名称">
          <el-input v-model="apiKeyForm.name" placeholder="如：CI/CD 自动化" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker
            v-model="apiKeyForm.expires_at"
            type="datetime"
            placeholder="不设置则永不过期"
            value-format="YYYY-MM-DDTHH:mm:ss"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item label="权限">
          <el-select
            v-model="apiKeyForm.permissions"
            multiple
            filterable
            placeholder="选择权限"
            style="width: 100%"
          >
            <el-option
              v-for="perm in allPermissions"
              :key="perm"
              :label="perm"
              :value="perm"
            />
          </el-select>
        </el-form-item>
      </el-form>

      <!-- 创建成功后展示 Key -->
      <div v-else class="space-y-3">
        <el-alert type="warning" :closable="false" show-icon>
          请立即复制并保存此 Key，关闭后将无法再次查看完整内容
        </el-alert>
        <div class="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 p-3">
          <code class="flex-1 break-all font-mono text-sm text-cyan-300">{{
            showKey ? createdKey?.key : '••••••••••••••••'
          }}</code>
          <el-button :icon="Eye" circle size="small" @click="showKey = !showKey" />
          <el-button :icon="Copy" circle size="small" @click="copyKey(createdKey?.key || '')" />
        </div>
      </div>

      <template #footer>
        <el-button v-if="!createdKey" @click="apiKeyDialogVisible = false">取消</el-button>
        <el-button v-if="!createdKey" type="primary" @click="saveApiKey">创建</el-button>
        <el-button v-else type="primary" @click="apiKeyDialogVisible = false">完成</el-button>
      </template>
    </el-dialog>

    <!-- 任务设置编辑弹窗 -->
    <el-dialog v-model="taskSettingDialogVisible" title="编辑任务设置" width="560px">
      <el-form label-width="100px">
        <el-form-item label="设置项">
          <el-input v-model="editingTaskKey" disabled />
        </el-form-item>
        <el-form-item label="值">
          <el-input
            v-model="editingTaskValue"
            type="textarea"
            :rows="6"
            placeholder="支持 JSON 格式"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="taskSettingDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveTaskSetting">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>
