<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshCw, Download, Search, Trash2, Database, Settings2 } from '@lucide/vue'
import {
  auditApi,
  type AuditLog,
  type AuditLogQuery,
  type BackupPolicy,
} from '@/api/system'

const logs = ref<AuditLog[]>([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = ref<AuditLogQuery>({})

// 日期范围
const dateRange = ref<[string, string] | null>(null)

// 动态加载日志类型
const logTypeOptions = ref<{ label: string; value: string }[]>([
  { label: '全部', value: '' },
])

const statusOptions = [
  { label: '全部', value: '' },
  { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' },
]

// 加载日志类型
async function loadLogTypes() {
  try {
    const res = await auditApi.types()
    const types = res.types || []
    logTypeOptions.value = [
      { label: '全部', value: '' },
      ...types.map((t) => ({ label: t, value: t })),
    ]
  } catch {
    // 错误已在拦截器处理
  }
}

async function loadLogs() {
  loading.value = true
  try {
    const params: AuditLogQuery = {
      ...filter.value,
      page: page.value,
      page_size: pageSize.value,
    }
    // 清空空值
    Object.keys(params).forEach((k) => {
      const v = params[k as keyof AuditLogQuery]
      if (v === '' || v === null || v === undefined) {
        delete params[k as keyof AuditLogQuery]
      }
    })
    // 日期范围
    if (dateRange.value && dateRange.value.length === 2) {
      params.start_time = dateRange.value[0]
      params.end_time = dateRange.value[1]
    }
    const res = await auditApi.list(params)
    logs.value = res.items
    total.value = res.total
  } catch {
    // 错误已在拦截器处理
  } finally {
    loading.value = false
  }
}

async function handleSearch() {
  page.value = 1
  await loadLogs()
}

async function handleExport() {
  try {
    const params: AuditLogQuery = { ...filter.value }
    Object.keys(params).forEach((k) => {
      const v = params[k as keyof AuditLogQuery]
      if (v === '' || v === null || v === undefined) {
        delete params[k as keyof AuditLogQuery]
      }
    })
    if (dateRange.value && dateRange.value.length === 2) {
      params.start_time = dateRange.value[0]
      params.end_time = dateRange.value[1]
    }
    const blob = (await auditApi.export(params)) as unknown as Blob
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'audit-logs.xlsx'
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    // 错误已在拦截器处理
  }
}

// 删除日志（按当前筛选条件）
async function handleDelete() {
  try {
    await ElMessageBox.confirm(
      '确定删除当前筛选条件下的日志吗？此操作不可恢复。',
      '删除日志',
      { type: 'warning' },
    )
    const params: AuditLogQuery = { ...filter.value }
    Object.keys(params).forEach((k) => {
      const v = params[k as keyof AuditLogQuery]
      if (v === '' || v === null || v === undefined) {
        delete params[k as keyof AuditLogQuery]
      }
    })
    await auditApi.delete(params)
    ElMessage.success('日志已删除')
    await loadLogs()
  } catch {
    // 用户取消或错误已在拦截器处理
  }
}

// 清空全部日志
async function handleClean() {
  try {
    await ElMessageBox.confirm(
      '确定清空所有审计日志吗？此操作不可恢复！',
      '清空日志',
      { type: 'error' },
    )
    await auditApi.clean()
    ElMessage.success('日志已清空')
    await loadLogs()
  } catch {
    // 用户取消或错误已在拦截器处理
  }
}

// ==================== 备份策略 ====================
const backupPolicyVisible = ref(false)
const backupPolicy = ref<BackupPolicy>({
  enabled: false,
  retention_days: 30,
  max_size_mb: 1024,
  backup_dir: '/var/log/argus/backup',
  schedule: '0 0 3 * * ?',
})
const backupPolicySaving = ref(false)
const backingUp = ref(false)

async function openBackupPolicy() {
  try {
    backupPolicy.value = await auditApi.getBackupPolicy()
  } catch {
    // 错误已在拦截器处理
  }
  backupPolicyVisible.value = true
}

async function saveBackupPolicy() {
  backupPolicySaving.value = true
  try {
    await auditApi.updateBackupPolicy(backupPolicy.value)
    ElMessage.success('备份策略保存成功')
    backupPolicyVisible.value = false
  } catch {
    // 错误已在拦截器处理
  } finally {
    backupPolicySaving.value = false
  }
}

async function handleBackup() {
  backingUp.value = true
  try {
    const res = await auditApi.backup()
    ElMessage.success(res.message || '备份任务已启动')
  } catch {
    // 错误已在拦截器处理
  } finally {
    backingUp.value = false
  }
}

// ==================== 辅助函数 ====================
const statusType = (status: string) => (status === 'success' ? 'success' : 'danger')
const statusLabel = (status: string) => (status === 'success' ? '成功' : '失败')

const logTypeLabel = (type: string) => {
  const map: Record<string, string> = {
    login: '登录',
    logout: '登出',
    system: '系统',
    security: '安全',
    operation: '操作',
    config: '配置',
    user: '用户',
  }
  return map[type] || type
}

const logTypeTagType = (type: string): string => {
  const map: Record<string, string> = {
    login: 'primary',
    logout: 'info',
    system: 'success',
    security: 'danger',
    operation: 'warning',
    config: 'info',
    user: 'success',
  }
  return map[type] || 'info'
}

function formatTime(t: string): string {
  return new Date(t).toLocaleString('zh-CN')
}

onMounted(() => {
  loadLogTypes()
  loadLogs()
})
</script>

<template>
  <div class="space-y-4">
    <!-- 过滤器 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <div class="flex flex-wrap items-center gap-2">
        <el-input
          v-model="filter.description"
          placeholder="关键词搜索"
          style="width: 160px"
          clearable
        />
        <el-input
          v-model="filter.username"
          placeholder="操作人"
          style="width: 120px"
          clearable
        />
        <el-input
          v-model="filter.login_ip"
          placeholder="IP 地址"
          style="width: 130px"
          clearable
        />
        <el-select
          v-model="filter.log_type"
          placeholder="日志类型"
          style="width: 120px"
          clearable
        >
          <el-option
            v-for="opt in logTypeOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-select
          v-model="filter.status"
          placeholder="结果"
          style="width: 100px"
          clearable
        >
          <el-option
            v-for="opt in statusOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-date-picker
          v-model="dateRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          value-format="YYYY-MM-DDTHH:mm:ss"
          style="width: 380px"
        />
        <el-button :icon="Search" type="primary" @click="handleSearch">搜索</el-button>
        <el-button :icon="RefreshCw" @click="loadLogs">刷新</el-button>
      </div>

      <!-- 操作按钮行 -->
      <div class="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
        <el-button :icon="Download" @click="handleExport">导出</el-button>
        <el-button type="warning" :icon="Trash2" @click="handleDelete">删除</el-button>
        <el-button type="danger" @click="handleClean">清空</el-button>
        <div class="ml-auto flex items-center gap-2">
          <el-button
            type="success"
            :icon="Database"
            :loading="backingUp"
            @click="handleBackup"
          >
            手动备份
          </el-button>
          <el-button :icon="Settings2" @click="openBackupPolicy">备份策略</el-button>
        </div>
      </div>
    </div>

    <!-- 日志表格 -->
    <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <el-table :data="logs" v-loading="loading" stripe style="width: 100%">
        <el-table-column prop="created_at" label="时间" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="log_type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag :type="logTypeTagType(row.log_type)" size="small">
              {{ logTypeLabel(row.log_type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="username" label="操作人" width="120" />
        <el-table-column prop="login_ip" label="IP 地址" width="130">
          <template #default="{ row }">{{ row.login_ip || '-' }}</template>
        </el-table-column>
        <el-table-column prop="status" label="结果" width="80">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="详情" min-width="300" show-overflow-tooltip />
      </el-table>

      <div class="mt-3 flex justify-end">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          @current-change="loadLogs"
          @size-change="loadLogs"
        />
      </div>
    </div>

    <!-- 备份策略弹窗 -->
    <el-dialog v-model="backupPolicyVisible" title="日志备份策略" width="560px">
      <el-form :model="backupPolicy" label-width="120px" label-position="right">
        <el-form-item label="启用备份">
          <el-switch v-model="backupPolicy.enabled" />
        </el-form-item>
        <el-form-item label="保留天数">
          <el-input-number
            v-model="backupPolicy.retention_days"
            :min="1"
            :max="3650"
            :step="1"
          />
          <span class="ml-2 text-xs text-slate-500">超过该天数的日志将被清理</span>
        </el-form-item>
        <el-form-item label="最大容量 (MB)">
          <el-input-number
            v-model="backupPolicy.max_size_mb"
            :min="10"
            :max="102400"
            :step="100"
          />
        </el-form-item>
        <el-form-item label="备份目录">
          <el-input v-model="backupPolicy.backup_dir" placeholder="/var/log/argus/backup" />
        </el-form-item>
        <el-form-item label="定时 Cron">
          <el-input v-model="backupPolicy.schedule" placeholder="0 0 3 * * ?（每天凌晨3点）" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="backupPolicyVisible = false">取消</el-button>
        <el-button type="primary" :loading="backupPolicySaving" @click="saveBackupPolicy">
          保存策略
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
