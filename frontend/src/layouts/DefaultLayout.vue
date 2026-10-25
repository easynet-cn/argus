<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { useRouter, RouterView, useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import {
  Gauge,
  ShieldCheck,
  AlertTriangle,
  Scan,
  Monitor,
  Database,
  ShieldAlert,
  KeyRound,
  Smartphone,
  Package,
  FileText,
  Wrench,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User,
  Bell,
  Power,
  RotateCcw,
  Monitor as ScreenIcon,
  Clock,
  Layers,
  Bug,
} from '@lucide/vue'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const collapsed = ref(false)

/// 当前系统时间（实时更新）
const currentTime = ref(new Date())
let timeTimer: ReturnType<typeof setInterval> | null = null

/// 格式化系统时间
const formattedTime = computed(() => {
  const d = currentTime.value
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
})

/// 当前星期
const weekday = computed(() => {
  const days = ['日', '一', '二', '三', '四', '五', '六']
  return `星期${days[currentTime.value.getDay()]}`
})

/// 用户角色中文映射
const userRoleLabel = computed(() => {
  const role = authStore.user?.role
  const map: Record<string, string> = {
    admin: '管理员',
    user: '安全员',
    audit: '审计员',
    superadmin: '超级管理员',
  }
  return map[role as string] || '用户'
})

interface MenuItem {
  path: string
  name: string
  icon: any
  children?: MenuItem[]
}

const menuItems: MenuItem[] = [
  { path: '/', name: '总览仪表盘', icon: Gauge },
  { path: '/assets', name: '资产管理', icon: ShieldCheck },
  { path: '/risk', name: '风险管理', icon: AlertTriangle },
  {
    path: '/scan',
    name: '扫描管理',
    icon: Scan,
    children: [
      { path: '/scan/port', name: '端口扫描', icon: Scan },
      { path: '/scan/system', name: '系统漏洞扫描', icon: Gauge },
      { path: '/scan/ics', name: '工控漏洞扫描', icon: Monitor },
      { path: '/scan/web', name: 'Web 应用扫描', icon: ShieldAlert },
      { path: '/scan/database', name: '数据库扫描', icon: Database },
    ],
  },
  { path: '/templates', name: '模板管理', icon: Layers },
  { path: '/vuln-verify', name: '漏洞验证', icon: Bug },
  { path: '/baseline', name: '基线核查', icon: ShieldAlert },
  { path: '/bruteforce', name: '弱口令审计', icon: KeyRound },
  { path: '/mobile', name: '移动 APP 扫描', icon: Smartphone },
  { path: '/container', name: '容器镜像扫描', icon: Package },
  { path: '/reports', name: '报表管理', icon: FileText },
  { path: '/tools', name: '辅助工具', icon: Wrench },
  { path: '/logs', name: '日志管理', icon: ScrollText },
  { path: '/system', name: '系统管理', icon: Settings },
]

function isActive(path: string): boolean {
  return route.path === path || route.path.startsWith(path + '/')
}

function handleLogout() {
  authStore.logout()
  router.push({ name: 'Login' })
}

/// 消息通知（简化：提示功能占位）
function handleNotifications() {
  ElMessage.info('暂无新消息通知')
}

/// 大屏入口
function handleBigScreen() {
  ElMessage.info('风险态势感知大屏功能开发中')
}

/// 关机确认
function handleShutdown() {
  ElMessageBox.confirm('确定要关闭系统吗？关闭后需要物理重启设备。', '关机确认', {
    confirmButtonText: '确定关机',
    cancelButtonText: '取消',
    type: 'warning',
  })
    .then(() => {
      ElMessage.warning('关机指令已发送（软件系统模拟，需物理操作重启）')
    })
    .catch(() => {})
}

/// 重启确认
function handleRestart() {
  ElMessageBox.confirm('确定要重启系统吗？重启期间服务将暂时不可用。', '重启确认', {
    confirmButtonText: '确定重启',
    cancelButtonText: '取消',
    type: 'warning',
  })
    .then(() => {
      ElMessage.success('重启指令已发送（软件系统模拟）')
    })
    .catch(() => {})
}

onMounted(() => {
  timeTimer = setInterval(() => {
    currentTime.value = new Date()
  }, 1000)
})

onBeforeUnmount(() => {
  if (timeTimer) clearInterval(timeTimer)
})
</script>

<template>
  <div class="flex h-screen bg-slate-950 text-slate-200">
    <!-- 侧边栏 -->
    <aside
      class="flex flex-col border-r border-slate-800 bg-slate-900/50 transition-all duration-300"
      :class="collapsed ? 'w-16' : 'w-60'"
    >
      <!-- Logo -->
      <div class="flex h-14 items-center gap-2 border-b border-slate-800 px-4">
        <ShieldCheck class="h-7 w-7 shrink-0 text-cyan-400" />
        <span v-if="!collapsed" class="text-lg font-bold text-cyan-400">Argus</span>
      </div>

      <!-- 菜单 -->
      <nav class="flex-1 overflow-y-auto py-3">
        <template v-for="item in menuItems" :key="item.path">
          <!-- 无子菜单 -->
          <div
            v-if="!item.children"
            class="mx-2 mb-1 flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors"
            :class="
              isActive(item.path)
                ? 'bg-cyan-500/10 text-cyan-400'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            "
            @click="router.push(item.path)"
          >
            <component :is="item.icon" class="h-5 w-5 shrink-0" />
            <span v-if="!collapsed">{{ item.name }}</span>
          </div>

          <!-- 有子菜单（扫描管理） -->
          <div v-else>
            <div
              class="mx-2 mb-1 flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
              @click="collapsed ? router.push(item.children[0].path) : null"
            >
              <component :is="item.icon" class="h-5 w-5 shrink-0" />
              <span v-if="!collapsed">{{ item.name }}</span>
            </div>
            <div v-if="!collapsed" class="ml-4">
              <div
                v-for="child in item.children"
                :key="child.path"
                class="mx-2 mb-1 flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors"
                :class="
                  isActive(child.path)
                    ? 'bg-cyan-500/10 text-cyan-400'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                "
                @click="router.push(child.path)"
              >
                <component :is="child.icon" class="h-4 w-4 shrink-0" />
                <span>{{ child.name }}</span>
              </div>
            </div>
          </div>
        </template>
      </nav>

      <!-- 折叠按钮 -->
      <div
        class="flex h-10 cursor-pointer items-center justify-center border-t border-slate-800 text-slate-500 hover:text-slate-300"
        @click="collapsed = !collapsed"
      >
        <ChevronLeft v-if="!collapsed" class="h-5 w-5" />
        <ChevronRight v-else class="h-5 w-5" />
      </div>
    </aside>

    <!-- 主区域 -->
    <div class="flex flex-1 flex-col overflow-hidden">
      <!-- 顶栏：工具栏（系统时间/消息通知/关机/重启/大屏/当前用户） -->
      <header class="flex h-14 items-center justify-between border-b border-slate-800 bg-slate-900/30 px-6">
        <h1 class="text-base font-medium text-slate-200">
          {{ menuItems.find((m) => m.path === route.path || route.path.startsWith(m.path + '/'))?.name || 'Argus' }}
        </h1>

        <div class="flex items-center gap-5">
          <!-- 系统时间 -->
          <div class="flex items-center gap-1.5 text-sm text-slate-400">
            <Clock class="h-4 w-4 text-cyan-400" />
            <span class="font-mono">{{ formattedTime }}</span>
            <span class="text-xs text-slate-500">{{ weekday }}</span>
          </div>

          <!-- 消息通知 -->
          <button
            class="relative flex items-center rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-cyan-400"
            title="消息通知"
            @click="handleNotifications"
          >
            <Bell class="h-4 w-4" />
            <span class="absolute -right-0.5 -top-0.5 flex h-2 w-2">
              <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75"></span>
              <span class="relative inline-flex h-2 w-2 rounded-full bg-rose-500"></span>
            </span>
          </button>

          <!-- 大屏入口 -->
          <button
            class="flex items-center rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-cyan-400"
            title="风险态势感知大屏"
            @click="handleBigScreen"
          >
            <ScreenIcon class="h-4 w-4" />
          </button>

          <!-- 重启 -->
          <button
            class="flex items-center rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-amber-400"
            title="重启系统"
            @click="handleRestart"
          >
            <RotateCcw class="h-4 w-4" />
          </button>

          <!-- 关机 -->
          <button
            class="flex items-center rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-rose-400"
            title="关闭系统"
            @click="handleShutdown"
          >
            <Power class="h-4 w-4" />
          </button>

          <!-- 分隔线 -->
          <div class="h-5 w-px bg-slate-700"></div>

          <!-- 当前用户 -->
          <div class="flex items-center gap-2 text-sm">
            <div class="flex h-7 w-7 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400">
              <User class="h-4 w-4" />
            </div>
            <div class="flex flex-col leading-tight">
              <span class="text-slate-200">{{ authStore.user?.username }}</span>
              <span class="text-xs text-slate-500">{{ userRoleLabel }}</span>
            </div>
          </div>

          <!-- 退出 -->
          <button
            class="flex items-center gap-1 rounded-md px-2.5 py-1.5 text-sm text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
            @click="handleLogout"
          >
            <LogOut class="h-4 w-4" />
          </button>
        </div>
      </header>

      <!-- 内容区 -->
      <main class="flex-1 overflow-auto p-6">
        <RouterView />
      </main>
    </div>
  </div>
</template>
