<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { ShieldCheck, User, Lock, Monitor, Shield, Eye, Cog } from '@lucide/vue'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const formRef = ref<FormInstance>()
const loading = ref(false)
const form = ref({ username: '', password: '', role: 'admin' })

/// 角色选项（4 种角色）
const roleOptions = [
  { label: '管理员', value: 'admin', icon: Cog, desc: '系统配置/用户管理/全量操作' },
  { label: '安全员', value: 'user', icon: Shield, desc: '扫描执行/风险处置/报表查看' },
  { label: '审计员', value: 'audit', icon: Eye, desc: '只读审计/日志查看/合规检查' },
  { label: '超级管理员', value: 'superadmin', icon: Monitor, desc: '全部权限+系统维护' },
]

const selectedRole = computed(
  () => roleOptions.find((r) => r.value === form.value.role) || roleOptions[0],
)

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

async function handleLogin() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  try {
    const res = await authStore.login({
      username: form.value.username,
      password: form.value.password,
    })
    ElMessage.success(`以${selectedRole.value.label}身份登录成功`)
    if (res.user.must_change_password) {
      ElMessage.warning('首次登录请修改密码')
      router.push({ name: 'System' })
    } else {
      const redirect = (route.query.redirect as string) || '/'
      router.push(redirect)
    }
  } catch {
    // 错误已在拦截器处理
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="flex h-screen items-center justify-center bg-slate-950">
    <!-- 背景装饰 -->
    <div class="pointer-events-none absolute inset-0 overflow-hidden">
      <div class="absolute -left-40 -top-40 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl"></div>
      <div class="absolute -bottom-40 -right-40 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl"></div>
    </div>

    <div class="relative z-10 w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-2xl backdrop-blur">
      <!-- Logo -->
      <div class="mb-8 flex flex-col items-center">
        <ShieldCheck class="mb-3 h-12 w-12 text-cyan-400" />
        <h1 class="text-2xl font-bold text-white">Argus</h1>
        <p class="mt-1 text-sm text-slate-400">远程安全扫描系统</p>
      </div>

      <el-form ref="formRef" :model="form" :rules="rules" size="large" @keyup.enter="handleLogin">
        <!-- 角色选择 -->
        <el-form-item prop="role">
          <div class="grid w-full grid-cols-4 gap-2">
            <button
              v-for="role in roleOptions"
              :key="role.value"
              type="button"
              class="flex flex-col items-center gap-1 rounded-lg border px-2 py-3 transition"
              :class="
                form.role === role.value
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                  : 'border-slate-700 bg-slate-800/50 text-slate-400 hover:border-slate-600 hover:text-slate-200'
              "
              @click="form.role = role.value"
            >
              <component :is="role.icon" class="h-5 w-5" />
              <span class="text-xs">{{ role.label }}</span>
            </button>
          </div>
        </el-form-item>

        <!-- 角色描述 -->
        <div class="mb-4 rounded-lg border border-slate-700 bg-slate-800/30 px-3 py-2 text-xs text-slate-400">
          <span class="font-medium text-slate-300">{{ selectedRole.label }}：</span>
          {{ selectedRole.desc }}
        </div>

        <el-form-item prop="username">
          <el-input
            v-model="form.username"
            placeholder="用户名"
            :prefix-icon="User"
          />
        </el-form-item>
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="密码"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            class="w-full"
            :loading="loading"
            @click="handleLogin"
          >
            以{{ selectedRole.label }}身份登录
          </el-button>
        </el-form-item>
      </el-form>

      <p class="mt-6 text-center text-xs text-slate-500">
        非生产环境请妥善保管凭证
      </p>
    </div>
  </div>
</template>
