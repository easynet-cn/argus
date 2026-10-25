import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/',
    component: () => import('@/layouts/DefaultLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: '', name: 'Dashboard', component: () => import('@/views/Dashboard.vue') },
      { path: 'assets', name: 'Assets', component: () => import('@/views/Assets.vue') },
      { path: 'risk', name: 'Risk', component: () => import('@/views/Risk.vue') },
      { path: 'scan/port', name: 'PortScan', component: () => import('@/views/ScanPage.vue') },
      { path: 'scan/system', name: 'SystemScan', component: () => import('@/views/ScanPage.vue') },
      { path: 'scan/ics', name: 'IcsScan', component: () => import('@/views/ScanPage.vue') },
      { path: 'scan/web', name: 'WebScan', component: () => import('@/views/ScanPage.vue') },
      { path: 'scan/database', name: 'DatabaseScan', component: () => import('@/views/ScanPage.vue') },
      { path: 'templates', name: 'Templates', component: () => import('@/views/Templates.vue') },
      { path: 'vuln-verify', name: 'VulnVerify', component: () => import('@/views/VulnVerify.vue') },
      { path: 'baseline', name: 'Baseline', component: () => import('@/views/ScanPage.vue') },
      { path: 'bruteforce', name: 'Bruteforce', component: () => import('@/views/ScanPage.vue') },
      { path: 'mobile', name: 'Mobile', component: () => import('@/views/ScanPage.vue') },
      { path: 'container', name: 'Container', component: () => import('@/views/ScanPage.vue') },
      { path: 'reports', name: 'Reports', component: () => import('@/views/Reports.vue') },
      { path: 'tools', name: 'Tools', component: () => import('@/views/Tools.vue') },
      { path: 'logs', name: 'Logs', component: () => import('@/views/Logs.vue') },
      { path: 'system', name: 'System', component: () => import('@/views/System.vue') },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const authStore = useAuthStore()
  if (to.meta.requiresAuth && !authStore.isLoggedIn) {
    return { name: 'Login', query: { redirect: to.fullPath } }
  }
  if (to.name === 'Login' && authStore.isLoggedIn) {
    return { name: 'Dashboard' }
  }
})

export default router
