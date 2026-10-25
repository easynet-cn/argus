import { defineStore } from 'pinia'
import { ref } from 'vue'
import { scanApi, type ScanTaskStatus, type ScanResultsResponse } from '@/api/scan'
import { taskApi, type ScanTask, type TaskListQuery } from '@/api/task'

export const useScanStore = defineStore('scan', () => {
  // 任务列表
  const tasks = ref<ScanTask[]>([])
  const total = ref(0)
  const loading = ref(false)

  // 当前查看的任务状态和结果
  const currentStatus = ref<ScanTaskStatus | null>(null)
  const currentResults = ref<ScanResultsResponse | null>(null)
  const detailLoading = ref(false)

  // 轮询定时器
  let pollTimer: ReturnType<typeof setInterval> | null = null

  async function fetchTasks(params?: TaskListQuery) {
    loading.value = true
    try {
      const res = await taskApi.list(params)
      tasks.value = res.items
      total.value = res.items.length
    } finally {
      loading.value = false
    }
  }

  async function fetchTaskStatus(taskId: string) {
    detailLoading.value = true
    try {
      currentStatus.value = await scanApi.getStatus(taskId)
    } catch {
      currentStatus.value = null
    } finally {
      detailLoading.value = false
    }
  }

  async function fetchTaskResults(taskId: string) {
    try {
      currentResults.value = await scanApi.getResults(taskId)
    } catch {
      currentResults.value = null
    }
  }

  async function loadTaskDetail(taskId: string) {
    await Promise.all([fetchTaskStatus(taskId), fetchTaskResults(taskId)])
  }

  // 启动轮询
  function startPolling(taskId: string, interval = 2000) {
    stopPolling()
    pollTimer = setInterval(async () => {
      await fetchTaskStatus(taskId)
      // 如果任务已完成/失败/取消，停止轮询
      const status = currentStatus.value?.status
      if (status && !['running', 'pending', 'paused'].includes(status)) {
        stopPolling()
        await fetchTaskResults(taskId)
      }
    }, interval)
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  async function cancelTask(taskId: string) {
    await scanApi.cancel(taskId)
    stopPolling()
    await fetchTaskStatus(taskId)
  }

  return {
    tasks,
    total,
    loading,
    currentStatus,
    currentResults,
    detailLoading,
    fetchTasks,
    fetchTaskStatus,
    fetchTaskResults,
    loadTaskDetail,
    startPolling,
    stopPolling,
    cancelTask,
  }
})
