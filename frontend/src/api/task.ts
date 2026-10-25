import http from './http'

function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

/// 扫描任务
export interface ScanTask {
  id: string
  name: string
  task_type: string
  status: string
  launch_mode: string
  targets: any
  progress: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  locked: boolean
  priority: string
  schedule_config: any
  params: any
  node_id: string | null
}

export interface TaskListResult {
  items: ScanTask[]
  page: number
  page_size: number
}

export interface CreateTaskRequest {
  name: string
  task_type: string
  launch_mode?: 'manual' | 'scheduled' | 'periodic'
  targets: string[]
  priority?: 'low' | 'normal' | 'high' | 'critical'
  schedule_config?: any
  params?: any
  node_id?: string
}

export interface TaskListQuery {
  page?: number
  page_size?: number
  name?: string
  status?: string
  task_type?: string
}

export const taskApi = {
  list: (params?: TaskListQuery) =>
    unwrap<TaskListResult>(http.get('/tasks', { params })),
  get: (id: string) => unwrap<ScanTask>(http.get(`/tasks/${id}`)),
  create: (data: CreateTaskRequest) => unwrap<ScanTask>(http.post('/tasks', data)),
  update: (id: string, data: Partial<CreateTaskRequest>) =>
    unwrap<ScanTask>(http.put(`/tasks/${id}`, data)),
  delete: (id: string) => http.delete(`/tasks/${id}`),
  start: (id: string) => http.post(`/tasks/${id}/start`),
  pause: (id: string) => http.post(`/tasks/${id}/pause`),
  resume: (id: string) => http.post(`/tasks/${id}/resume`),
  stop: (id: string) => http.post(`/tasks/${id}/stop`),
  copy: (id: string) => unwrap<ScanTask>(http.post(`/tasks/${id}/copy`)),
  lock: (id: string) => http.post(`/tasks/${id}/lock`),
  unlock: (id: string) => http.post(`/tasks/${id}/unlock`),
}
