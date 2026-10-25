import http from './http'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  user: {
    id: string
    username: string
    role: string
    must_change_password: boolean
  }
}

export interface ChangePasswordRequest {
  old_password: string
  new_password: string
}

// 响应拦截器已解包 response.data，这里用类型断言获取实际数据
function unwrap<T>(p: Promise<unknown>): Promise<T> {
  return p as Promise<T>
}

export const authApi = {
  login: (data: LoginRequest) => unwrap<LoginResponse>(http.post('/auth/login', data)),
  logout: () => http.post('/auth/logout'),
  changePassword: (data: ChangePasswordRequest) => http.post('/auth/change-password', data),
}
