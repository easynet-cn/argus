<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Wifi,
  Globe,
  Terminal,
  Route,
  Search,
  Code2,
  Hash,
  Network,
} from '@lucide/vue'
import { toolApi } from '@/api/system'

// 当前激活的工具分类
const activeTab = ref<'network' | 'encode'>('network')

// ==================== 网络诊断工具状态 ====================

const pingForm = ref({ host: '', count: 4, timeout: 2000 })
const pingResult = ref('')
const pingLoading = ref(false)

const telnetForm = ref({ host: '', port: 80, timeout: 3000 })
const telnetResult = ref('')
const telnetLoading = ref(false)

const httpForm = ref({ url: '', timeout: 5000 })
const httpResult = ref('')
const httpLoading = ref(false)

const dnsForm = ref({ domain: '', record_type: 'A', dns_server: '' })
const dnsResult = ref('')
const dnsLoading = ref(false)
const dnsMode = ref<'dig' | 'nslookup'>('dig')

const tracerouteForm = ref({ host: '', max_hops: 30, timeout: 2000 })
const tracerouteResult = ref('')
const tracerouteLoading = ref(false)

const whoisForm = ref({ query: '' })
const whoisResult = ref('')
const whoisLoading = ref(false)

// ==================== 编码工具状态 ====================

const encodeForm = ref({ text: '', type: 'base64' as 'base64' | 'hex' | 'url' })
const encodeResult = ref('')
const encodeLoading = ref(false)
const decodeForm = ref({ text: '', type: 'base64' as 'base64' | 'hex' | 'url' })
const decodeResult = ref('')
const decodeLoading = ref(false)
const hashForm = ref({ text: '', algorithm: 'sha256' as 'md5' | 'sha1' | 'sha256' | 'sha512' })
const hashResult = ref('')
const hashLoading = ref(false)
const subnetForm = ref({ cidr: '192.168.1.0/24' })
const subnetResult = ref('')
const subnetLoading = ref(false)

// ==================== 网络诊断工具方法 ====================

async function runPing() {
  if (!pingForm.value.host) {
    ElMessage.warning('请输入目标主机')
    return
  }
  pingLoading.value = true
  pingResult.value = ''
  try {
    const res = await toolApi.ping(pingForm.value)
    pingResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    pingLoading.value = false
  }
}

async function runTelnet() {
  if (!telnetForm.value.host || !telnetForm.value.port) {
    ElMessage.warning('请输入主机和端口')
    return
  }
  telnetLoading.value = true
  telnetResult.value = ''
  try {
    const res = await toolApi.telnet(telnetForm.value)
    telnetResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    telnetLoading.value = false
  }
}

async function runHttp() {
  if (!httpForm.value.url) {
    ElMessage.warning('请输入 URL')
    return
  }
  httpLoading.value = true
  httpResult.value = ''
  try {
    const res = await toolApi.http(httpForm.value)
    httpResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    httpLoading.value = false
  }
}

async function runDns() {
  if (!dnsForm.value.domain) {
    ElMessage.warning('请输入域名')
    return
  }
  dnsLoading.value = true
  dnsResult.value = ''
  try {
    const req = {
      domain: dnsForm.value.domain,
      record_type: dnsForm.value.record_type,
      dns_server: dnsForm.value.dns_server || undefined,
    }
    const res = await (dnsMode.value === 'dig' ? toolApi.dig(req) : toolApi.nslookup(req))
    dnsResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    dnsLoading.value = false
  }
}

async function runTraceroute() {
  if (!tracerouteForm.value.host) {
    ElMessage.warning('请输入目标主机')
    return
  }
  tracerouteLoading.value = true
  tracerouteResult.value = ''
  try {
    const res = await toolApi.traceroute(tracerouteForm.value)
    tracerouteResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    tracerouteLoading.value = false
  }
}

async function runWhois() {
  if (!whoisForm.value.query) {
    ElMessage.warning('请输入查询内容（域名或 IP）')
    return
  }
  whoisLoading.value = true
  whoisResult.value = ''
  try {
    const res = await toolApi.whois(whoisForm.value)
    whoisResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    whoisLoading.value = false
  }
}

// ==================== 编码工具方法 ====================

async function runEncode() {
  if (!encodeForm.value.text) {
    ElMessage.warning('请输入待编码文本')
    return
  }
  encodeLoading.value = true
  encodeResult.value = ''
  try {
    const res = await toolApi.encode(encodeForm.value)
    encodeResult.value = (res as any)?.result || ''
  } catch {
    // 错误已在拦截器处理
  } finally {
    encodeLoading.value = false
  }
}

async function runDecode() {
  if (!decodeForm.value.text) {
    ElMessage.warning('请输入待解码文本')
    return
  }
  decodeLoading.value = true
  decodeResult.value = ''
  try {
    const res = await toolApi.decode(decodeForm.value)
    decodeResult.value = (res as any)?.result || ''
  } catch {
    // 错误已在拦截器处理
  } finally {
    decodeLoading.value = false
  }
}

async function runHash() {
  if (!hashForm.value.text) {
    ElMessage.warning('请输入待哈希文本')
    return
  }
  hashLoading.value = true
  hashResult.value = ''
  try {
    const res = await toolApi.hash(hashForm.value)
    hashResult.value = (res as any)?.result || ''
  } catch {
    // 错误已在拦截器处理
  } finally {
    hashLoading.value = false
  }
}

async function runSubnet() {
  if (!subnetForm.value.cidr) {
    ElMessage.warning('请输入 CIDR（如 192.168.1.0/24）')
    return
  }
  subnetLoading.value = true
  subnetResult.value = ''
  try {
    const res = await toolApi.subnet(subnetForm.value)
    subnetResult.value = typeof res === 'string' ? res : JSON.stringify(res, null, 2)
  } catch {
    // 错误已在拦截器处理
  } finally {
    subnetLoading.value = false
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    ElMessage.success('已复制到剪贴板')
  })
}
</script>

<template>
  <div class="space-y-4">
    <!-- 分类切换 -->
    <div class="flex items-center gap-2">
      <el-radio-group v-model="activeTab">
        <el-radio-button value="network">网络诊断</el-radio-button>
        <el-radio-button value="encode">编码与转换</el-radio-button>
      </el-radio-group>
    </div>

    <!-- ==================== 网络诊断工具 ==================== -->
    <div v-if="activeTab === 'network'" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <!-- Ping -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Wifi class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">Ping 连通性检测</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="主机">
            <el-input v-model="pingForm.host" placeholder="例如 example.com 或 192.168.1.1" />
          </el-form-item>
          <el-form-item label="次数">
            <el-input-number v-model="pingForm.count" :min="1" :max="20" />
          </el-form-item>
          <el-form-item label="超时(ms)">
            <el-input-number v-model="pingForm.timeout" :min="500" :step="500" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="pingLoading" @click="runPing">执行 Ping</el-button>
          </el-form-item>
        </el-form>
        <div v-if="pingResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(pingResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ pingResult }}</pre>
        </div>
      </div>

      <!-- Telnet -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Terminal class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">Telnet 端口连通</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="主机">
            <el-input v-model="telnetForm.host" placeholder="例如 192.168.1.1" />
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="telnetForm.port" :min="1" :max="65535" />
          </el-form-item>
          <el-form-item label="超时(ms)">
            <el-input-number v-model="telnetForm.timeout" :min="500" :step="500" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="telnetLoading" @click="runTelnet">执行 Telnet</el-button>
          </el-form-item>
        </el-form>
        <div v-if="telnetResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(telnetResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ telnetResult }}</pre>
        </div>
      </div>

      <!-- HTTP 探测 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Globe class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">HTTP 探测</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="URL">
            <el-input v-model="httpForm.url" placeholder="https://example.com/path" />
          </el-form-item>
          <el-form-item label="超时(ms)">
            <el-input-number v-model="httpForm.timeout" :min="1000" :step="1000" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="httpLoading" @click="runHttp">执行 HTTP</el-button>
          </el-form-item>
        </el-form>
        <div v-if="httpResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(httpResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ httpResult }}</pre>
        </div>
      </div>

      <!-- DNS 查询（dig / nslookup） -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Search class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">DNS 查询</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="模式">
            <el-radio-group v-model="dnsMode">
              <el-radio value="dig">dig</el-radio>
              <el-radio value="nslookup">nslookup</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="域名">
            <el-input v-model="dnsForm.domain" placeholder="example.com" />
          </el-form-item>
          <el-form-item label="记录类型">
            <el-select v-model="dnsForm.record_type" style="width: 100%">
              <el-option value="A" label="A (IPv4)" />
              <el-option value="AAAA" label="AAAA (IPv6)" />
              <el-option value="MX" label="MX (邮件)" />
              <el-option value="NS" label="NS (名称服务器)" />
              <el-option value="TXT" label="TXT" />
              <el-option value="CNAME" label="CNAME" />
              <el-option value="SOA" label="SOA" />
            </el-select>
          </el-form-item>
          <el-form-item label="DNS 服务器">
            <el-input v-model="dnsForm.dns_server" placeholder="可选，如 8.8.8.8" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="dnsLoading" @click="runDns">执行 DNS 查询</el-button>
          </el-form-item>
        </el-form>
        <div v-if="dnsResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(dnsResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ dnsResult }}</pre>
        </div>
      </div>

      <!-- Traceroute -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Route class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">Traceroute 路由追踪</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="主机">
            <el-input v-model="tracerouteForm.host" placeholder="例如 example.com" />
          </el-form-item>
          <el-form-item label="最大跳数">
            <el-input-number v-model="tracerouteForm.max_hops" :min="1" :max="64" />
          </el-form-item>
          <el-form-item label="超时(ms)">
            <el-input-number v-model="tracerouteForm.timeout" :min="500" :step="500" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="tracerouteLoading" @click="runTraceroute">执行追踪</el-button>
          </el-form-item>
        </el-form>
        <div v-if="tracerouteResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(tracerouteResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ tracerouteResult }}</pre>
        </div>
      </div>

      <!-- Whois -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Network class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">Whois 域名信息</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="查询">
            <el-input v-model="whoisForm.query" placeholder="域名或 IP，如 example.com" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="whoisLoading" @click="runWhois">执行 Whois</el-button>
          </el-form-item>
        </el-form>
        <div v-if="whoisResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(whoisResult)">复制</el-button>
          </div>
          <pre class="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200">{{ whoisResult }}</pre>
        </div>
      </div>
    </div>

    <!-- ==================== 编码与转换工具 ==================== -->
    <div v-if="activeTab === 'encode'" class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <!-- 编码 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Code2 class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">编码工具</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="文本">
            <el-input
              v-model="encodeForm.text"
              type="textarea"
              :rows="3"
              placeholder="输入待编码文本"
            />
          </el-form-item>
          <el-form-item label="类型">
            <el-select v-model="encodeForm.type" style="width: 100%">
              <el-option value="base64" label="Base64" />
              <el-option value="hex" label="Hex 十六进制" />
              <el-option value="url" label="URL 编码" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="encodeLoading" @click="runEncode">编码</el-button>
          </el-form-item>
        </el-form>
        <div v-if="encodeResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(encodeResult)">复制</el-button>
          </div>
          <pre class="max-h-48 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200 break-all whitespace-pre-wrap">{{ encodeResult }}</pre>
        </div>
      </div>

      <!-- 解码 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Code2 class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">解码工具</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="文本">
            <el-input
              v-model="decodeForm.text"
              type="textarea"
              :rows="3"
              placeholder="输入待解码文本"
            />
          </el-form-item>
          <el-form-item label="类型">
            <el-select v-model="decodeForm.type" style="width: 100%">
              <el-option value="base64" label="Base64" />
              <el-option value="hex" label="Hex 十六进制" />
              <el-option value="url" label="URL 解码" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="decodeLoading" @click="runDecode">解码</el-button>
          </el-form-item>
        </el-form>
        <div v-if="decodeResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(decodeResult)">复制</el-button>
          </div>
          <pre class="max-h-48 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200 break-all whitespace-pre-wrap">{{ decodeResult }}</pre>
        </div>
      </div>

      <!-- 哈希计算 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Hash class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">哈希计算</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="文本">
            <el-input
              v-model="hashForm.text"
              type="textarea"
              :rows="3"
              placeholder="输入待哈希文本"
            />
          </el-form-item>
          <el-form-item label="算法">
            <el-select v-model="hashForm.algorithm" style="width: 100%">
              <el-option value="md5" label="MD5" />
              <el-option value="sha1" label="SHA-1" />
              <el-option value="sha256" label="SHA-256" />
              <el-option value="sha512" label="SHA-512" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="hashLoading" @click="runHash">计算哈希</el-button>
          </el-form-item>
        </el-form>
        <div v-if="hashResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(hashResult)">复制</el-button>
          </div>
          <pre class="max-h-32 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200 break-all whitespace-pre-wrap">{{ hashResult }}</pre>
        </div>
      </div>

      <!-- 子网计算 -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
        <div class="mb-3 flex items-center gap-2">
          <Network class="h-5 w-5 text-cyan-400" />
          <h3 class="text-base font-medium text-slate-200">子网计算器</h3>
        </div>
        <el-form label-width="80px" label-position="right" size="small">
          <el-form-item label="CIDR">
            <el-input v-model="subnetForm.cidr" placeholder="例如 192.168.1.0/24" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="subnetLoading" @click="runSubnet">计算</el-button>
          </el-form-item>
        </el-form>
        <div v-if="subnetResult" class="mt-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-xs text-slate-400">结果</span>
            <el-button link size="small" @click="copyToClipboard(subnetResult)">复制</el-button>
          </div>
          <pre class="max-h-48 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-200 break-all whitespace-pre-wrap">{{ subnetResult }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>
