import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  networkAssetApi,
  applicationAssetApi,
  databaseAssetApi,
  assetGroupApi,
  type NetworkAsset,
  type ApplicationAsset,
  type DatabaseAsset,
  type AssetGroup,
  type AssetGroupNode,
  type PageQuery,
  type CreateNetworkAssetRequest,
  type UpdateNetworkAssetRequest,
  type CreateApplicationAssetRequest,
  type UpdateApplicationAssetRequest,
  type CreateDatabaseAssetRequest,
  type UpdateDatabaseAssetRequest,
  type CreateAssetGroupRequest,
  type UpdateAssetGroupRequest,
} from '@/api/asset'

export const useAssetStore = defineStore('asset', () => {
  // 网络资产
  const networkAssets = ref<NetworkAsset[]>([])
  const networkTotal = ref(0)
  const networkLoading = ref(false)

  // 应用资产
  const applicationAssets = ref<ApplicationAsset[]>([])
  const applicationTotal = ref(0)
  const applicationLoading = ref(false)

  // 数据库资产
  const databaseAssets = ref<DatabaseAsset[]>([])
  const databaseTotal = ref(0)
  const databaseLoading = ref(false)

  // 资产组
  const assetGroups = ref<AssetGroup[]>([])
  const assetGroupTree = ref<AssetGroupNode[]>([])
  const groupLoading = ref(false)

  // ===== 网络资产操作 =====
  async function fetchNetworkAssets(params?: PageQuery) {
    networkLoading.value = true
    try {
      const res = await networkAssetApi.list(params)
      networkAssets.value = res.items
      // 后端未返回 total，用 items 长度近似（分页场景下取首页时近似总数需额外查询）
      networkTotal.value = res.items.length
    } finally {
      networkLoading.value = false
    }
  }

  async function createNetworkAsset(data: CreateNetworkAssetRequest) {
    return await networkAssetApi.create(data)
  }

  async function updateNetworkAsset(id: string, data: UpdateNetworkAssetRequest) {
    return await networkAssetApi.update(id, data)
  }

  async function deleteNetworkAsset(id: string) {
    await networkAssetApi.delete(id)
  }

  async function batchDeleteNetworkAssets(ids: string[]) {
    return await networkAssetApi.batchDelete(ids)
  }

  // ===== 应用资产操作 =====
  async function fetchApplicationAssets(params?: PageQuery) {
    applicationLoading.value = true
    try {
      const res = await applicationAssetApi.list(params)
      applicationAssets.value = res.items
      applicationTotal.value = res.items.length
    } finally {
      applicationLoading.value = false
    }
  }

  async function createApplicationAsset(data: CreateApplicationAssetRequest) {
    return await applicationAssetApi.create(data)
  }

  async function updateApplicationAsset(id: string, data: UpdateApplicationAssetRequest) {
    return await applicationAssetApi.update(id, data)
  }

  async function deleteApplicationAsset(id: string) {
    await applicationAssetApi.delete(id)
  }

  async function batchDeleteApplicationAssets(ids: string[]) {
    return await applicationAssetApi.batchDelete(ids)
  }

  // ===== 数据库资产操作 =====
  async function fetchDatabaseAssets(params?: PageQuery) {
    databaseLoading.value = true
    try {
      const res = await databaseAssetApi.list(params)
      databaseAssets.value = res.items
      databaseTotal.value = res.items.length
    } finally {
      databaseLoading.value = false
    }
  }

  async function createDatabaseAsset(data: CreateDatabaseAssetRequest) {
    return await databaseAssetApi.create(data)
  }

  async function updateDatabaseAsset(id: string, data: UpdateDatabaseAssetRequest) {
    return await databaseAssetApi.update(id, data)
  }

  async function deleteDatabaseAsset(id: string) {
    await databaseAssetApi.delete(id)
  }

  async function batchDeleteDatabaseAssets(ids: string[]) {
    return await databaseAssetApi.batchDelete(ids)
  }

  // ===== 资产组操作 =====
  async function fetchAssetGroups(params?: PageQuery) {
    groupLoading.value = true
    try {
      const res = await assetGroupApi.list(params)
      assetGroups.value = res.items
    } finally {
      groupLoading.value = false
    }
  }

  async function fetchAssetGroupTree() {
    groupLoading.value = true
    try {
      const res = await assetGroupApi.tree()
      assetGroupTree.value = res.items
    } finally {
      groupLoading.value = false
    }
  }

  async function createAssetGroup(data: CreateAssetGroupRequest) {
    return await assetGroupApi.create(data)
  }

  async function updateAssetGroup(id: string, data: UpdateAssetGroupRequest) {
    return await assetGroupApi.update(id, data)
  }

  async function deleteAssetGroup(id: string) {
    await assetGroupApi.delete(id)
  }

  return {
    // 网络资产
    networkAssets,
    networkTotal,
    networkLoading,
    fetchNetworkAssets,
    createNetworkAsset,
    updateNetworkAsset,
    deleteNetworkAsset,
    batchDeleteNetworkAssets,
    // 应用资产
    applicationAssets,
    applicationTotal,
    applicationLoading,
    fetchApplicationAssets,
    createApplicationAsset,
    updateApplicationAsset,
    deleteApplicationAsset,
    batchDeleteApplicationAssets,
    // 数据库资产
    databaseAssets,
    databaseTotal,
    databaseLoading,
    fetchDatabaseAssets,
    createDatabaseAsset,
    updateDatabaseAsset,
    deleteDatabaseAsset,
    batchDeleteDatabaseAssets,
    // 资产组
    assetGroups,
    assetGroupTree,
    groupLoading,
    fetchAssetGroups,
    fetchAssetGroupTree,
    createAssetGroup,
    updateAssetGroup,
    deleteAssetGroup,
  }
})
