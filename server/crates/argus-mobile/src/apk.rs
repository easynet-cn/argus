//! APK 文件解析器
//!
//! APK 是 ZIP 格式，包含:
//! - AndroidManifest.xml (AXML 二进制)
//! - classes.dex / classes2.dex / ... (Dalvik 字节码)
//! - resources.arsc (编译后的资源)
//! - res/ 目录 (原始资源)
//! - META-INF/ (签名信息)
//! - lib/ (Native 库)

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use thiserror::Error;
use zip::ZipArchive;

use crate::axml::{self, AxmlNode};
use crate::dex;
use crate::types::*;

#[derive(Debug, Error)]
pub enum ApkError {
    #[error("文件不存在: {0}")]
    FileNotFound(String),
    #[error("打开 ZIP 失败: {0}")]
    ZipOpen(String),
    #[error("读取 ZIP 条目失败: {0}")]
    ZipRead(String),
    #[error("AndroidManifest.xml 缺失")]
    ManifestMissing,
    #[error("AXML 解析失败: {0}")]
    AxmlParse(#[from] axml::AxmlError),
    #[error("DEX 解析失败: {0}")]
    DexParse(#[from] dex::DexError),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// APK 解析器
pub struct ApkParser;

impl ApkParser {
    pub fn new() -> Self {
        Self
    }

    /// 从文件路径解析 APK
    pub fn parse_file(&self, path: &str) -> Result<ApkInfo, ApkError> {
        if !Path::new(path).exists() {
            return Err(ApkError::FileNotFound(path.to_string()));
        }
        // R7.1 修复：读取完整文件到内存，以便 V2/V3 签名块解析
        let data = std::fs::read(path)?;
        self.parse_bytes(&data)
    }

    /// 从字节数据解析 APK
    pub fn parse_bytes(&self, data: &[u8]) -> Result<ApkInfo, ApkError> {
        let cursor = std::io::Cursor::new(data);
        let mut zip = ZipArchive::new(cursor).map_err(|e| ApkError::ZipOpen(e.to_string()))?;

        self.parse_zip(&mut zip, data)
    }

    fn parse_zip<R: std::io::Read + std::io::Seek>(
        &self,
        zip: &mut ZipArchive<R>,
        raw: &[u8],
    ) -> Result<ApkInfo, ApkError> {
        // 1. 读取 AndroidManifest.xml
        let manifest_data = read_zip_entry(zip, "AndroidManifest.xml")?;
        let manifest_node = axml::parse_axml(&manifest_data)?;

        // 2. 解析 manifest 节点
        let mut apk_info = parse_manifest_node(&manifest_node);
        apk_info.file_size = raw.len() as u64;

        // 3. 解析 DEX 文件
        apk_info.dex_files = self.parse_dex_files(zip)?;

        // 4. 解析签名信息（R7.1：真实解析 V1 JAR + V2/V3 APK Signing Block）
        apk_info.signatures = self.parse_signatures(zip, raw)?;

        Ok(apk_info)
    }

    /// 解析所有 DEX 文件
    fn parse_dex_files<R: std::io::Read + std::io::Seek>(
        &self,
        zip: &mut ZipArchive<R>,
    ) -> Result<Vec<DexFileInfo>, ApkError> {
        let mut dex_files = Vec::new();
        let names: Vec<String> = zip
            .file_names()
            .map(|s| s.to_string())
            .collect();

        for name in &names {
            if name.ends_with(".dex") {
                let entry = match zip.by_name(name) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!("读取 DEX 文件 {} 失败: {}", name, e);
                        continue;
                    }
                };
                let size = entry.size();

                // 读取前 512 字节用于解析 header
                let mut buf = Vec::with_capacity(entry.size() as usize);
                let mut reader = entry;
                reader.read_to_end(&mut buf)?;

                match dex::parse_dex(&buf) {
                    Ok(info) => {
                        dex_files.push(DexFileInfo {
                            path: name.clone(),
                            size,
                            class_count: info.class_count,
                            method_count: info.method_count,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("DEX {} 解析失败: {}", name, e);
                    }
                }
            }
        }

        Ok(dex_files)
    }

    /// 解析签名信息（R7.1 修复：真实解析 V1 JAR + V2/V3 APK Signing Block）
    fn parse_signatures<R: std::io::Read + std::io::Seek>(
        &self,
        zip: &mut ZipArchive<R>,
        raw: &[u8],
    ) -> Result<Vec<SignatureInfo>, ApkError> {
        let mut sigs = Vec::new();
        let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();

        // V1 JAR 签名: META-INF/*.RSA / *.DSA / *.EC（PKCS#7 SignedData）
        for name in &names {
            let lower = name.to_lowercase();
            if lower.starts_with("meta-inf/")
                && (lower.ends_with(".rsa")
                    || lower.ends_with(".dsa")
                    || lower.ends_with(".ec"))
            {
                if let Ok(cert_data) = read_zip_entry(zip, name) {
                    if let Some(sig) = parse_v1_jar_signature(&cert_data) {
                        sigs.push(sig);
                    }
                }
            }
        }

        // V2/V3 APK Signing Block（ZIP Central Directory 之前的签名块）
        if let Some(v2v3_sigs) = parse_apk_signing_block(raw) {
            sigs.extend(v2v3_sigs);
        }

        Ok(sigs)
    }
}

impl Default for ApkParser {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取 ZIP 条目数据
fn read_zip_entry<R: std::io::Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>, ApkError> {
    let mut entry = zip
        .by_name(name)
        .map_err(|e| ApkError::ZipRead(format!("{}: {}", name, e)))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

// ===========================================================================
// R7.1: APK 签名证书真实解析（V1 JAR PKCS#7 + V2/V3 APK Signing Block）
// ===========================================================================

/// 读取 DER 长度字段，返回 (长度值, 长度字段自身占用的字节数)
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let b = data[0];
    if b < 0x80 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + n))
    }
}

/// 提取一个 DER TLV，返回 (值字节引用, 整个 TLV 占用的字节数)
fn extract_der_tlv(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 2 {
        return None;
    }
    let (length, length_size) = read_der_length(&data[1..])?;
    let value_start = 1 + length_size;
    let total_size = value_start + length;
    if data.len() < total_size {
        return None;
    }
    Some((&data[value_start..total_size], total_size))
}

/// 从 PKCS#7 SignedData (DER) 中提取所有 X.509 证书 DER 字节
///
/// PKCS#7 结构:
/// ```text
/// ContentInfo ::= SEQUENCE { OID 1.2.840.113549.1.7.2, [0] SignedData }
/// SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
///                          [0] IMPLICIT SET OF Certificate, ... }
/// ```
fn extract_certs_from_pkcs7(data: &[u8]) -> Vec<&[u8]> {
    let mut certs = Vec::new();

    // ContentInfo: SEQUENCE { OID, [0] explicit }
    let (content_info_value, _) = match extract_der_tlv(data) {
        Some(r) => r,
        None => return certs,
    };

    // 跳过 OID (contentType)
    let (_, oid_tlv_size) = match extract_der_tlv(content_info_value) {
        Some(r) => r,
        None => return certs,
    };
    let after_oid = &content_info_value[oid_tlv_size..];

    // [0] explicit content (0xA0 标签)
    if after_oid.is_empty() || after_oid[0] != 0xA0 {
        return certs;
    }
    let (explicit_value, _) = match extract_der_tlv(after_oid) {
        Some(r) => r,
        None => return certs,
    };

    // SignedData: SEQUENCE
    let (signed_data_value, _) = match extract_der_tlv(explicit_value) {
        Some(r) => r,
        None => return certs,
    };

    // 跳过 version (INTEGER)
    let (_, version_size) = match extract_der_tlv(signed_data_value) {
        Some(r) => r,
        None => return certs,
    };
    let rest = &signed_data_value[version_size..];

    // 跳过 digestAlgorithms (SET)
    let (_, digest_alg_size) = match extract_der_tlv(rest) {
        Some(r) => r,
        None => return certs,
    };
    let rest = &rest[digest_alg_size..];

    // 跳过 encapContentInfo (SEQUENCE)
    let (_, encap_size) = match extract_der_tlv(rest) {
        Some(r) => r,
        None => return certs,
    };
    let rest = &rest[encap_size..];

    // [0] IMPLICIT SET OF Certificate (0xA0 标签)
    if rest.is_empty() || rest[0] != 0xA0 {
        return certs;
    }
    let (certs_set_value, _) = match extract_der_tlv(rest) {
        Some(r) => r,
        None => return certs,
    };

    // 遍历 SET 中的每个 Certificate (SEQUENCE)
    let mut remaining = certs_set_value;
    while !remaining.is_empty() {
        match extract_der_tlv(remaining) {
            Some((_, total_size)) => {
                // 证书 DER = 整个 TLV (tag + length + value)
                certs.push(&remaining[..total_size]);
                remaining = &remaining[total_size..];
            }
            None => break,
        }
    }

    certs
}

/// 解析 X.509 证书 DER 字节，构建 SignatureInfo
fn cert_to_signature_info(cert_der: &[u8], algorithm: &str) -> Option<SignatureInfo> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    // SHA-256 指纹（DER 证书的 SHA-256，格式: AB:CD:EF:...）
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    let fingerprint = hash
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    // 主体 / 颁发者
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // 有效期
    let validity = cert.validity();
    let not_before = validity.not_before.to_string();
    let not_after = validity.not_after.to_string();

    Some(SignatureInfo {
        algorithm: algorithm.to_string(),
        cert_fingerprint: fingerprint,
        issuer,
        subject,
        not_before,
        not_after,
    })
}

/// 解析 V1 JAR 签名（META-INF/*.RSA|DSA|EC → PKCS#7 → X.509 证书）
fn parse_v1_jar_signature(pkcs7_data: &[u8]) -> Option<SignatureInfo> {
    let certs = extract_certs_from_pkcs7(pkcs7_data);
    for cert_der in certs {
        if let Some(sig) = cert_to_signature_info(cert_der, "V1 JAR (PKCS#7 SignedData)") {
            return Some(sig);
        }
    }
    None
}

/// APK Signing Block 魔术字节
const APK_SIG_BLOCK_MAGIC: &[u8] = b"APK Sig Block 42";

/// APK Signature Scheme v2 的 block ID
const APK_SIGNATURE_SCHEME_V2_ID: u32 = 0x7109871A;
/// APK Signature Scheme v3 的 block ID
const APK_SIGNATURE_SCHEME_V3_ID: u32 = 0xF05368C0;

/// 解析 V2/V3 APK Signing Block，从原始 APK 字节中提取签名证书
///
/// APK Signing Block 位于 ZIP Central Directory 之前，结构:
/// - size_of_block (uint64 LE)
/// - 0 或多个 key-value pair: { id (uint32 LE), value (length-prefixed bytes) }
/// - size_of_block (uint64 LE, 同首尾)
/// - magic "APK Sig Block 42" (16 bytes)
fn parse_apk_signing_block(raw: &[u8]) -> Option<Vec<SignatureInfo>> {
    let mut sigs = Vec::new();

    // 1. 定位 ZIP End of Central Directory (EOCD)
    // EOCD 签名: 0x06054b50 (PK\5\6)
    let eocd_sig = [0x50, 0x4B, 0x05, 0x06];
    // EOCD 最小 22 字节，最长 22 + 65535 (comment)
    let max_scan = raw.len().min(65557);
    let scan_start = raw.len().saturating_sub(max_scan);

    let mut eocd_offset = None;
    for i in (scan_start..raw.len().saturating_sub(21)).rev() {
        if raw[i..i + 4] == eocd_sig {
            eocd_offset = Some(i);
            break;
        }
    }
    let eocd_offset = eocd_offset?;

    // 2. 从 EOCD 读取 Central Directory 偏移
    // EOCD 结构: 4(sig) + 2(disk) + 2(cd_disk) + 4(entries_disk) + 4(entries)
    //            + 4(cd_size) + 4(cd_offset) + 2(comment_len) + comment
    let cd_offset = u32::from_le_bytes([
        raw[eocd_offset + 16],
        raw[eocd_offset + 17],
        raw[eocd_offset + 18],
        raw[eocd_offset + 19],
    ]) as usize;

    // 3. APK Signing Block 在 CD 之前
    if cd_offset < 24 || cd_offset > raw.len() {
        return None;
    }

    // 检查 magic: "APK Sig Block 42" 在 CD 前 16 字节
    let magic_start = cd_offset - 16;
    if magic_start < 24 {
        return None;
    }
    if &raw[magic_start..cd_offset] != APK_SIG_BLOCK_MAGIC {
        return None;
    }

    // 4. 读取 block size (在 magic 前 8 字节，uint64 LE)
    let block_size = u64::from_le_bytes([
        raw[magic_start - 8],
        raw[magic_start - 7],
        raw[magic_start - 6],
        raw[magic_start - 5],
        raw[magic_start - 4],
        raw[magic_start - 3],
        raw[magic_start - 2],
        raw[magic_start - 1],
    ]) as usize;

    // Signing Block 范围: [block_start, cd_offset)
    // block_start = cd_offset - block_size - 8 (8 字节是 block_size 自身的 uint64)
    let block_start = cd_offset.saturating_sub(block_size + 8);
    if block_start >= raw.len() {
        return None;
    }

    // Signing Block 内容: 从 block_start + 8 (跳过首部 size_of_block) 到 magic_start
    let block_content = &raw[block_start + 8..magic_start - 8];

    // 5. 遍历 key-value pairs
    let mut offset = 0;
    while offset + 12 <= block_content.len() {
        // pair: uint32 LE id + uint64 LE length + data[length]
        let pair_id = u32::from_le_bytes([
            block_content[offset],
            block_content[offset + 1],
            block_content[offset + 2],
            block_content[offset + 3],
        ]);
        let pair_len = u64::from_le_bytes([
            block_content[offset + 4],
            block_content[offset + 5],
            block_content[offset + 6],
            block_content[offset + 7],
            block_content[offset + 8],
            block_content[offset + 9],
            block_content[offset + 10],
            block_content[offset + 11],
        ]) as usize;

        if offset + 12 + pair_len > block_content.len() {
            break;
        }

        let pair_value = &block_content[offset + 12..offset + 12 + pair_len];

        // V2 (0x7109871A) 或 V3 (0xF05368C0)
        if pair_id == APK_SIGNATURE_SCHEME_V2_ID || pair_id == APK_SIGNATURE_SCHEME_V3_ID {
            let scheme_name = if pair_id == APK_SIGNATURE_SCHEME_V2_ID {
                "V2 (APK Signature Scheme v2)"
            } else {
                "V3 (APK Signature Scheme v3)"
            };

            // pair_value 是 length-prefixed signers
            // V2/V3 签名数据格式:
            // - length-prefixed sequence of signers
            //   每个 signer:
            //   - length-prefixed signed data
            //     signed data 包含: length-prefixed digests,
            //                       length-prefixed certificates,
            //                       length-prefixed additional attributes
            //   - ...
            if let Some(certs) = extract_certs_from_v2v3_signers(pair_value) {
                for cert_der in certs {
                    if let Some(sig) = cert_to_signature_info(&cert_der, scheme_name) {
                        sigs.push(sig);
                    }
                }
            }
        }

        offset += 12 + pair_len;
    }

    if sigs.is_empty() {
        None
    } else {
        Some(sigs)
    }
}

/// 从 V2/V3 签名数据中提取证书
///
/// V2/V3 签名数据的 signers 部分使用 length-prefixed (uint32 LE) 编码:
/// - uint32 length + signers_data[length]
///   signers_data: 0 或多个 signer
///   每个 signer: uint32 length + signer_data[length]
///     signer_data: uint32 signed_data_length + signed_data[signed_data_length]
///       signed_data: uint32 digests_len + digests + uint32 certs_len + certs + ...
///         certs: uint32 length + cert_sequence
///           cert_sequence: 0 或多个 uint32 length + cert_der[length]
fn extract_certs_from_v2v3_signers(signers_data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    // 外层: uint32 LE length + signers
    if signers_data.len() < 4 {
        return None;
    }
    let signers_len = u32::from_le_bytes([
        signers_data[0],
        signers_data[1],
        signers_data[2],
        signers_data[3],
    ]) as usize;
    if 4 + signers_len > signers_data.len() {
        return None;
    }
    let signers = &signers_data[4..4 + signers_len];

    // 遍历每个 signer
    let mut offset = 0;
    while offset + 4 <= signers.len() {
        let signer_len = u32::from_le_bytes([
            signers[offset],
            signers[offset + 1],
            signers[offset + 2],
            signers[offset + 3],
        ]) as usize;
        if offset + 4 + signer_len > signers.len() {
            break;
        }
        let signer = &signers[offset + 4..offset + 4 + signer_len];
        offset += 4 + signer_len;

        // signer: uint32 signed_data_len + signed_data
        if signer.len() < 4 {
            continue;
        }
        let signed_data_len = u32::from_le_bytes([
            signer[0],
            signer[1],
            signer[2],
            signer[3],
        ]) as usize;
        if 4 + signed_data_len > signer.len() {
            continue;
        }
        let signed_data = &signer[4..4 + signed_data_len];

        // signed_data: uint32 digests_len + digests + uint32 certs_len + certs
        if signed_data.len() < 4 {
            continue;
        }
        let digests_len = u32::from_le_bytes([
            signed_data[0],
            signed_data[1],
            signed_data[2],
            signed_data[3],
        ]) as usize;
        if 4 + digests_len > signed_data.len() {
            continue;
        }
        let after_digests = &signed_data[4 + digests_len..];

        // certificates: uint32 certs_total_len + cert_sequence
        if after_digests.len() < 4 {
            continue;
        }
        let certs_total_len = u32::from_le_bytes([
            after_digests[0],
            after_digests[1],
            after_digests[2],
            after_digests[3],
        ]) as usize;
        if 4 + certs_total_len > after_digests.len() {
            continue;
        }
        let cert_sequence = &after_digests[4..4 + certs_total_len];

        // 遍历每个证书: uint32 cert_len + cert_der
        let mut cert_offset = 0;
        while cert_offset + 4 <= cert_sequence.len() {
            let cert_len = u32::from_le_bytes([
                cert_sequence[cert_offset],
                cert_sequence[cert_offset + 1],
                cert_sequence[cert_offset + 2],
                cert_sequence[cert_offset + 3],
            ]) as usize;
            if cert_offset + 4 + cert_len > cert_sequence.len() {
                break;
            }
            let cert_der = &cert_sequence[cert_offset + 4..cert_offset + 4 + cert_len];
            certs.push(cert_der.to_vec());
            cert_offset += 4 + cert_len;
        }
    }

    if certs.is_empty() {
        None
    } else {
        Some(certs)
    }
}

/// 从 AXML manifest 节点解析 APK 信息
fn parse_manifest_node(root: &AxmlNode) -> ApkInfo {
    let mut info = ApkInfo {
        package: root
            .get_attr("package")
            .unwrap_or("")
            .to_string(),
        version_name: root
            .get_attr("versionName")
            .unwrap_or("")
            .to_string(),
        version_code: root
            .get_attr("versionCode")
            .and_then(|s| {
                let s = s.trim_start_matches("0x");
                if s.is_empty() {
                    None
                } else {
                    s.parse::<i64>().ok().or_else(|| i64::from_str_radix(s, 16).ok())
                }
            })
            .unwrap_or(0),
        min_sdk: root
            .get_attr("minSdkVersion")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1),
        target_sdk: root
            .get_attr("targetSdkVersion")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1),
        compile_sdk: root
            .get_attr("compileSdkVersion")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1),
        app_name: String::new(),
        main_activity: None,
        dex_files: vec![],
        permissions: vec![],
        components: AndroidComponents::default(),
        meta_data: HashMap::new(),
        file_size: 0,
        signatures: vec![],
    };

    // 解析 uses-permission 子节点
    for child in &root.children {
        if child.tag == "uses-permission" {
            if let Some(name) = child.get_attr("name") {
                info.permissions.push(name.to_string());
            }
        }
        // 解析 uses-sdk（如果 SDK 版本在 uses-sdk 中）
        if child.tag == "uses-sdk" {
            if let Some(v) = child.get_attr("minSdkVersion") {
                info.min_sdk = parse_sdk_int(v);
            }
            if let Some(v) = child.get_attr("targetSdkVersion") {
                info.target_sdk = parse_sdk_int(v);
            }
        }
        // 解析 application 子节点
        if child.tag == "application" {
            if let Some(label) = child.get_attr("label") {
                info.app_name = label.to_string();
            }
            if let Some(name) = child.get_attr("name") {
                // 自定义 Application 类
                info.meta_data.insert("application".to_string(), name.to_string());
            }
            // R7.3 修复：将 application 节点的所有属性真实存入 meta_data
            // 包含 allowBackup/debuggable/usesCleartextTraffic/networkSecurityConfig 等
            // 以便 config_check.rs 能从 meta_data 读取真实值而非走默认值
            for (attr_name, attr_value) in &child.attributes {
                // "application" 键已被上方自定义 Application 类占用，跳过避免覆盖
                if attr_name != "application" {
                    info.meta_data
                        .insert(attr_name.clone(), attr_value.clone());
                }
            }
            // 提取所有组件
            for app_child in &child.children {
                match app_child.tag.as_str() {
                    "activity" => {
                        let mut ci = parse_component(app_child);
                        // 检查是否有 LAUNCHER Intent Filter
                        for intent_filter in &app_child.children {
                            if intent_filter.tag == "intent-filter" {
                                let mut actions = vec![];
                                let mut categories = vec![];
                                for if_child in &intent_filter.children {
                                    if if_child.tag == "action" {
                                        if let Some(name) = if_child.get_attr("name") {
                                            actions.push(name.to_string());
                                        }
                                    }
                                    if if_child.tag == "category" {
                                        if let Some(name) = if_child.get_attr("name") {
                                            categories.push(name.to_string());
                                        }
                                    }
                                }
                                if actions.iter().any(|a| a == "android.intent.action.MAIN")
                                    && categories.iter().any(|c| c == "android.intent.category.LAUNCHER")
                                {
                                    ci.has_launcher = true;
                                    ci.is_main = true;
                                    if info.main_activity.is_none() {
                                        info.main_activity = Some(ci.name.clone());
                                    }
                                }
                                ci.intent_filters.push(crate::types::IntentFilter {
                                    actions,
                                    categories,
                                    data_schemes: vec![],
                                    data_hosts: vec![],
                                });
                            }
                        }
                        info.components.activities.push(ci);
                    }
                    "service" => {
                        info.components.services.push(parse_component(app_child));
                    }
                    "receiver" => {
                        info.components.receivers.push(parse_component(app_child));
                    }
                    "provider" => {
                        info.components.providers.push(parse_component(app_child));
                    }
                    "meta-data" => {
                        if let (Some(name), Some(value)) =
                            (app_child.get_attr("name"), app_child.get_attr("value"))
                        {
                            info.meta_data.insert(name.to_string(), value.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    info
}

/// 解析组件信息
fn parse_component(node: &AxmlNode) -> ComponentInfo {
    let name = node.get_attr("name").unwrap_or("").to_string();
    // exported 属性可能是 "true"/"false" 字符串，或 0x0/0xFFFFFFFF 的整数
    let exported_str = node.get_attr("exported").unwrap_or("");
    let exported = match exported_str.to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            // 整数形式：0xFFFFFFFF = true，0x0 = false
            if let Ok(val) = exported_str.parse::<u32>() {
                val != 0
            } else if let Ok(val) = i64::from_str_radix(exported_str.trim_start_matches("0x"), 16) {
                val != 0
            } else {
                false
            }
        }
    };

    ComponentInfo {
        name,
        exported,
        permission: node
            .get_attr("permission")
            .map(|s| s.to_string()),
        intent_filters: vec![],
        has_launcher: false,
        is_main: false,
        task_affinity: node
            .get_attr("taskAffinity")
            .map(|s| s.to_string()),
    }
}

/// 解析 SDK 版本号（支持 "21" 或 "0x15" 形式）
fn parse_sdk_int(s: &str) -> i32 {
    if let Ok(v) = s.parse::<i32>() {
        return v;
    }
    if let Ok(v) = i32::from_str_radix(s.trim_start_matches("0x"), 16) {
        return v;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sdk_int_decimal() {
        assert_eq!(parse_sdk_int("21"), 21);
        assert_eq!(parse_sdk_int("29"), 29);
    }

    #[test]
    fn test_parse_sdk_int_hex() {
        assert_eq!(parse_sdk_int("0x15"), 21);
    }

    #[test]
    fn test_parse_sdk_int_invalid() {
        assert_eq!(parse_sdk_int("invalid"), 1);
    }

    #[test]
    fn test_parse_component_exported_true() {
        let mut node = AxmlNode::new("activity");
        node.attributes.insert("name".into(), "com.example.MainActivity".into());
        node.attributes.insert("exported".into(), "true".into());
        let ci = parse_component(&node);
        assert!(ci.exported);
        assert_eq!(ci.name, "com.example.MainActivity");
    }

    #[test]
    fn test_parse_component_exported_false() {
        let mut node = AxmlNode::new("activity");
        node.attributes.insert("name".into(), "com.example.Secret".into());
        node.attributes.insert("exported".into(), "false".into());
        let ci = parse_component(&node);
        assert!(!ci.exported);
    }

    #[test]
    fn test_parse_component_no_exported_attr() {
        let mut node = AxmlNode::new("service");
        node.attributes.insert("name".into(), "com.example.Svc".into());
        let ci = parse_component(&node);
        assert!(!ci.exported);
    }

    #[test]
    fn test_parse_manifest_node_simple() {
        let mut root = AxmlNode::new("manifest");
        root.attributes.insert("package".into(), "com.example.app".into());
        root.attributes.insert("versionName".into(), "1.0".into());
        root.attributes.insert("versionCode".into(), "1".into());

        let mut perm = AxmlNode::new("uses-permission");
        perm.attributes.insert("name".into(), "android.permission.INTERNET".into());
        root.children.push(perm);

        let info = parse_manifest_node(&root);
        assert_eq!(info.package, "com.example.app");
        assert_eq!(info.version_name, "1.0");
        assert_eq!(info.version_code, 1);
        assert_eq!(info.permissions.len(), 1);
        assert_eq!(info.permissions[0], "android.permission.INTERNET");
    }

    #[test]
    fn test_parse_manifest_node_with_application() {
        let mut root = AxmlNode::new("manifest");
        root.attributes.insert("package".into(), "com.example.app".into());

        let mut app = AxmlNode::new("application");
        app.attributes.insert("label".into(), "TestApp".into());

        let mut activity = AxmlNode::new("activity");
        activity.attributes.insert("name".into(), "com.example.MainActivity".into());
        activity.attributes.insert("exported".into(), "true".into());

        app.children.push(activity);
        root.children.push(app);

        let info = parse_manifest_node(&root);
        assert_eq!(info.app_name, "TestApp");
        assert_eq!(info.components.activities.len(), 1);
        assert!(info.components.activities[0].exported);
    }

    /// R7.3 验证：application 节点的安全相关属性应真实存入 meta_data
    /// 避免后续 config_check 走默认值（allowBackup=true, debuggable=false）
    #[test]
    fn test_parse_manifest_node_application_attrs_stored() {
        let mut root = AxmlNode::new("manifest");
        root.attributes
            .insert("package".into(), "com.example.secure".into());

        let mut app = AxmlNode::new("application");
        app.attributes
            .insert("allowBackup".into(), "false".into());
        app.attributes
            .insert("debuggable".into(), "true".into());
        app.attributes
            .insert("usesCleartextTraffic".into(), "false".into());
        app.attributes
            .insert("networkSecurityConfig".into(), "@xml/network_security_config".into());
        app.attributes
            .insert("label".into(), "SecureApp".into());
        root.children.push(app);

        let info = parse_manifest_node(&root);

        // 关键安全属性应真实存入 meta_data，而非走默认值
        assert_eq!(info.meta_data.get("allowBackup").map(|s| s.as_str()), Some("false"));
        assert_eq!(info.meta_data.get("debuggable").map(|s| s.as_str()), Some("true"));
        assert_eq!(
            info.meta_data.get("usesCleartextTraffic").map(|s| s.as_str()),
            Some("false")
        );
        assert_eq!(
            info.meta_data.get("networkSecurityConfig").map(|s| s.as_str()),
            Some("@xml/network_security_config")
        );
        // label 走 app_name，但也应存入 meta_data
        assert_eq!(info.meta_data.get("label").map(|s| s.as_str()), Some("SecureApp"));
    }

    /// R7.3 验证：application 节点无 allowBackup 属性时，meta_data 不应包含该键
    /// config_check 据此走默认值 true（Android 默认开启备份）
    #[test]
    fn test_parse_manifest_node_application_attrs_absent() {
        let mut root = AxmlNode::new("manifest");
        root.attributes
            .insert("package".into(), "com.example.default".into());

        let app = AxmlNode::new("application");
        root.children.push(app);

        let info = parse_manifest_node(&root);

        // 未显式声明时，meta_data 不应包含 allowBackup，让 config_check 走默认值
        assert!(!info.meta_data.contains_key("allowBackup"));
        assert!(!info.meta_data.contains_key("debuggable"));
        assert!(!info.meta_data.contains_key("usesCleartextTraffic"));
    }

    // ===== R7.1 签名解析测试 =====

    #[test]
    fn test_read_der_length_short() {
        // 1 字节长度: 0x05 = 5
        let (len, size) = read_der_length(&[0x05]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(size, 1);
    }

    #[test]
    fn test_read_der_length_long() {
        // 2 字节长度: 0x82 0x01 0x00 = 256
        let (len, size) = read_der_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(size, 3);
    }

    #[test]
    fn test_extract_der_tlv_simple() {
        // SEQUENCE { INTEGER 42 } => 30 03 02 01 2A
        let data = [0x30, 0x03, 0x02, 0x01, 0x2A];
        let (value, total) = extract_der_tlv(&data).unwrap();
        assert_eq!(total, 5);
        assert_eq!(value, &[0x02, 0x01, 0x2A]);
    }

    /// 最小自签名 X.509 证书 DER（仅用于 PKCS#7 解析结构验证）
    /// 结构: SEQUENCE { OID(signedData), [0] SEQUENCE { INT(1), SET, SEQ, [0] SET { cert } } }
    #[test]
    fn test_extract_certs_from_pkcs7_minimal() {
        // 构建一个最小 PKCS#7 结构
        // Certificate (最小): 30 02 30 00 (空 SEQUENCE)
        let cert_tlv: &[u8] = &[0x30, 0x02, 0x30, 0x00]; // Certificate SEQUENCE containing empty SEQUENCE

        // certificates field: [0] IMPLICIT SET OF Certificate
        // 0xA0 + length + cert_tlv
        let certs_field = {
            let mut buf = vec![0xA0u8];
            buf.push(cert_tlv.len() as u8);
            buf.extend_from_slice(cert_tlv);
            buf
        };

        // encapContentInfo: SEQUENCE { OID }
        let encap_content = {
            let mut buf = vec![0x30u8];
            let oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // OID placeholder
            buf.push(oid.len() as u8);
            buf.extend_from_slice(oid);
            buf
        };

        // digestAlgorithms: SET { }
        let digest_algs = vec![0x31u8, 0x00];

        // version: INTEGER 1
        let version = vec![0x02u8, 0x01, 0x01];

        // SignedData: SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates }
        let signed_data = {
            let mut inner = Vec::new();
            inner.extend_from_slice(&version);
            inner.extend_from_slice(&digest_algs);
            inner.extend_from_slice(&encap_content);
            inner.extend_from_slice(&certs_field);
            let mut buf = vec![0x30u8];
            buf.push(inner.len() as u8);
            buf.extend_from_slice(&inner);
            buf
        };

        // [0] explicit: 0xA0 + length + SignedData
        let explicit = {
            let mut buf = vec![0xA0u8];
            buf.push(signed_data.len() as u8);
            buf.extend_from_slice(&signed_data);
            buf
        };

        // OID 1.2.840.113549.1.7.2 (signedData)
        let oid_signed_data: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

        // ContentInfo: SEQUENCE { OID, [0] explicit }
        let content_info = {
            let mut inner = Vec::new();
            inner.extend_from_slice(oid_signed_data);
            inner.extend_from_slice(&explicit);
            let mut buf = vec![0x30u8];
            buf.push(inner.len() as u8);
            buf.extend_from_slice(&inner);
            buf
        };

        let certs = extract_certs_from_pkcs7(&content_info);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert_tlv);
    }

    #[test]
    fn test_parse_v1_jar_signature_no_cert() {
        // 空数据应返回 None
        assert!(parse_v1_jar_signature(&[]).is_none());
        assert!(parse_v1_jar_signature(&[0x30, 0x00]).is_none());
    }

    #[test]
    fn test_parse_apk_signing_block_no_block() {
        // 空数据或无 EOCD 的数据应返回 None
        assert!(parse_apk_signing_block(&[]).is_none());
        assert!(parse_apk_signing_block(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn test_extract_certs_from_v2v3_signers_empty() {
        assert!(extract_certs_from_v2v3_signers(&[]).is_none());
        assert!(extract_certs_from_v2v3_signers(&[0x00, 0x00, 0x00, 0x00]).is_none());
    }
}
