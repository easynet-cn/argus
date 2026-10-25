//! Android 二进制 XML (AXML) 解析器
//!
//! APK 中的 AndroidManifest.xml 和其他 XML 资源是 AXML 格式，
//! 需要专门的解析器将其转换为可读结构。

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AxmlError {
    #[error("AXML 文件过短: {0} bytes")]
    TooShort(usize),
    #[error("无效的 AXML 魔数: 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("字符串池解析失败: {0}")]
    StringPoolError(String),
    #[error("资源映射解析失败: {0}")]
    ResourceMapError(String),
    #[error("XML 节点解析失败: {0}")]
    XmlNodeError(String),
    #[error("IO 错误: {0}")]
    Io(String),
}

/// AXML 文件头
#[derive(Debug, Clone)]
pub struct AxmlHeader {
    /// 文件类型 (magic)
    pub magic: u32,
    /// 文件大小
    pub file_size: u32,
}

/// 字符串池
#[derive(Debug, Clone, Default)]
pub struct StringPool {
    pub strings: Vec<String>,
}

/// 解析后的 AXML 节点
#[derive(Debug, Clone)]
pub struct AxmlNode {
    pub tag: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<AxmlNode>,
}

impl AxmlNode {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    pub fn find_children(&self, tag: &str) -> Vec<&AxmlNode> {
        self.children.iter().filter(|c| c.tag == tag).collect()
    }
}

/// 解析 AXML 二进制数据为节点树
pub fn parse_axml(data: &[u8]) -> Result<AxmlNode, AxmlError> {
    if data.len() < 8 {
        return Err(AxmlError::TooShort(data.len()));
    }

    // 读取文件头
    let magic = read_u32_le(data, 0)?;
    if magic != 0x00080003 {
        return Err(AxmlError::InvalidMagic(magic));
    }
    let _file_size = read_u32_le(data, 4)?;

    let mut offset = 8;
    let mut string_pool: Option<StringPool> = None;
    // 资源 ID 池（用于属性名映射，这里我们直接用字符串池）
    let mut _resource_ids: Vec<u32> = Vec::new();

    // 第一遍：读取字符串池和资源 ID 池
    while offset + 8 <= data.len() {
        let chunk_type = read_u16_le(data, offset)?;
        let chunk_size = read_u32_le(data, offset + 4)? as usize;
        if chunk_size == 0 || offset + chunk_size > data.len() {
            break;
        }

        match chunk_type {
            0x0001 => {
                // RES_STRING_POOL_TYPE
                string_pool = Some(parse_string_pool(&data[offset..offset + chunk_size])?);
            }
            0x0180 => {
                // RES_XML_RESOURCE_MAP_TYPE
                _resource_ids = parse_resource_map(&data[offset..offset + chunk_size])?;
            }
            0x0003 | 0x0004 | 0x0170 | 0x0171 => {
                // RES_XML_TYPE / RES_XML_START_NAMESPACE / RES_XML_END_NAMESPACE
                // 这些是 XML 命名空间声明，我们跳过命名空间信息直接进入子 chunk
                // 真正的 XML 内容在后续的 chunk 中
                break;
            }
            _ => {}
        }
        offset += chunk_size;
    }

    let string_pool = string_pool.ok_or_else(|| AxmlError::StringPoolError("字符串池缺失".into()))?;

    // 第二遍：解析 XML 节点
    let root = parse_xml_chunks(data, offset, &string_pool)?;

    Ok(root)
}

/// 解析字符串池
fn parse_string_pool(data: &[u8]) -> Result<StringPool, AxmlError> {
    if data.len() < 28 {
        return Err(AxmlError::StringPoolError(format!("数据过短: {} bytes", data.len())));
    }

    let string_count = read_u32_le(data, 8)? as usize;
    // flags at offset 16 (bit 8 = UTF-8 encoding)
    let flags = read_u32_le(data, 16)?;
    let is_utf8 = (flags & (1 << 8)) != 0;
    let strings_start = read_u32_le(data, 20)? as usize;

    // 读取字符串偏移表
    let mut offsets: Vec<u32> = Vec::with_capacity(string_count);
    for i in 0..string_count {
        let off = read_u32_le(data, 28 + i * 4)?;
        offsets.push(off);
    }

    let mut strings: Vec<String> = Vec::with_capacity(string_count);
    for off in offsets {
        let abs = strings_start + off as usize;
        if abs >= data.len() {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            read_utf8_string(data, abs)?
        } else {
            read_utf16_string(data, abs)?
        };
        strings.push(s);
    }

    Ok(StringPool { strings })
}

/// 读取 UTF-16 字符串（Android 旧格式）
fn read_utf16_string(data: &[u8], offset: usize) -> Result<String, AxmlError> {
    if offset + 4 > data.len() {
        return Ok(String::new());
    }
    // 前 2 字节是字符数（UTF-16），后 2 字节是字节数
    let char_count = read_u16_le(data, offset)? as usize;
    let start = offset + 4;
    let end = (start + char_count * 2).min(data.len());
    let mut utf16: Vec<u16> = Vec::with_capacity(char_count);
    for i in 0..char_count {
        let pos = start + i * 2;
        if pos + 2 > end {
            break;
        }
        utf16.push(read_u16_le(data, pos)?);
    }
    Ok(String::from_utf16_lossy(&utf16))
}

/// 读取 UTF-8 字符串（Android 新格式）
fn read_utf8_string(data: &[u8], offset: usize) -> Result<String, AxmlError> {
    if offset + 2 > data.len() {
        return Ok(String::new());
    }
    // UTF-8 格式：1 字节字符数 + 1 字节字节数 + 数据
    let _char_count = data[offset];
    let byte_count = data[offset + 1] as usize;
    let start = offset + 2;
    let end = (start + byte_count).min(data.len());
    Ok(String::from_utf8_lossy(&data[start..end]).to_string())
}

/// 解析资源映射
fn parse_resource_map(data: &[u8]) -> Result<Vec<u32>, AxmlError> {
    // 跳过 chunk header (8 bytes)
    let mut ids = Vec::new();
    let mut offset = 8;
    while offset + 4 <= data.len() {
        ids.push(read_u32_le(data, offset)?);
        offset += 4;
    }
    Ok(ids)
}

/// 解析 XML chunk 树
fn parse_xml_chunks(data: &[u8], mut offset: usize, string_pool: &StringPool) -> Result<AxmlNode, AxmlError> {
    // 创建虚拟根节点
    let mut root = AxmlNode::new("root");
    // 用栈维护当前节点路径
    let mut stack: Vec<AxmlNode> = vec![root.clone()];

    while offset + 8 <= data.len() {
        let chunk_type = read_u16_le(data, offset)?;
        let chunk_size = read_u32_le(data, offset + 4)? as usize;
        if chunk_size == 0 || offset + chunk_size > data.len() {
            break;
        }

        match chunk_type {
            0x0102 => {
                // RES_XML_START_ELEMENT_TYPE - 开始标签
                let node = parse_start_element(&data[offset..offset + chunk_size], string_pool)?;
                stack.push(node);
            }
            0x0103 => {
                // RES_XML_END_ELEMENT_TYPE - 结束标签
                if stack.len() <= 1 {
                    break;
                }
                let node = stack.pop().unwrap();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                }
            }
            _ => {}
        }
        offset += chunk_size;
    }

    // 把栈剩余的节点归位到 root
    while stack.len() > 1 {
        let node = stack.pop().unwrap();
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        }
    }
    if let Some(node) = stack.pop() {
        root = node;
    }

    Ok(root)
}

/// 解析 START_ELEMENT chunk
fn parse_start_element(data: &[u8], string_pool: &StringPool) -> Result<AxmlNode, AxmlError> {
    if data.len() < 36 {
        return Err(AxmlError::XmlNodeError("START_ELEMENT chunk 过短".into()));
    }
    // chunk header (8 bytes) + lineNumber (4) + comment (4) + namespace (4) + name (4)
    let name_idx = read_u32_le(data, 16)? as usize;
    let tag = string_pool
        .strings
        .get(name_idx)
        .cloned()
        .unwrap_or_default();

    // attribute start at offset 20, attribute size at 20, count at 28
    // 实际布局：
    // 0-1: chunkType (u16)
    // 2-3: headerSize (u16) = 0x0010 (16 bytes)
    // 4-7: chunkSize (u32)
    // 8-11: lineNumber (u32)
    // 12-15: comment (u32)
    // 16-19: ns (u32) - namespace uri string index (or 0xFFFFFFFF)
    // 20-23: name (u32) - element name string index
    // 24-25: attributeStart (u16) - 0x0014
    // 26-27: attributeSize (u16) - 0x0014
    // 28-31: attributeCount (u16 in low bits, but actually u32)
    // 32-35: idIndex (u16) + classIndex (u16) + styleIndex (u16)
    // 实际 Android 实现：attributeStart (u16) 在 offset 24, attributeSize (u16) 在 26,
    // idIndex (u16) 在 28, classIndex (u16) 在 30, styleIndex (u16) 在 32,
    // attributeCount 在 36 (但实际是：从 offset 28 开始读取 attributes）
    // 真实布局参考 AOSP frameworks/base/include/androidfw/ResourceTypes.h
    // 这里用简化版本：从 offset 28 开始是 attributes
    // 但实际上 attribute count 在 offset 36 (作为 32 位读取，但只用低 16 位)

    // 简化：按常见布局 attributeCount 在 offset 36
    // 真实布局：lineNumber(8) + comment(12) + ns(16) + name(20) + attributeStart(24, u16)
    // + attributeSize(26, u16) + idIndex(28, u16) + classIndex(30, u16) + styleIndex(32, u16)
    // + ?(34, u16) + attributeCount(36, u16 as u32) ... 不对
    // 重新查阅源码:
    // struct ResXMLTree_attrExt {
    //   ResXMLTree_node header;
    //   ResStringPool_ref ns;     // offset 0 (相对此结构)，即 chunk 数据的 offset 16 之后再加 0 = 16
    //   ResStringPool_ref name;   // offset 4，即 20
    //   uint16_t attributeStart;  // offset 8，即 24
    //   uint16_t attributeSize;   // offset 10，即 26
    //   uint16_t idIndex;         // offset 12，即 28
    //   uint16_t classIndex;      // offset 14，即 30
    //   uint16_t styleIndex;      // offset 16，即 32
    //   uint16_t attributeCount;  // offset 18，即 34
    //   ...padding to align...
    // };
    // 所以 attributeStart 在 chunk offset 24 (u16)，attributeCount 在 chunk offset 34 (u16)
    // attributeSize 在 chunk offset 26 (u16)
    let attribute_start = read_u16_le(data, 24)? as usize;
    let _attribute_size = read_u16_le(data, 26)? as usize;
    let attribute_count = read_u16_le(data, 34)? as usize;

    let mut node = AxmlNode::new(tag);

    // 解析属性
    // 每个 attribute 是 20 字节（attributeSize 通常为 0x14 = 20）:
    // ns (u32) + name (u32) + rawValue (u32) + typedValue(size u16 + res0 u8 + dataType u8 + data u32) = 20 bytes
    for i in 0..attribute_count {
        let attr_offset = attribute_start + i * 20;
        if attr_offset + 20 > data.len() {
            break;
        }
        // 跳过 ns（offset 0）
        let attr_name_idx = read_u32_le(data, attr_offset + 4)? as usize;
        let attr_name = string_pool
            .strings
            .get(attr_name_idx)
            .cloned()
            .unwrap_or_default();

        // typed value 在 attr_offset + 12 (size u16, res0 u8, dataType u8, data u32)
        let data_type = data[attr_offset + 15];
        let typed_data = read_u32_le(data, attr_offset + 16)?;

        let value = match data_type {
            0x03 => {
                // TYPE_STRING
                string_pool
                    .strings
                    .get(typed_data as usize)
                    .cloned()
                    .unwrap_or_default()
            }
            0x10 => {
                // TYPE_INT_DEC
                typed_data.to_string()
            }
            0x11 => {
                // TYPE_INT_HEX
                format!("0x{:08X}", typed_data)
            }
            0x12 => {
                // TYPE_INT_BOOLEAN
                (typed_data != 0).to_string()
            }
            0x04 => {
                // TYPE_INT_DEC (newer)
                typed_data.to_string()
            }
            _ => {
                // 其他类型用 raw value
                // raw value 在 attr_offset + 8 (u32)，可能是 string index
                let raw_idx = read_u32_le(data, attr_offset + 8)? as usize;
                string_pool
                    .strings
                    .get(raw_idx)
                    .cloned()
                    .unwrap_or_else(|| typed_data.to_string())
            }
        };

        if !attr_name.is_empty() {
            node.attributes.insert(attr_name, value);
        }
    }

    Ok(node)
}

// === 字节读取辅助函数 ===

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, AxmlError> {
    if offset + 2 > data.len() {
        return Err(AxmlError::Io(format!(
            "读取 u16 越界: offset={}, len={}",
            offset,
            data.len()
        )));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, AxmlError> {
    if offset + 4 > data.len() {
        return Err(AxmlError::Io(format!(
            "读取 u32 越界: offset={}, len={}",
            offset,
            data.len()
        )));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le() {
        let data = [0x01, 0x00, 0x02, 0x00];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 1);
        assert_eq!(read_u16_le(&data, 2).unwrap(), 2);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x80];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 0x12345678);
        assert_eq!(read_u32_le(&data, 4).unwrap(), 0x80000000);
    }

    #[test]
    fn test_read_u32_oob() {
        let data = [0x00, 0x00];
        assert!(read_u32_le(&data, 0).is_err());
    }

    #[test]
    fn test_axml_node_get_attr() {
        let mut node = AxmlNode::new("manifest");
        node.attributes
            .insert("package".to_string(), "com.example.app".to_string());
        assert_eq!(node.get_attr("package"), Some("com.example.app"));
        assert_eq!(node.get_attr("missing"), None);
    }

    #[test]
    fn test_axml_node_find_children() {
        let mut root = AxmlNode::new("root");
        let mut child1 = AxmlNode::new("application");
        child1.attributes.insert("label".into(), "App".into());
        let child2 = AxmlNode::new("uses-permission");
        root.children.push(child1);
        root.children.push(child2);
        assert_eq!(root.find_children("application").len(), 1);
        assert_eq!(root.find_children("uses-permission").len(), 1);
        assert_eq!(root.find_children("missing").len(), 0);
    }

    #[test]
    fn test_parse_axml_too_short() {
        let data = [0x00, 0x00, 0x00];
        let result = parse_axml(&data);
        assert!(matches!(result, Err(AxmlError::TooShort(_))));
    }

    #[test]
    fn test_parse_axml_invalid_magic() {
        let mut data = vec![0u8; 16];
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        let result = parse_axml(&data);
        assert!(matches!(result, Err(AxmlError::InvalidMagic(_))));
    }
}
