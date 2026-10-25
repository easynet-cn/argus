//! DEX (Dalvik Executable) 文件解析器
//!
//! 解析 DEX 文件头、字符串池、类定义等基础信息，用于:
//! - 统计类/方法数量
//! - 提取 API 调用特征
//! - 检测可疑类（如反射、动态加载等）

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DexError {
    #[error("DEX 文件过短: {0} bytes")]
    TooShort(usize),
    #[error("无效的 DEX 魔数: {0:?}")]
    InvalidMagic([u8; 8]),
    #[error("DEX 版本不支持: {0:?}")]
    UnsupportedVersion([u8; 3]),
    #[error("解析失败: {0}")]
    Parse(String),
}

/// DEX 文件头
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

/// DEX 解析结果
#[derive(Debug, Clone)]
pub struct DexInfo {
    pub header: DexHeader,
    /// 类数量
    pub class_count: u32,
    /// 方法数量
    pub method_count: u32,
    /// 字段数量
    pub field_count: u32,
    /// 字符串数量
    pub string_count: u32,
    /// 类型数量
    pub type_count: u32,
    /// 原型数量
    pub proto_count: u32,
    /// 文件大小
    pub file_size: u64,
}

/// 解析 DEX 文件
pub fn parse_dex(data: &[u8]) -> Result<DexInfo, DexError> {
    if data.len() < 112 {
        return Err(DexError::TooShort(data.len()));
    }

    // 魔数检查："dex\n" + 版本（3 字节）+ "\0"
    let magic = [
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ];
    if &magic[0..4] != b"dex\n" {
        return Err(DexError::InvalidMagic(magic));
    }

    let version = [data[4], data[5], data[6]];
    // 支持版本 035/036/037/038/039/040
    match version {
        [b'0', b'3', b'5'] | [b'0', b'3', b'6'] | [b'0', b'3', b'7']
        | [b'0', b'3', b'8'] | [b'0', b'3', b'9'] | [b'0', b'4', b'0'] => {}
        _ => return Err(DexError::UnsupportedVersion(version)),
    }

    let header = parse_header(data)?;
    let file_size = header.file_size as u64;
    let class_count = header.class_defs_size;
    let method_count = header.method_ids_size;
    let field_count = header.field_ids_size;
    let string_count = header.string_ids_size;
    let type_count = header.type_ids_size;
    let proto_count = header.proto_ids_size;

    Ok(DexInfo {
        header,
        class_count,
        method_count,
        field_count,
        string_count,
        type_count,
        proto_count,
        file_size,
    })
}

/// 解析 DEX 文件头
fn parse_header(data: &[u8]) -> Result<DexHeader, DexError> {
    let read_u32 = |offset: usize| -> Result<u32, DexError> {
        if offset + 4 > data.len() {
            return Err(DexError::Parse(format!("读取 u32 越界: offset={}", offset)));
        }
        Ok(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    };

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&data[0..8]);
    let checksum = read_u32(8)?;

    let mut signature = [0u8; 20];
    signature.copy_from_slice(&data[12..32]);

    let file_size = read_u32(32)?;
    let header_size = read_u32(36)?;
    let endian_tag = read_u32(40)?;
    let link_size = read_u32(44)?;
    let link_off = read_u32(48)?;
    let map_off = read_u32(52)?;
    let string_ids_size = read_u32(56)?;
    let string_ids_off = read_u32(60)?;
    let type_ids_size = read_u32(64)?;
    let type_ids_off = read_u32(68)?;
    let proto_ids_size = read_u32(72)?;
    let proto_ids_off = read_u32(76)?;
    let field_ids_size = read_u32(80)?;
    let field_ids_off = read_u32(84)?;
    let method_ids_size = read_u32(88)?;
    let method_ids_off = read_u32(92)?;
    let class_defs_size = read_u32(96)?;
    let class_defs_off = read_u32(100)?;
    let data_size = read_u32(104)?;
    let data_off = read_u32(108)?;

    Ok(DexHeader {
        magic,
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dex_too_short() {
        let data = [0u8; 100];
        let result = parse_dex(&data);
        assert!(matches!(result, Err(DexError::TooShort(_))));
    }

    #[test]
    fn test_parse_dex_invalid_magic() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"XXXX");
        let result = parse_dex(&data);
        assert!(matches!(result, Err(DexError::InvalidMagic(_))));
    }

    #[test]
    fn test_parse_dex_unsupported_version() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"099");
        let result = parse_dex(&data);
        assert!(matches!(result, Err(DexError::UnsupportedVersion(_))));
    }

    #[test]
    fn test_parse_dex_valid_header() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data[7] = 0;
        // 填充典型值
        let mut write_u32 = |offset: usize, val: u32| {
            let bytes = val.to_le_bytes();
            data[offset..offset + 4].copy_from_slice(&bytes);
        };
        write_u32(32, 120);  // file_size
        write_u32(36, 112);  // header_size
        write_u32(40, 0x12345678);  // endian_tag
        write_u32(88, 100);  // method_ids_size
        write_u32(92, 0);  // method_ids_off
        write_u32(96, 50);  // class_defs_size
        write_u32(100, 0);  // class_defs_off
        write_u32(80, 200);  // field_ids_size
        write_u32(56, 1000); // string_ids_size
        write_u32(64, 300); // type_ids_size
        write_u32(72, 50);  // proto_ids_size

        let result = parse_dex(&data);
        assert!(result.is_ok(), "解析应该成功");
        let info = result.unwrap();
        assert_eq!(info.class_count, 50);
        assert_eq!(info.method_count, 100);
        assert_eq!(info.field_count, 200);
        assert_eq!(info.string_count, 1000);
        assert_eq!(info.type_count, 300);
        assert_eq!(info.proto_count, 50);
        assert_eq!(info.file_size, 120);
    }
}
