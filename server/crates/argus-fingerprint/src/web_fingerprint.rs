//! Web 应用框架检测

use crate::types::*;
use crate::signature_db::WebAppSignatureDb;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// 检测 Web 应用框架
pub async fn detect_web_apps(
    host: &str,
    port: u16,
    timeout_ms: u64,
    web_db: &WebAppSignatureDb,
) -> Vec<WebAppFingerprint> {
    let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}/");

    let response = fetch_http_response(&url, timeout_ms).await;
    let mut results = vec![];

    if let Some(resp) = response {
        // 用签名库匹配
        for sig in &web_db.signatures {
            let mut indicators_matched = vec![];
            let mut all_matched = true;

            for indicator in &sig.indicators {
                let matched = match indicator.kind.as_str() {
                    "header" => {
                        resp.headers.iter().any(|(k, v)| {
                            k.to_lowercase().contains(&indicator.pattern.to_lowercase()) ||
                            v.to_lowercase().contains(&indicator.pattern.to_lowercase())
                        })
                    }
                    "body" => {
                        let lower_body = resp.body.to_lowercase();
                        lower_body.contains(&indicator.pattern.to_lowercase())
                    }
                    _ => false,
                };
                if matched {
                    indicators_matched.push(format!("{}:{}", indicator.kind, indicator.pattern));
                } else {
                    all_matched = false;
                    break;
                }
            }

            if all_matched && !indicators_matched.is_empty() {
                // 提取版本
                let version = sig.version_indicator.as_ref()
                    .and_then(|pattern| {
                        let lower_body = resp.body.to_lowercase();
                        if let Some(pos) = lower_body.find(&pattern.to_lowercase()) {
                            let after = &resp.body[pos + pattern.len()..];
                            let ver: String = after.chars()
                                .take_while(|c| c.is_ascii_digit() || *c == '.')
                                .collect();
                            if !ver.is_empty() { Some(ver) } else { None }
                        } else {
                            None
                        }
                    });

                results.push(WebAppFingerprint {
                    host: host.to_string(),
                    port,
                    app: sig.app.clone(),
                    version,
                    categories: sig.categories.clone(),
                    confidence: 0.8,
                    indicators: indicators_matched,
                });
            }
        }

        // 内置 fallback 检测
        if results.is_empty() {
            results = builtin_web_detect(host, port, &resp);
        }
    }

    results
}

/// 内置 Web 应用检测（fallback）
fn builtin_web_detect(host: &str, port: u16, resp: &HttpResponse) -> Vec<WebAppFingerprint> {
    let mut results = vec![];
    let lower_body = resp.body.to_lowercase();

    // WordPress
    if lower_body.contains("wp-content") || lower_body.contains("wp-includes") {
        let version = extract_meta_generator(&resp.body, "wordpress");
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "WordPress".to_string(),
            version, categories: vec!["CMS".to_string()],
            confidence: 0.9, indicators: vec!["body:wp-content".to_string()],
        });
    }

    // Django
    if lower_body.contains("csrfmiddlewaretoken") || lower_body.contains("csrftoken") {
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Django".to_string(),
            version: None, categories: vec!["Framework".to_string()],
            confidence: 0.8, indicators: vec!["body:csrftoken".to_string()],
        });
    }

    // Spring Boot
    if resp.headers.iter().any(|(k, _)| k.to_lowercase() == "x-application-context") ||
       lower_body.contains("whitelabel error page") {
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Spring Boot".to_string(),
            version: None, categories: vec!["Framework".to_string()],
            confidence: 0.85, indicators: vec!["header:x-application-context".to_string()],
        });
    }

    // Joomla
    if lower_body.contains("joomla") || lower_body.contains("generator") && lower_body.contains("joomla") {
        let version = extract_meta_generator(&resp.body, "joomla");
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Joomla".to_string(),
            version, categories: vec!["CMS".to_string()],
            confidence: 0.85, indicators: vec!["body:joomla".to_string()],
        });
    }

    // Drupal
    if lower_body.contains("drupal") {
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Drupal".to_string(),
            version: None, categories: vec!["CMS".to_string()],
            confidence: 0.8, indicators: vec!["body:drupal".to_string()],
        });
    }

    // Tomcat
    if lower_body.contains("apache tomcat") {
        let version = extract_version_from_text(&resp.body, "Apache Tomcat/");
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Apache Tomcat".to_string(),
            version, categories: vec!["Application Server".to_string()],
            confidence: 0.9, indicators: vec!["body:apache tomcat".to_string()],
        });
    }

    // Jenkins
    if lower_body.contains("jenkins") || resp.headers.iter().any(|(k, _)| k.to_lowercase() == "x-jenkins") {
        results.push(WebAppFingerprint {
            host: host.to_string(), port,
            app: "Jenkins".to_string(),
            version: None, categories: vec!["CI/CD".to_string()],
            confidence: 0.85, indicators: vec!["body:jenkins".to_string()],
        });
    }

    results
}

/// 从 meta generator 标签提取版本
fn extract_meta_generator(body: &str, app_name: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if let Some(pos) = lower.find(&format!("generator")) {
        let nearby = &body[pos..pos.saturating_add(200).min(body.len())];
        if let Some(vpos) = nearby.to_lowercase().find(app_name) {
            let after = &nearby[vpos + app_name.len()..];
            let ver: String = after.chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !ver.is_empty() { return Some(ver); }
        }
    }
    None
}

/// 从文本中提取版本号
fn extract_version_from_text(text: &str, prefix: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let prefix_lower = prefix.to_lowercase();
    if let Some(pos) = lower.find(&prefix_lower) {
        let after = &text[pos + prefix_lower.len()..];
        let ver: String = after.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !ver.is_empty() { return Some(ver); }
    }
    None
}

/// 获取 HTTP 响应
async fn fetch_http_response(url: &str, timeout_ms: u64) -> Option<HttpResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(true)
        .build().ok()?;

    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.ok()?;

    Some(HttpResponse { status, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordpress_detection() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: r#"<html><head><script src="/wp-content/themes/test/script.js"></script></head></html>"#.to_string(),
        };
        let results = builtin_web_detect("192.168.1.1", 80, &resp);
        assert!(results.iter().any(|r| r.app == "WordPress"));
    }

    #[test]
    fn test_django_detection() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: r#"<form><input type="hidden" name="csrfmiddlewaretoken" value="abc123"></form>"#.to_string(),
        };
        let results = builtin_web_detect("192.168.1.1", 80, &resp);
        assert!(results.iter().any(|r| r.app == "Django"));
    }

    #[test]
    fn test_spring_boot_detection() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("x-application-context".to_string(), "application:dev".to_string())],
            body: "OK".to_string(),
        };
        let results = builtin_web_detect("192.168.1.1", 80, &resp);
        assert!(results.iter().any(|r| r.app == "Spring Boot"));
    }

    #[test]
    fn test_tomcat_detection() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Apache Tomcat/9.0.41 - Error report".to_string(),
        };
        let results = builtin_web_detect("192.168.1.1", 80, &resp);
        assert!(results.iter().any(|r| r.app == "Apache Tomcat" && r.version == Some("9.0.41".to_string())));
    }

    #[test]
    fn test_jenkins_detection() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Jenkins Dashboard".to_string(),
        };
        let results = builtin_web_detect("192.168.1.1", 80, &resp);
        assert!(results.iter().any(|r| r.app == "Jenkins"));
    }
}
