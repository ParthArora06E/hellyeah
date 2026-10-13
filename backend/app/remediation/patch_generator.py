"""
Automated Remediation & Configuration Patch Generator
Generates concrete, copy-pasteable configuration directives, firewall rules,
Terraform infrastructure-as-code, and unified .diff patches for findings.
"""
from typing import Dict, Any, Optional

def generate_remediation_patch(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    title = (finding_dict.get("title") or "").lower()
    desc = (finding_dict.get("description") or "").lower()
    cve_list = finding_dict.get("cve_ids") or []
    cve_str = ", ".join(cve_list) if cve_list else "General Vulnerability"

    # Default category determination
    if any(k in title for k in ["hsts", "strict-transport-security", "header", "x-frame", "csp", "content-security-policy", "nosniff"]):
        patch_type = "web_server_headers"
        nginx_snippet = """# Auditor Remediation: Deploy Comprehensive Security Headers
# File: /etc/nginx/conf.d/security_headers.conf (or within server {} block)

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;
server_tokens off;
"""
        apache_snippet = """# Auditor Remediation: Apache .htaccess / httpd.conf Headers Directive
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    ServerSignature Off
</IfModule>
"""
        diff_snippet = """--- nginx.conf.orig
+++ nginx.conf
@@ -35,6 +35,13 @@
     server_name example.com;
 
+    # Auditor Security Hardening Patch
+    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
+    add_header X-Content-Type-Options "nosniff" always;
+    add_header X-Frame-Options "DENY" always;
+    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
+    server_tokens off;
+
     location / {
         proxy_pass http://backend;
     }
"""
        guidance = "Reload web server via `sudo nginx -t && sudo systemctl reload nginx` or `sudo systemctl reload apache2`."

    elif any(k in title for k in ["tls", "ssl", "cipher", "weak protocol", "poodle", "heartbleed"]):
        patch_type = "tls_crypto"
        nginx_snippet = """# Auditor Remediation: Enforce Modern TLS 1.2+ & Modern Ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
"""
        apache_snippet = """# Auditor Remediation: Apache SSL Protocol Modernization
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
"""
        diff_snippet = """--- ssl.conf.orig
+++ ssl.conf
@@ -10,3 +10,6 @@
-ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
+ssl_protocols TLSv1.2 TLSv1.3;
+ssl_prefer_server_ciphers on;
"""
        guidance = "Verify SSL posture via `openssl s_client -connect <domain>:443 -tls1_2`."

    elif any(k in title for k in ["database", "mysql", "postgres", "mongodb", "redis", "3306", "5432", "27017", "6379"]):
        patch_type = "database_isolation"
        nginx_snippet = """# Linux Firewall (UFW) Hardening Directive:
sudo ufw deny 3306/tcp comment 'Block public MySQL'
sudo ufw deny 5432/tcp comment 'Block public PostgreSQL'
sudo ufw deny 27017/tcp comment 'Block public MongoDB'
sudo ufw deny 6379/tcp comment 'Block public Redis'
"""
        apache_snippet = """# Database Config: /etc/mysql/mysql.conf.d/mysqld.cnf
[mysqld]
bind-address = 127.0.0.1
# Ensure public network interfaces cannot establish direct socket connections.
"""
        diff_snippet = """--- mysqld.cnf.orig
+++ mysqld.cnf
@@ -42,3 +42,3 @@
-bind-address = 0.0.0.0
+bind-address = 127.0.0.1
"""
        guidance = "Restart database daemon and verify listening socket with `ss -tulpn | grep -E '3306|5432|27017|6379'`."

    elif any(k in title for k in ["bucket", "s3", "storage", "blob"]):
        patch_type = "cloud_storage"
        nginx_snippet = """# Terraform AWS S3 Bucket Public Access Block:
resource "aws_s3_bucket_public_access_block" "remediated_bucket" {
  bucket = aws_s3_bucket.target.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
        apache_snippet = """# AWS CLI Command: Block S3 Public Access Immediately
aws s3api put-public-access-block \
    --bucket <BUCKET_NAME> \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
"""
        diff_snippet = """--- main.tf.orig
+++ main.tf
@@ -14,0 +15,7 @@
+resource "aws_s3_bucket_public_access_block" "block_public" {
+  bucket                  = aws_s3_bucket.assets.id
+  block_public_acls       = true
+  block_public_policy     = true
+  restrict_public_buckets = true
+}
"""
        guidance = "Run `terraform apply` or execute the AWS CLI command to immediately close public bucket access."

    else:
        patch_type = "package_upgrade"
        nginx_snippet = f"""# Auditor Remediation for {cve_str}:
# Operating System Package Upgrade Directive
sudo apt-get update && sudo apt-get --only-upgrade install nginx apache2 openssl
"""
        apache_snippet = f"""# Container / Dockerfile Base Image Hardening:
# Update base image to patched upstream version
FROM debian:bookworm-slim
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
"""
        diff_snippet = f"""--- Dockerfile.orig
+++ Dockerfile
@@ -1,2 +1,3 @@
-FROM nginx:1.18.0
+FROM nginx:1.24.0-alpine
+RUN apk update && apk upgrade
"""
        guidance = f"Upgrade the vulnerable package to resolve {cve_str}. Retest once updated service is running."

    return {
        "finding_id": finding_dict.get("id"),
        "title": finding_dict.get("title"),
        "patch_type": patch_type,
        "nginx_config": nginx_snippet.strip(),
        "apache_or_cli_config": apache_snippet.strip(),
        "diff_patch": diff_snippet.strip(),
        "implementation_guidance": guidance,
        "estimated_hours": finding_dict.get("fix_hours_dev") or 3.0
    }
