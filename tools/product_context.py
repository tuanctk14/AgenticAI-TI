"""
tools/product_context.py - Product-Aware Context for ATT&CK Inference

Different products have different attack vectors:
- Network device (Cisco IOS) → T1059.008 (Network Device CLI)
- Web application (WordPress) → T1059.004 (Bash)
- Windows server → T1059.001 (PowerShell)
"""

# Product category context - affects ATT&CK inference
PRODUCT_CONTEXT = {
    # Network Devices (T1059.008 primary)
    "cisco:ios": "network_device",
    "cisco:ios_xe": "network_device",
    "cisco:ios-xe": "network_device",
    "cisco_ios": "network_device",
    "cisco_ios_xe": "network_device",
    "cisco_asa": "network_device",
    "fortinet_fortios": "network_device",
    "paloaltonetworks_pan_os": "network_device",
    "juniper_junos": "network_device",

    # Web Applications & Servers (T1059.004 primary)
    "wordpress_wordpress": "web_application",
    "wordpress_plugin": "web_application",
    "apache_http_server": "web_server",
    "apache_tomcat": "web_server",
    "nginx": "web_server",
    "microsoft_exchange_server": "web_application",
    "iis": "web_server",

    # Web Applications & Servers
    "wordpress:wordpress": "web_application",
    "wordpress:plugin": "web_application",
    "apache:http_server": "web_server",
    "apache:tomcat": "web_server",
    "apache_http_server": "web_server",
    "nginx": "web_server",
    "microsoft:exchange_server": "web_application",
    "iis": "web_server",

    # Databases (T1059.008 or vendor-specific)
    "mysql:mysql": "database",
    "mysql_mysql": "database",
    "postgresql": "database",
    "mongodb": "database",
    "oracle:database": "database",

    # Programming Frameworks (T1059.004 or language-specific)
    "pivotal:spring_framework": "framework",
    "pivotal_spring_framework": "framework",
    "django": "framework",
    "rails": "framework",
    "laravel": "framework",

    # Operating Systems (T1059.001, T1059.004 depending on OS)
    "microsoft:windows": "operating_system_windows",
    "microsoft_windows": "operating_system_windows",
    "linux": "operating_system_linux",
    "apple:macos": "operating_system_macos",

    # Desktop/Office (T1059.001 primary)
    "microsoft:office": "office_suite",
    "adobe:acrobat": "desktop_application",
    "google:chrome": "browser",

    # Development Tools (T1059.004, T1559)
    "jenkins:jenkins": "ci_cd",
    "atlassian:confluence": "collaboration_tool",
    "atlassian:jira": "collaboration_tool",
    "github": "scm",
    "gitlab": "scm",

    # SSL/Crypto (No direct T1059, but data protection)
    "openssl:openssl": "crypto_library",
    "curl": "http_client",
}

# Context-aware ATT&CK technique remapping
CONTEXT_ATTACK_REMAPPING = {
    "network_device": {
        "T1059": "T1059.008",  # Network Device CLI instead of generic
    },
    "web_server": {
        "T1059": "T1059.004",  # Bash/Shell instead of generic
    },
    "web_application": {
        "T1059": "T1059.004",  # Bash/Shell for web apps
    },
    "database": {
        "T1059": "T1059.008",  # Database-specific (TSQL, etc.)
    },
    "operating_system_windows": {
        "T1059": "T1059.001",  # PowerShell instead of generic
    },
    "operating_system_linux": {
        "T1059": "T1059.004",  # Bash instead of generic
    },
    "framework": {
        "T1059": "T1059.004",  # Language interpreter
    },
}

# Context-specific remediation actions
CONTEXT_REMEDIATION_ACTIONS = {
    "network_device": [
        "- Apply firmware updates for network devices",
        "- Review and update access control lists (ACLs)",
        "- Disable unnecessary network services",
        "- Monitor CLI access and enable logging",
    ],
    "web_server": [
        "- Apply patches to web server software",
        "- Review web server configuration",
        "- Disable unnecessary modules and services",
        "- Implement web application firewall (WAF) rules",
    ],
    "web_application": [
        "- Update application code to patch vulnerabilities",
        "- Review input validation and output encoding",
        "- Implement security headers (CSP, X-Frame-Options, etc.)",
        "- Apply principle of least privilege to application permissions",
    ],
    "database": [
        "- Apply database patches and security updates",
        "- Review and restrict database user permissions",
        "- Implement database query logging and monitoring",
        "- Use parameterized queries to prevent injection",
    ],
    "operating_system_windows": [
        "- Apply Windows security patches (Windows Update)",
        "- Review Windows Defender settings",
        "- Check Windows firewall rules",
        "- Review Windows event logs for suspicious activity",
    ],
    "operating_system_linux": [
        "- Apply system updates and security patches",
        "- Review file permissions and user accounts",
        "- Check system logs (syslog) for suspicious activity",
        "- Enable and review audit logging (auditd)",
    ],
    "ci_cd": [
        "- Apply Jenkins/CI-CD tool updates",
        "- Review pipeline security and access controls",
        "- Implement artifact scanning in CI/CD pipeline",
        "- Review CI/CD secrets management",
    ],
}


def get_product_category(normalized_software_id: str) -> str:
    """
    Get product category (context) from normalized software ID.

    Example: "cisco:ios" → "network_device"
    """
    return PRODUCT_CONTEXT.get(normalized_software_id, "unknown")


def remap_technique_for_context(technique_id: str, product_context: str) -> str:
    """
    Remap generic ATT&CK technique to context-specific variant.

    Example:
    - T1059 (generic) + network_device → T1059.008
    - T1059 (generic) + web_server → T1059.004
    """
    if product_context not in CONTEXT_ATTACK_REMAPPING:
        return technique_id

    remapping = CONTEXT_ATTACK_REMAPPING[product_context]
    return remapping.get(technique_id, technique_id)


def get_context_remediation_actions(product_context: str) -> list:
    """Get context-specific remediation actions."""
    return CONTEXT_REMEDIATION_ACTIONS.get(product_context, [])


def get_all_product_contexts() -> dict:
    """Get all product context mappings."""
    return PRODUCT_CONTEXT
