/*
 * SkillGuard YARA Rules - Data Exfiltration Patterns
 * Detects data exfiltration and C2 communication patterns
 */

rule Exfiltration_ReverseShell {
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
        category = "code_execution"
        owasp_llm = "LLM06"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" nocase
        $bash2 = "/bin/sh -i" nocase
        $py1 = "socket.socket" nocase
        $py2 = "subprocess.call([\"/bin/sh\""
        $py3 = "os.dup2" nocase
        $nc1 = "nc -e /bin/sh" nocase
        $nc2 = "ncat -e" nocase
        $perl1 = "perl -e" nocase
    condition:
        any of ($bash*) or (($py1) and ($py2 or $py3)) or any of ($nc*) or ($perl1)
}

rule Exfiltration_CurlExfil {
    meta:
        description = "Detects curl-based data exfiltration"
        severity = "high"
        category = "data_exfiltration"
        owasp_llm = "LLM06"
    strings:
        $s1 = "curl -X POST" nocase
        $s2 = "curl --data" nocase
        $s3 = "wget --post-data" nocase
        $s4 = /curl\s+.*-d\s+@/
    condition:
        any of them
}

rule Exfiltration_DNSTunnel {
    meta:
        description = "Detects DNS tunneling patterns"
        severity = "high"
        category = "data_exfiltration"
        owasp_llm = "LLM06"
    strings:
        $s1 = "nslookup" nocase
        $s2 = "dig " nocase
        $s3 = "host " nocase
        $s4 = ".burpcollaborator.net" nocase
        $s5 = ".oastify.com" nocase
        $s6 = ".interact.sh" nocase
    condition:
        any of them
}

rule Exfiltration_WebhookPost {
    meta:
        description = "Detects data posting to webhooks and external services"
        severity = "high"
        category = "data_exfiltration"
        owasp_llm = "LLM06"
    strings:
        $s1 = "hooks.slack.com" nocase
        $s2 = "discord.com/api/webhooks" nocase
        $s3 = "webhook.site" nocase
        $s4 = "requestbin.com" nocase
        $s5 = "pipedream.net" nocase
        $s6 = "ngrok.io" nocase
    condition:
        any of them
}
