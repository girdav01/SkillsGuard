/*
 * SkillGuard YARA Rules - Credential Theft Patterns
 * Detects credential harvesting and exfiltration patterns
 */

rule CredentialTheft_APIKeyHarvest {
    meta:
        description = "Detects API key harvesting instructions"
        severity = "critical"
        category = "credential_theft"
        owasp_llm = "LLM06"
    strings:
        $s1 = "read the api key" nocase
        $s2 = "extract the token" nocase
        $s3 = "steal credentials" nocase
        $s4 = "harvest api keys" nocase
        $s5 = "dump all secrets" nocase
        $s6 = "collect passwords" nocase
    condition:
        any of them
}

rule CredentialTheft_EnvFileAccess {
    meta:
        description = "Detects .env file access patterns"
        severity = "high"
        category = "credential_theft"
        owasp_llm = "LLM06"
    strings:
        $s1 = "cat .env" nocase
        $s2 = "read .env" nocase
        $s3 = "type .env" nocase
        $s4 = "source .env" nocase
        $s5 = ".env file" nocase
        $s6 = "dotenv" nocase
    condition:
        2 of them
}

rule CredentialTheft_AWSCreds {
    meta:
        description = "Detects AWS credential theft patterns"
        severity = "critical"
        category = "credential_theft"
        owasp_llm = "LLM06"
    strings:
        $s1 = ".aws/credentials" nocase
        $s2 = "AWS_SECRET_ACCESS_KEY" nocase
        $s3 = "AWS_ACCESS_KEY_ID" nocase
        $s4 = /AKIA[0-9A-Z]{16}/
    condition:
        any of them
}

rule CredentialTheft_SSHKeys {
    meta:
        description = "Detects SSH key access patterns"
        severity = "critical"
        category = "credential_theft"
        owasp_llm = "LLM06"
    strings:
        $s1 = ".ssh/id_rsa" nocase
        $s2 = ".ssh/id_ed25519" nocase
        $s3 = "-----BEGIN RSA PRIVATE KEY-----"
        $s4 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $s5 = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}
