/*
 * SkillGuard YARA Rules - Obfuscation Patterns
 * Detects encoded, packed, or obfuscated payloads
 */

rule Obfuscation_Base64Payload {
    meta:
        description = "Detects base64 encoded payloads being decoded and executed"
        severity = "high"
        category = "obfuscation"
        owasp_llm = "LLM01"
    strings:
        $py1 = "base64.b64decode" nocase
        $py2 = "base64.decodebytes" nocase
        $js1 = "atob(" nocase
        $js2 = "Buffer.from(" nocase
        $bash1 = "base64 -d" nocase
        $bash2 = "base64 --decode" nocase
        $exec1 = "exec(" nocase
        $exec2 = "eval(" nocase
        $exec3 = "subprocess" nocase
    condition:
        (any of ($py*, $js*, $bash*)) and (any of ($exec*))
}

rule Obfuscation_HexEncoded {
    meta:
        description = "Detects hex-encoded strings being decoded"
        severity = "medium"
        category = "obfuscation"
        owasp_llm = "LLM01"
    strings:
        $s1 = "bytes.fromhex" nocase
        $s2 = "\\x" nocase
        $s3 = "hex decode" nocase
        $s4 = "unhexlify" nocase
    condition:
        any of them
}

rule Obfuscation_DynamicExec {
    meta:
        description = "Detects dynamic code execution from constructed strings"
        severity = "high"
        category = "obfuscation"
        owasp_llm = "LLM01"
    strings:
        $s1 = "exec(compile(" nocase
        $s2 = "eval(compile(" nocase
        $s3 = "__import__(" nocase
        $s4 = "getattr(" nocase
        $s5 = "importlib.import_module" nocase
    condition:
        any of them
}

rule Obfuscation_UnicodeEscape {
    meta:
        description = "Detects unicode escape sequences used for obfuscation"
        severity = "medium"
        category = "obfuscation"
        owasp_llm = "LLM01"
    strings:
        $s1 = /\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}/
        $s2 = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
    condition:
        any of them
}
