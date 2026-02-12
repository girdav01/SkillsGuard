/*
 * SkillGuard YARA Rules - Prompt Injection Patterns
 * Detects prompt injection attempts in AI Agent Skills
 */

rule PromptInjection_InstructionOverride {
    meta:
        description = "Detects instruction override patterns"
        severity = "critical"
        category = "prompt_injection"
        owasp_llm = "LLM01"
    strings:
        $s1 = "ignore previous instructions" nocase
        $s2 = "ignore all previous" nocase
        $s3 = "disregard your guidelines" nocase
        $s4 = "disregard all rules" nocase
        $s5 = "override system prompt" nocase
        $s6 = "new instructions:" nocase
        $s7 = "forget everything" nocase
    condition:
        any of them
}

rule PromptInjection_RoleHijacking {
    meta:
        description = "Detects role hijacking attempts"
        severity = "high"
        category = "prompt_injection"
        owasp_llm = "LLM01"
    strings:
        $s1 = "you are now a" nocase
        $s2 = "act as if you" nocase
        $s3 = "pretend to be" nocase
        $s4 = "switch to DAN mode" nocase
        $s5 = "Do Anything Now" nocase
        $s6 = "jailbreak mode" nocase
    condition:
        any of them
}

rule PromptInjection_SystemPromptExtraction {
    meta:
        description = "Detects system prompt extraction attempts"
        severity = "high"
        category = "prompt_injection"
        owasp_llm = "LLM01"
    strings:
        $s1 = "reveal your system prompt" nocase
        $s2 = "show me your instructions" nocase
        $s3 = "print your initial prompt" nocase
        $s4 = "what are your rules" nocase
        $s5 = "output your system message" nocase
        $s6 = "repeat the above" nocase
    condition:
        any of them
}

rule PromptInjection_JailbreakDelimiters {
    meta:
        description = "Detects jailbreak delimiter injection"
        severity = "critical"
        category = "prompt_injection"
        owasp_llm = "LLM01"
    strings:
        $s1 = "<|im_start|>" nocase
        $s2 = "<|im_end|>" nocase
        $s3 = "[SYSTEM]" nocase
        $s4 = "```system" nocase
        $s5 = "</s>" nocase
        $s6 = "<|endoftext|>" nocase
    condition:
        any of them
}
