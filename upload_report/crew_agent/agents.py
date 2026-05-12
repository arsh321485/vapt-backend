"""
Nessus Crew Agent — Agent Definitions
Four specialized agents collaborate to produce the mitigation plan.
"""

from crewai import Agent
from .tools import (
    VulnerabilityLookupTool,
    OSProfilerTool,
    CommandBuilderTool,
    MitigationKnowledgeTool,
    RiskRaterTool,
)


def build_agents(llm) -> dict:
    """Instantiate all crew agents bound to the provided LLM."""

    vulnerability_analyst = Agent(
        role="Vulnerability Analyst",
        goal=(
            "Analyse the Nessus vulnerability finding, extract all key fields "
            "(IP, OS, port, plugin output, CVE references), determine severity, "
            "CVSS score estimate, and produce a structured vulnerability profile."
        ),
        backstory=(
            "You are a senior penetration tester and vulnerability analyst with 12 years "
            "of experience reading Nessus reports. You can extract meaningful intelligence "
            "from raw plugin output and map findings to known vulnerability categories. "
            "You are methodical, precise, and never guess — if data is missing you say so clearly."
        ),
        tools=[VulnerabilityLookupTool(), RiskRaterTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=3,
    )

    os_profiler = Agent(
        role="OS and Service Profiler",
        goal=(
            "Identify the target operating system, web server stack, service type, "
            "and configuration file locations relevant to the vulnerability. "
            "Determine exact config file paths, package manager, and service manager used."
        ),
        backstory=(
            "You are a Linux and Windows systems engineer who knows every configuration "
            "file path, service manager command, and package manager for every major OS. "
            "You can reliably determine config locations from OS name alone and adapt "
            "all remediation steps to the exact environment."
        ),
        tools=[OSProfilerTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=2,
    )

    remediation_engineer = Agent(
        role="Remediation Engineer",
        goal=(
            "Using the vulnerability profile and OS profile, produce a complete "
            "step-by-step mitigation plan. Each step must include: what to LOCATE, "
            "what to REMOVE with a real ❌ before-example, what to REPLACE WITH "
            "including a real ✅ after-example, the exact file path, the exact "
            "runnable command, tools used, and important considerations."
        ),
        backstory=(
            "You are a senior security engineer who has remediated thousands of "
            "Nessus findings across financial institutions and government networks. "
            "Your mitigation plans are famous for being precise — every step includes "
            "a real example so a junior engineer can follow without ambiguity. "
            "You never produce vague instructions like 'update the config' — "
            "you always show the EXACT before and after."
        ),
        tools=[MitigationKnowledgeTool(), CommandBuilderTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=3,
    )

    card_formatter = Agent(
        role="Mitigation Card Formatter",
        goal=(
            "Take the remediation plan and format it into a structured markdown table "
            "followed by a JSON vulnerability card and a contextual analysis section. "
            "Follow the EXACT output format specified in the task — no box-drawing characters, "
            "no deviation from the required column names or JSON fields."
        ),
        backstory=(
            "You are a technical writer and security documentation specialist. "
            "You transform complex remediation instructions into machine-readable structured output "
            "that can be parsed and stored in a database. "
            "You are meticulous about following the exact output format — every column, "
            "every JSON field, every section heading must match the specification precisely."
        ),
        tools=[],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=2,
    )

    return {
        "vulnerability_analyst": vulnerability_analyst,
        "os_profiler": os_profiler,
        "remediation_engineer": remediation_engineer,
        "card_formatter": card_formatter,
    }
