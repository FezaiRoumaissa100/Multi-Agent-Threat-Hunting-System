# Multi-Agent Threat Hunting System

A context-aware multi-agent system for automated threat hunting in SOC environments, 
built with Wazuh SIEM, OpenSearch MCP, LangGraph and a local LLM via Ollama.

## Problem

Security analysts face **alert fatigue** — alerts are processed in isolation without 
historical context. Multi-step attacks go undetected because each step appears 
harmless alone.

## Our Contribution

We introduce **automatic Context Gathering** : before investigating an alert, the 
system automatically searches for related historical alerts to build a rich context 
and detect multi-step attack patterns.

## Tech Stack

- Wazuh SIEM
- OpenSearch + MCP
- LangGraph
- Ollama (Qwen2.5:7B)
- Python