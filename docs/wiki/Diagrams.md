# Diagrams

## User Perspective

```mermaid
flowchart LR
    USER[Platform + Product Teams] --> CHANNELS[CLI • Streamlit • REST API • MCP]
    CHANNELS --> GUARDRAIL[Terraform Guardrail MCP (TerraGuard)]
    GUARDRAIL --> REPORTS[Readable Guidance + Evidence]
    GUARDRAIL --> TERRAFORM[Safer Terraform Applies]
```

## Ways Developers Use Guardrail

```mermaid
flowchart LR
    DEV[Developer] --> CLI[CLI]
    DEV --> UI[Streamlit UI]
    DEV --> API[REST API]
    DEV --> MCP[MCP for AI Assistants]
    DEV --> CI[GitHub Action]
    DEV --> ADO[Azure DevOps]
    CLI --> GUARDRAIL
    UI --> GUARDRAIL
    API --> GUARDRAIL
    MCP --> GUARDRAIL
    CI --> GUARDRAIL
    ADO --> GUARDRAIL
```

## Docker Compose Stack (Local Dev)

```mermaid
flowchart LR
    subgraph ComposeStack[Docker Compose Stack]
        UI([Streamlit UI])
        API([REST API])
        REG[(Policy Registry)]
        REGAPI([Registry API])
        PROM[[Prometheus]]
        GRAF[[Grafana]]
    end
    UI --> API
    API -.-> REG
    REGAPI -.-> REG
    API --> PROM
    PROM --> GRAF

    classDef core fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#1b5e20;
    classDef optional fill:#fff3e0,stroke:#ef6c00,stroke-width:1px,color:#e65100;
    class UI,API,REG,REGAPI core;
    class PROM,GRAF optional;
```

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Interfaces
        CLI([CLI])
        MCP([MCP Server])
        WEB([Web UI])
        API([REST API])
        STL([Streamlit App])
    end

    subgraph Core
        SCAN((Compliance Engine))
        GEN[[Snippet Generator]]
        POLICY{Policy Layering}
    end

    subgraph Integrations
        TF[/Terraform CLI/]
        REG[(Terraform Registry)]
    end

    CLI --> SCAN
    WEB --> SCAN
    API --> SCAN
    STL --> SCAN
    MCP --> SCAN
    MCP --> GEN
    SCAN --> POLICY --> TF
    GEN --> REG

    classDef interface fill:#e3f2fd,stroke:#1e88e5,stroke-width:1px,color:#0d47a1;
    classDef core fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#1b5e20;
    classDef integration fill:#fff3e0,stroke:#ef6c00,stroke-width:1px,color:#e65100;

    class CLI,MCP,WEB,API,STL interface;
    class SCAN,GEN,POLICY core;
    class TF,REG integration;
```

## Detailed Flow

```mermaid
flowchart TB
    INPUTS[Inputs: .tf, .tfvars, .tfstate] --> PARSE[Parse & Normalize]
    PARSE --> SCHEMA[Provider Schema + Metadata]
    SCHEMA --> RULES[Apply Guardrail Rules]
    RULES --> REPORT[Findings + Summary]
    REPORT --> OUTPUTS[CLI JSON • UI • MCP • REST]
```
