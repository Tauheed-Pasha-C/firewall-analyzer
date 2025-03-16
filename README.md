# Firewall Policy Analyzer And Optimizer

A comprehensive tool for analyzing and optimizing firewall rulesets, detecting anomalies like shadowed, redundant, and correlated rules. Features both CLI and web interface with AI-driven optimization capabilities.

## Key Features

- 🕵️ **Anomaly Detection**: Identifies 5 types of rule conflicts:
  - Shadowing (SHD)
  - Redundancy (RXD/RYD)
  - Correlation (COR)
  - Generalization (GEN)
- 🤖 **AI-Driven Optimization**: Expert system with rule-based optimization
- 📊 **Interactive Web UI**: Streamlit-based interface with real-time analysis
- 🔌 **REST API**: Flask-based service for programmatic access
- 📦 **Rule Management**: Supports CSV/JSON input and manual rule entry

## Project Structure
| File | Purpose |
|------|---------|
| `final.py` | Main web interface |
| `firewall_logic.py` | Core analysis logic |
| `api_services.py` | REST API endpoints |
| `expert_system.py` | AI optimization engine |
|`parsing.py`| Rule parsing utilities |
|`policyanalyzer.py`| Policy analysis library |

## Optimization Modes
- **Predefined Logic**: Rule reordering and removal
- **AI-Driven**: Expert system with merge capabilities


## API Documentation
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/submit-rules` | Upload firwall rules (CSV/JSON) |
| POST | `/analyze/{job_id}` | Start analysis job |
| GET | `/results/{job_id}` | Get analysis results |

