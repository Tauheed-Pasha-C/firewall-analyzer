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
File	                        |           Description
--------------------------------------------------------------------------------------
final.py	                    |          Main Streamlit web interface
firewall_logic.py	            |          Core anomaly detection and optimization logic
api_services.py	              |          Flask REST API endpoints
analyze.py	                  |          Command line analysis tool
expert_system.py	            |          AI-driven optimization engine
parsing.py	                  |          Rule parsing utilities
policyanalyzer.py	            |          Policy analysis library

## API Documentation

Endpoints
----------
POST /submit-rules: Submit firewall rules (CSV/JSON)

POST /analyze/<job_id>: Start analysis job

GET /results/<job_id>: Retrieve analysis results
