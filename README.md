# IaC DriftWatch

IaC DriftWatch is a centralized Infrastructure-as-Code drift
detection and monitoring platform.

The platform is currently presented in single account drift detection and management account, but is capable of handling few more AWS accounts . The scalability and the overall quality of the project has a further requirement of improvement along with addition of new features related to Posture management of Cloud resources. This project was built in very limited time hence, despite of lacking scaled working outputs and analysis, tries to provide opportunity to learn and understand how drift detection looks and actually works in background behind the scene. 
The project deals with a niche concept of Drift detection and is intended to learn and understand the technology and experiment the understanding related to cloud security domain.
The focus of this project is to try and implement Drift detection security principles across a live working sandbox account and experiment an automated stateful, transition-gated notification of drift detection along with an attempt of achieving efficiency and accuracy.
The tool mainly focus on being an environment independent platform which works on a Terraform baseline (json) provided as baseline input for comparison of deployed instances. 

## Signin credentials:-
Username: creator 

Password: password

## Current Technology Stack

- Python
- FastAPI
- PostgreSQL
- Terraform
- Docker

## Current Status

The project is up in running on :- https://iac-drift-watch.onrender.com

NOTE:- Render Blocks SMTP services across all services , Hence the SMTP Email trigger won't work for the online (Render) Deployment .
