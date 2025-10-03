
# 📝 TaskManager - Minikube Deployment

TaskManager is a collaborative web application inspired by Google Tasks. It allows users to register, manage, and share daily tasks in a user-friendly interface. The project is containerized and deployed locally using Minikube, with integrated monitoring tools.

## 🚀 Features

- ✅ User registration and authentication  
- 🗋 Create, edit, delete tasks  
- 👥 Share tasks with other users  
- 📊 Application performance monitoring  
- 🌐 Web-based frontend interface  
- ⚙️ RESTful backend API

## 🧰 Tech Stack

- **Frontend:** Nginx + HTML, CSS, JS  
- **Backend:** Flask, Sqlite with Pvc Mount
- **Containerization:** Docker  
- **Orchestration:** Kubernetes via Minikube  
- **Monitoring:** Victoria Metrics

## 📦 Deployment with Minikube

### Prerequisites

- Docker desktop (running)  
- Minikube  
- kubectl


### Getting Started

1. Run deploy.ps1
2. Add the line: "127.0.0.1 taskmanager.local" (without quotes) to the hosts file located at: C:\Windows\System32\drivers\etc
3. Run the command: minikube tunnel (keep it running in a PowerShell window without closing it)
4. To access the app page: http://taskmanager.local/
To access VictoriaMetrics: http://taskmanager.local/metrics/vmui

