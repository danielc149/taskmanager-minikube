minikube start --driver=docker
minikube docker-env | Invoke-Expression 
minikube addons enable ingress

# Build Docker images
docker build -t backend:v2 ./backend
docker build -t frontend:latest ./frontend

# Apply Kubernetes manifests
kubectl apply -f ./k8s/backend-deployment.yaml
kubectl apply -f ./k8s/backend-service.yaml
kubectl apply -f ./k8s/frontend-deployment.yaml
kubectl apply -f ./k8s/frontend-service.yaml
kubectl apply -f ./k8s/ingress.yaml
kubectl apply -f ./k8s/victoria-metrics.yaml
kubectl apply -f ./k8s/vmagent-config.yaml

# Get service URLs
kubectl get services
