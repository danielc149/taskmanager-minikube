FROM python:3.9

WORKDIR /app

# Copiar el código de la aplicación
COPY app.py .

# Copiar datos existentes si los hay
COPY data/ ./data/

# Instalar dependencias (agregamos prometheus-client para métricas)
RUN pip install flask flask-cors prometheus-client

# Exponer el puerto
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]