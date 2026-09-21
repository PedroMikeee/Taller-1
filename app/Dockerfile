# Dockerfile de la app objetivo con agente RASP (app.py + rasp_agent.py)
# Construido desde la raíz del repo: docker build -f app/Dockerfile .
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias primero para aprovechar la cache de capas de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY app/ .

EXPOSE 5000

CMD ["python", "app.py"]
