# Dockerfile de la app objetivo con agente RASP (app.py + rasp_agent.py)
# Construido desde la raiz del repo: docker build -f app/Dockerfile .
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias primero para aprovechar la cache de capas de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el codigo de la aplicacion
COPY app/ .

# Crear un usuario sin privilegios y ejecutar la app con el, en vez de root
# (hallazgo real de Semgrep: dockerfile.security.missing-user.missing-user)
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
