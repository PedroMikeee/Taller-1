# Dockerfile de la app objetivo con agente RASP (app.py + rasp_agent.py)
# Construido desde la raiz del repo: docker build -f app/Dockerfile .
FROM python:3.11-slim

WORKDIR /app

# Requirements propios y livianos de esta app (NO el requirements.txt de la
# raiz del repo, que trae librerias de ML de la Fase 3 incompatibles con
# esta imagen base de Python 3.11)
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el codigo de la aplicacion
COPY app/ .

# Crear un usuario sin privilegios y ejecutar la app con el, en vez de root
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
