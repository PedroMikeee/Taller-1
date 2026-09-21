# Dockerfile de la app objetivo con agente RASP (app.py + rasp_agent.py)
# Construido desde la raiz del repo: docker build -f app/Dockerfile .
# Se usa Alpine en vez de Debian/slim: imagen base mucho mas minimalista,
# con muchos menos paquetes de sistema y por lo tanto menos CVEs heredados
# (hallazgo real de Trivy: 44 vulnerabilidades HIGH en la variante slim/Debian).
FROM python:3.11-alpine

WORKDIR /app

# Requirements propios y livianos de esta app
COPY app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copiar el codigo de la aplicacion
COPY app/ .

# Crear un usuario sin privilegios y ejecutar la app con el, en vez de root
RUN adduser -D appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
