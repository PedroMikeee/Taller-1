# Dockerfile de la app objetivo con agente RASP (app.py + rasp_agent.py)
# Construido desde la raiz del repo: docker build -f app/Dockerfile .
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

# Healthcheck: verifica que la app responda, no solo que el proceso exista
# (hallazgo de Checkov: CKV_DOCKER_2)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/login?username=healthcheck&password=x', timeout=2)" || exit 1

CMD ["python", "app.py"]
