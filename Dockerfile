FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CHIMERA_DATA=/data CHIMERA_SECRETS=/secrets CHIMERA_GEOLITE=/geolite
WORKDIR /opt/chimera
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -m -u 10001 chimera && mkdir /data /secrets /geolite && chown chimera:chimera /data /secrets /geolite
COPY app ./app
COPY scripts ./scripts
USER chimera
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=4s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

