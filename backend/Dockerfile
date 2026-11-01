FROM python:3.12-slim

# INSTALL_ML=true adds DeBERTa (CPU torch + transformers) and Presidio + spaCy small (~1.5 GB image)
ARG INSTALL_ML=false
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HOME=/models

WORKDIR /app
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
      pip install --no-cache-dir -r requirements-ml.txt && \
      python -m spacy download en_core_web_sm ; \
    fi

COPY gateway ./gateway
COPY data/docs ./data/docs
COPY eval ./eval

RUN useradd -m gateway && mkdir -p /app/data /models && chown -R gateway /app/data /models
USER gateway
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
