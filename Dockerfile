# Usamos imagen oficial optimizada para Python 3.11 en Linux
FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc y activar logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar dependencias del sistema necesarias para compilar paquetes de red y BD
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente completo del proyecto
COPY . .

# Exponer el puerto de la API FastAPI y Frontend
EXPOSE 8000

# Comando de arranque de producción con Uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]