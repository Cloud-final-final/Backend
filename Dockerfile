# Usa una imagen base ligera con Python
FROM python:3.11-slim

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Variable de entorno que espera Cloud Run
ENV PORT=8080

# Expone el puerto que Cloud Run usará
EXPOSE 8080

# Comando para arrancar la app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]