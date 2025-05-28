# Usa una imagen ligera de Python
FROM python:3.11-slim

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos necesarios
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto de la aplicación
COPY ./app ./app

# Expone el puerto 8080, obligatorio para Cloud Run
EXPOSE 8080

# Comando para iniciar la app. Asegúrate de que el archivo esté en app/main.py y haya una instancia "app"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
