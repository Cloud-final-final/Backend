# Usa la imagen oficial de Python 3.11.6
FROM python:3.11.6

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos necesarios
COPY requirements.txt .
COPY app/ ./app/

# Instala dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Expone el puerto en el que correrá FastAPI
EXPOSE 8000

# Comando para ejecutar la aplicación
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
