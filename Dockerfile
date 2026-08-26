# Use lightweight Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing .pyc files & buffer output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy requirements and install dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and frontend source directories
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

# Expose server port
EXPOSE 5000

# Set execution path to backend and launch Flask server
WORKDIR /app/backend
CMD ["python3", "app.py"]

