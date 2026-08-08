FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/instance && useradd --create-home --uid 10001 logiclab && chown -R logiclab:logiclab /app
USER logiclab
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.app:app"]
