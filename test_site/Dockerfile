FROM python:3.12-slim
WORKDIR /app
COPY test_site/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY test_site /app/test_site
EXPOSE 8001
CMD ["uvicorn", "test_site.app:app", "--host", "0.0.0.0", "--port", "8001"]
