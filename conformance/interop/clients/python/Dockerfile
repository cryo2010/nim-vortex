# Python interop client (httpx with the h2 backend for real HTTP/2).
FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir "httpx[http2]==0.27.*"
COPY client.py .
CMD ["python", "client.py"]
