FROM python:3.11-slim
WORKDIR /srv
COPY payloads /srv/payloads
EXPOSE 80
CMD ["python", "-m", "http.server", "80", "--directory", "/srv/payloads"]
