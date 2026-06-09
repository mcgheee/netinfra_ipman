FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY netinfra_ipman ./netinfra_ipman
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "netinfra_ipman.main:app", "--host", "0.0.0.0", "--port", "8000"]
