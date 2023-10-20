FROM python:3.11

ARG PGW_PW
ENV PGW_PW=$PGW_PW

RUN mkdir /app
WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY chunktest.py .
COPY chunks.json .
USER nobody
ENTRYPOINT ["python3", "chunktest.py"]
EXPOSE ${APP_PORT}
