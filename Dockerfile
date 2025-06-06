FROM python:3-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY falcon2thehive.py ./
COPY assets ./assets

CMD ["python", "falcon2thehive.py"]
