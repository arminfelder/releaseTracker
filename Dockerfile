FROM python:3.12.0-slim-bullseye

COPY src /app

WORKDIR /app

RUN pip install -r requirements.txt

CMD ["python", "./main.py"]