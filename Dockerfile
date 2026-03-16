FROM python:3-slim

WORKDIR /usr/src/app
COPY . /usr/src/app/
RUN pip install --no-cache-dir -r ./requirements.txt

ENTRYPOINT ["python", "balancer"]
