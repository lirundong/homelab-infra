FROM python:3-alpine

WORKDIR /app/homelab-infra

COPY . .

RUN pip install --trusted-host pypi.python.org -e common -e util-cookbook/tencent-cloud

ENTRYPOINT ["register-dns"]
