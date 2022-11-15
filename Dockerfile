FROM python:3.9

# ENV HTTP_PROXY="proxy:port"
# ENV HTTPS_PROXY="proxy:port"

RUN pip install requests

WORKDIR /app

COPY main.py .
COPY config.py .
ADD /mail ./mail

CMD ["/usr/local/bin/python3.9", "/app/main.py"]