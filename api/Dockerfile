FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install -y python3
RUN apt-get install -y python3-pip python-dev build-essential
RUN python3 -m pip install --upgrade pip
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]
