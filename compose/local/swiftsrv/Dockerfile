FROM swift:latest

RUN apt update && \
    apt install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt install -y python3.12 python-pip wget git && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

WORKDIR /app

COPY ./compose/local/swiftsrv/requirements.txt /app/requirements.txt
RUN wget https://bootstrap.pypa.io/get-pip.py -O get-pip.py \
    && python3.12 get-pip.py \
    && pip install -r /app/requirements.txt
# RUN pip install -r /app/requirements.txt

COPY ./compose/local/swiftsrv/swift_srv.py /app
COPY ./mastf/ios/swiftsrv_format.py /app



CMD ["python3.12", "/app/swift_srv.py"]