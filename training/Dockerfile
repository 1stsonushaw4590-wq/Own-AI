FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "train.py"]
