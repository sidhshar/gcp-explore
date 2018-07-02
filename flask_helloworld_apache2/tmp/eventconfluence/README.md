# Event Confluence

Flask based project to handle confluence of the request originating between the Browser and NVM flow

# Vulnerability Assessment service integration using grpc 

python -m grpc_tools.protoc -I./protos --python_out=. --grpc_python_out=. ./protos/applicationVulnerabilityServiceIf.proto

pip install google_compute_engine

mkdir /home/sidhshar/data

virtualenv venv01

source venv01/bin/activate

python -m pip install --upgrade pip
python -m pip install grpcio

gsutil cp gs://cpe_cvss/cpe-cvss.json /home/sidhshar/data

docker run -it --name vul-ser-1 -v /home/sidhshar/data:/root/res:ro vishnuvp/app-vulnerability-service

