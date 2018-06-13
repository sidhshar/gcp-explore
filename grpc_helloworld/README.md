# grpc setup

Source credit - https://grpc.io/docs/quickstart/python.html

sudo apt-get install python-virtualenv

virtualenv venv01

source venv01/bin/activate

python -m pip install grpcio

python -m pip install grpcio-tools

# grpc hello world example (using python 2.7)

Source credit - https://grpc.io/docs/quickstart/python.html#run-a-grpc-application

Run the server

$ python greeter_server.py

In another terminal, run the client

$ python greeter_client.py

Generate gRPC code

python -m grpc_tools.protoc -I./protos --python_out=. --grpc_python_out=. ./protos/helloworld.proto


