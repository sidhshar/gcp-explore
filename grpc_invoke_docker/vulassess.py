import grpc

import applicationVulnerabilityServiceIf_pb2_grpc
import applicationVulnerabilityServiceIf_pb2


def run(phash):
    channel = grpc.insecure_channel('172.17.0.2:7777')
    stub = applicationVulnerabilityServiceIf_pb2_grpc.VulnerabilityScoreServiceStub(channel)
    response = stub.getVulnerabilityScore(applicationVulnerabilityServiceIf_pb2.FileInfo(file_hash=phash))
    return response


if __name__ == '__main__':
	ph = '9d65c6f0998061e1c77c281974fc7fa437f42c62d3cd09f833892d1f63031ff2'
    response = run(ph)
    print("response received: " + response.message)
