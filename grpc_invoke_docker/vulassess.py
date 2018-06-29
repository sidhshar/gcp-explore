import grpc

import applicationVulnerabilityServiceIf_pb2_grpc
import applicationVulnerabilityServiceIf_pb2


def run(phash):
    channel = grpc.insecure_channel('172.17.0.2:7777')
    stub = applicationVulnerabilityServiceIf_pb2_grpc.VulnerabilityScoreServiceStub(channel)
    try:
    	response = stub.getVulnerabilityScore(applicationVulnerabilityServiceIf_pb2.FileInfo(file_hash=phash))
    except Exception, e:
    	# TODO: Handle at the Service for default 0 case
    	response = 0
    return response


if __name__ == '__main__':
    phs = ["0830AF92B1959E2137B8E4B304266842AED1EA5B40735A5F0CA3792A3779D7C0",
    "6BCAA2B71971433CFEEEA784A782C57E1A8AFC209BEEC285DCB037B20C9C0F35",
    "C00B9F2B32828341A9185AE2BE1A0649C9F503F0B5CCCEBC75BE4C2F8C596530"]

    for ph in phs:
        response = run(ph)
        print("response received: %s" % (response.cvss,))