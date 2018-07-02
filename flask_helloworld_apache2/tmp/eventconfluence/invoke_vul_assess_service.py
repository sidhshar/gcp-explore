import grpc

import applicationVulnerabilityServiceIf_pb2_grpc
import applicationVulnerabilityServiceIf_pb2

import localsettings as ls


def get_cvss_for_process_hash(phash):
    channel = grpc.insecure_channel(ls.VUL_DOCKER_SERVICE)
    stub = applicationVulnerabilityServiceIf_pb2_grpc.VulnerabilityScoreServiceStub(channel)
    try:
        response = stub.getVulnerabilityScore(applicationVulnerabilityServiceIf_pb2.FileInfo(file_hash=phash))
    except Exception, e:
        # TODO: Handle at the Service for default 0 case
        print '[get_cvss_for_process_hash] Exception: %s' % (e,)
        response = 0
    return response


if __name__ == '__main__':
    for ph in ls.TEST_DATA_PROCESS_HASHES:
        response = get_cvss_for_process_hash(ph)
        if response:
            print("response received: %s" % (response.cvss,))
        else:
            print "No match found for %s" % (ph,)
        #break
