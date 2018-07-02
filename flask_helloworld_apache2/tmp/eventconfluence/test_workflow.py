import time

from istio_integration import invoke_istio_integration
from splunk_integration import invoke_step2, get_ph_from_splunk_event

def invoke_test_step1():
	istio_request = {'X-Initiator-Remote-Addr-1': '72.163.208.155, 72.163.217.103',
					 'X-Initiator-Ua': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'}
	remote_addr = istio_request['X-Initiator-Remote-Addr-1'].split(',')[0]
	result = invoke_istio_integration(remote_addr, istio_request['X-Initiator-Ua'])



def invoke_test_step2():
	splunk_webhook_data = { 'host': '72.163.208.155', 'ph': '072041FA70BB351030C516E1B6F7F21D15495DA158F3890826BA5B978AF8900E' }
	invoke_step2(splunk_webhook_data['host'], splunk_webhook_data['ph'])

if __name__ == '__main__':
	# Note: Remove db to execute positive flow
	# rm /var/data/istiodemo.db

	invoke_test_step1()

	invoke_test_step2()
