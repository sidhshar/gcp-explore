import localsettings as ls
from dbhandler import DBHandler
from workflow_manager import WorkflowManager, wait_for_complete_state

def invoke_istio_integration(ip, ua):
	"""
	"""


	print 'Invoke invoke_istio_integration. ip: %s, ua: %s' % (ip, ua)

	cvss_score = 10

	dbhandle = DBHandler()
	results = dbhandle.perform_select_on_ip(ip)

	if results:
		# Assume 1 result as of now. TODO
		result = results[0]
		cvss_score = result[4]
		print 'Got data from DB'
	else:
		print 'Starting Workflow Manager..'
		wobj = WorkflowManager()
		print '11111 wobj: ',wobj
		reqitem = wobj.create_new_request(ip, ua)
		status = wait_for_complete_state(reqitem)
		if not status:
			# Timeout occured. Return negative response
			print 'Timeout in Step1'
			return { 'cvss': ls.CVSS_IN_TIMEOUT_CASES }
		cvss_score = reqitem.cvss_score

	response = { 'cvss': cvss_score }

	# if ls.TEST_CVSS_THRESHOLD <= cvss_score:
	# 	# Return Positive response
	# 	response = { ls.INSERT_HEADER_NAME: True }
	# else:
	# 	# Return negative response
	# 	response = { ls.INSERT_HEADER_NAME: False }
	print 'Step 1 response: ',response
	return response
