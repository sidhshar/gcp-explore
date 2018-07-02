from workflow_manager import WorkflowManager


def get_ph_from_splunk_event(reqjson):

	app.logger.info('In get_ph_from_splunk_event reqjson: %s' % (reqjson,))
	#write_json_file(ls.SPLUNK_JSON_STORE, reqjson)
	rawevent = reqjson['result']['_raw']

	# TODO: Change to regex
	splitbyph = rawevent.split("ph=")
	ph = splitbyph[1][1:65]
	#pph = splitbyph[2][1:65]

	if not ph:
		return False, 'ph not found: %s' % (ph,)
	return True, ph


def invoke_step2(host, ph):

	print 'Invoke step2: host: %s, ph: %s' % (host, ph)

	wobj = WorkflowManager()
	response = wobj.mark_nvm_flow_arrival(host, ph)
	print 'Step 2 response: ',response
	return response

