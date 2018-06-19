import datetime
import time
import localsettings as ls
import sqlite3


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class DBHandler(object):
	def __init__(self):
		self.connection = sqlite3.connect(ls.DBSTORE)
		self.connection.isolation_level = None #If you want autocommit mode, then set isolation_level to None.
		self.create_table()
	def execute_query_via_cursor(self, query):
		cursor = self.connection.cursor()
		cursor.execute(query)
		cursor.close()
	def execute_parameterised_query_via_cursor(self, query, parameters):
		# TODO: Create cursor pool
		cursor = self.connection.cursor()
		cursor.execute(query, parameters)
		cursor.close()
	def execute_parameterised_query_via_cursor_with_results(self, query, parameters):
		cursor = self.connection.cursor()
		cursor.execute(query, parameters)
		results = cursor.fetchall()
		cursor.close()
		return results
	def create_table(self):
		create_query = '''CREATE TABLE IF NOT EXISTS EVENT_PROCESSOR
			(ID INTEGER PRIMARY KEY, REMOTE_ADDR text, ua text, ph text, ts timestamp, vulassessment int, retrycount int, retry_timestamps text)'''
		self.execute_query_via_cursor(create_query)
	def write_to_db(self, ip, ua, ph, ts, cvss, rcount, rts):
		now = datetime.datetime.now()
		insert_query = "INSERT INTO EVENT_PROCESSOR(REMOTE_ADDR, ua, ph, ts, vulassessment, retrycount, retry_timestamps) values (?, ?, ?, ?, ?, ?, ?)"
		insert_values = (ip, ua, ph, ts, cvss, rcount, rts)
		self.execute_parameterised_query_via_cursor(insert_query, insert_values)
	def perform_select_on_ip(self, ip):
		selectvalues = (ip,)
		select_query = 'SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=?'
		results = self.execute_parameterised_query_via_cursor_with_results(select_query, selectvalues)
		return results
	def close(self):
		self.connection.close()



class RequestItem(object):
	def __init__(self, ip, ua):
		self.ip = ip
		self.ua_from_istio = ua
		self.state = ls.WORKFLOW_STATES[ls.RECEIVED_FROM_ISTIO]
		self.retry_count = 0
		self.retry_timestamps = []
		self.ts = datetime.datetime.now()
		self.cvss_score = 0
		self.ph = None

	def get_ip(self):
		return self.ip
	def get_verbose_state(self):
		return ls.WORKFLOW_STATES_VERBOSE[self.state]
	def increment_retry_count(self):
		self.retry_count += 1
		self.retry_timestamps.append(datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p"))
	def change_to_nvm_event_recieved(self):
		self.state = ls.WORKFLOW_STATES[ls.RECIEVED_WEBHOOK_TRIGGER]
	def mark_vul_assess_done(self):
		self.state = ls.WORKFLOW_STATES[ls.VUL_ASSESS_COMPLETE]
	def mark_complete(self):
		self.state = ls.WORKFLOW_STATES[ls.ALL_PROCESSING_DONE]
	def is_complete(self):
		return self.state == ls.WORKFLOW_STATES[ls.ALL_PROCESSING_DONE]
	def set_cvss_score(self, cvss):
		self.cvss_score = cvss
	def set_process_hash(self, ph):
		self.ph = ph
	def save_audit_trail(self):
		dbhandle = DBHandler()
		dbhandle.write_to_db(self.ip, self.ua_from_istio, self.ph, self.ts, self.cvss_score,
							 self.retry_count, "+".join(self.retry_timestamps))
		dbhandle.close()


class WorkflowManager(object):
	__metaclass__ = Singleton

	def __init__(self):
		self.pending = {}

	def get_pending_by_ip(self, ip):
		if self.pending.has_key(ip):
			return self.pending[ip]

	def create_new_request(self, ip, ua):
		pending = self.get_pending_by_ip(ip)
		if pending is None:
			# Create new pending request
			reqitem = RequestItem(ip, ua)
			self.pending[ip] = reqitem
			return reqitem
		else:
			# Update the retry count
			pending.increment_retry_count()
			return pending

	def mark_nvm_flow_arrival(self, ip, ph):
		pending = self.get_pending_by_ip(ip)
		if pending is None:
			# Error condition. Exit loop here
			print 'Did not find workflow object with IP: %s hash: %s. IGNORE Request.' % (ip, ph)
			return False
		else:
			pending.change_to_nvm_event_recieved()
			pending.set_process_hash(ph)
			cvss_score = self.make_vul_assess_call(ph)
			pending.set_cvss_score(cvss_score)
			pending.mark_vul_assess_done()
			# Write object details to DB and pop the queue object
			pending.save_audit_trail()
			pending.mark_complete()
			self.pending.pop(ip)
			return True

	def make_vul_assess_call(self, ph):
		time.sleep(2)
		return ls.TEST_CVSS_SCORE


def wait_for_complete_state(reqitem):
	waiting_time = 0
	while (waiting_time <= ls.TIMEOUT_IN_SECS):
		if reqitem.is_complete():
			return True
		time.sleep(ls.SLEEP_TIME_SLICE)
		waiting_time += ls.SLEEP_TIME_SLICE
	return False


def invoke_step1(ip, ua):

	print 'Invoke step1'

	cvss_score = 0

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
		reqitem = wobj.create_new_request(ip, ua)
		status = wait_for_complete_state(reqitem)
		if not status:
			# Timeout occured. Return negative response
			print 'Timeout in Step1'
			return { ls.INSERT_HEADER_NAME: False }
		cvss_score = reqitem.cvss_score

	if ls.TEST_CVSS_THRESHOLD <= cvss_score:
		# Return Positive response
		response = { ls.INSERT_HEADER_NAME: True }
	else:
		# Return negative response
		response = { ls.INSERT_HEADER_NAME: False }
	print 'Step 1 response: ',response
	return response


def invoke_step2(host, ph):
	print 'Invoke step2'
	wobj = WorkflowManager()
	response = wobj.mark_nvm_flow_arrival(host, ph)
	print 'Step 2 response: ',response
	return response


def invoke_test_step1():
	istio_request = {'X-Initiator-Remote-Addr-1': '72.163.208.155, 72.163.217.103',
					 'X-Initiator-Ua': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'}
	remote_addr = istio_request['X-Initiator-Remote-Addr-1'].split(',')[0]
	result = invoke_step1(remote_addr, istio_request['X-Initiator-Ua'])


def invoke_test_step2():
	splunk_webhook_data = { 'host': '72.163.208.155', 'ph': '072041FA70BB351030C516E1B6F7F21D15495DA158F3890826BA5B978AF8900E' }
	invoke_step2(splunk_webhook_data['host'], splunk_webhook_data['ph'])


if __name__ == '__main__':

	#invoke_test_step1()

	#time.sleep(2)

	invoke_test_step2()

