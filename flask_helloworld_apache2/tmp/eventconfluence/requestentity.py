import datetime

import localsettings as ls
from dbhandler import DBHandler


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

