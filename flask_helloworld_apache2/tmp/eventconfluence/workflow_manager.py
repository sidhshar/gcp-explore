import time

import localsettings as ls
from singleton import Singleton
from requestentity import RequestItem
#from invoke_vul_assess_service import get_cvss_for_process_hash


class WorkflowManager(object):
	__metaclass__ = Singleton
	# pending = {}

	def __init__(self):
		self.pending = {}

	def get_pending_by_ip(self, ip):
		print 'pending queue contents: %s' % (self.pending,)
		if self.pending.has_key(ip):
			return self.pending[ip]

	def set_pending_by_ip(self, ip, reqitem):
		self.pending[ip] = reqitem
		print 'pending queue contents: %s' % (self.pending,)

	def create_new_request(self, ip, ua):
		pending = self.get_pending_by_ip(ip)
		if pending is None:
			# Create new pending request
			reqitem = RequestItem(ip, ua)
			#self.pending[ip] = reqitem
			print 'Creating new pending..'
			self.set_pending_by_ip(ip, reqitem)
			return reqitem
		else:
			# Update the retry count
			pending.increment_retry_count()
			print 'Got pending.. Increment Retry count.'
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
		cvss = get_cvss_for_process_hash(ph)
		return cvss
		# Comment above/Uncomment below for test purposes without invoking vulnerability assessment service
		# time.sleep(1)
		# return ls.TEST_CVSS_SCORE


def wait_for_complete_state(reqitem):
	waiting_time = 0
	while (waiting_time <= ls.TIMEOUT_IN_SECS):
		if reqitem.is_complete():
			return True
		time.sleep(ls.SLEEP_TIME_SLICE)
		waiting_time += ls.SLEEP_TIME_SLICE
	return False

