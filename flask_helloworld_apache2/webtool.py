import os
import time
import json
import requests
import random
import sqlite3, datetime
from flask import Flask, request, jsonify

import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
DBSTORE = os.path.join(PROJECT_ROOT, 'istiodemo.db')
LOG_DIR = os.path.expanduser('/var/log/istiopoc')
VT_JSON_STORE = os.path.join(LOG_DIR, 'json_store_vt')
SPLUNK_JSON_STORE = os.path.join(LOG_DIR, 'json_store_splunk')

# ------------------ LOCALSETTINGS ---------------------- #

HEADER_OF_INTEREST = 'User-Agent'
CUSTOM_HEADER_NAME = 'x-is-allowed'
CUSTOM_HEADER_STATE_ON = 'enabled'
CUSTOM_HEADER_STATE_OFF = 'disabled'
WAIT_TIME_IN_SECONDS = 5
SLEEP_TIME_SLICE = 0.5
CVSS_THRESHOLD_FOR_REJECTION = 7
SAMPLE_CVSS_VALUE = 8

VT_URL = 'https://www.virustotal.com/ui/search?query=%s'
VT_CALL_ENABLE = False
VT_TEST_DATA = {'file_version': '47.0.2526.111', 'file_description': 'Google Chrome'}


# ------------------ SQLITE3 ---------------------- #

#connection = sqlite3.connect(":memory:")
# connection = sqlite3.connect('istiodemo.db')
# connection.isolation_level = None #If you want autocommit mode, then set isolation_level to None.
# cursor = connection.cursor()

# ------------------ SQL ---------------------- #

UPDATE_SQL_STATE = '''UPDATE EVENT_PROCESSOR
          SET state = ?
          WHERE ID = ?'''


UPDATE_SQL_IS_VA = '''UPDATE EVENT_PROCESSOR
          			  SET incomingstate = ?,
          			  vulassessment = ?
          			  WHERE ID = ?'''

# ------------------------------------------------------- #


# ------------------ Use Case  ---------------------- #
# Use case to get the request from Istio and based on a timeout
# send back result that header is not present

# Step 1. When Istio request comes, make an entry into db
# Step 2. Keep checking the status to find out whether there is any updation on the Vul score
# Step 3. If Vul score present and passed, send appropriate success or failure response
# Step 4. If Timeout then return the failure state




class EventProcessor(object):
	def __init__(self):
		#self.connection = sqlite3.connect(DBSTORE)
		# In memory
		self.connection = sqlite3.connect(":memory:")

		self.connection.isolation_level = None #If you want autocommit mode, then set isolation_level to None.
		#self.cursor = self.connection.cursor()

	def execute_parameterised_query_via_cursor(self, query, parameters):
		cursor = self.connection.cursor()
		cursor.execute(query, parameters)
		cursor.close()

	def execute_parameterised_query_via_cursor_with_results(self, query, parameters):
		cursor = self.connection.cursor()
		cursor.execute(query, parameters)
		results = cursor.fetchall()
		cursor.close()
		return results

	def execute_query_via_cursor(self, query):
		cursor = self.connection.cursor()
		cursor.execute(query)
		cursor.close()

	# def execute_query_via_cursor_with_results(self, query):
	# 	cursor = self.connection.cursor()
	# 	cursor.execute(query)
	# 	return cursor

	def create_table(self):
	# Query 1
		# Create table
		# self.cursor.execute('''CREATE TABLE IF NOT EXISTS EVENT_PROCESSOR
  #            	 	(ID INTEGER PRIMARY KEY, REMOTE_ADDR text, ua text, ts timestamp, state int, incomingstate int, vulassessment int)''')
		create_query = '''CREATE TABLE IF NOT EXISTS EVENT_PROCESSOR
			(ID INTEGER PRIMARY KEY, REMOTE_ADDR text, ua text, ts timestamp, state int, incomingstate int, vulassessment int)'''
		self.execute_query_via_cursor(create_query)

	def perform_select_on_state(self, remoteaddr):
		# Query 2
		selectvalues = (remoteaddr, 0)
		select_query = 'SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=? AND state=? ORDER BY ts'
		#self.cursor.execute('SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=? AND state=? ORDER BY ts', selectvalues)
		results = self.execute_parameterised_query_via_cursor_with_results(select_query, selectvalues)
		#results = self.cursor.fetchall()
		app.logger.info('00 SELECT BY REMOTE_ADDR: %s STATE: %s, results: %s' % (remoteaddr, 0, results))
		return results

	def release_wait(self, results):
		# Query 3
		for each_result in results:
			app.logger.info('00 UPDATE state: 1 for ID: %s' % (each_result[0],))
			updatevalues = (1, each_result[0])
			#self.cursor.execute(UPDATE_SQL_STATE, updatevalues)
			self.execute_parameterised_query_via_cursor(UPDATE_SQL_STATE, updatevalues)

	def clear_current_remoteaddr_entries(self, remoteaddr):
		results = self.perform_select_on_state(remoteaddr)
		app.logger.info('Step 0. Clearing older results: %s' % (results,))
		self.release_wait(results)

	def create_entry_of_incoming_request(self, remoteaddr, useragent):
		# Query 4
		app.logger.info('Step 1. Creating entry for incoming request')
		now = datetime.datetime.now()
		insert_query = "INSERT INTO EVENT_PROCESSOR(REMOTE_ADDR, ua, ts, state, incomingstate, vulassessment) values (?, ?, ?, ?, ?, ?)"
		insert_values = (remoteaddr, useragent, now, 0, 0, 0)
		self.execute_parameterised_query_via_cursor(insert_query, insert_values)

		#self.cursor.execute("INSERT INTO EVENT_PROCESSOR(REMOTE_ADDR, ua, ts, state, incomingstate, vulassessment) values (?, ?, ?, ?, ?, ?)", (remoteaddr, useragent, now, 0, 0, 0))
		app.logger.info('INSERT REMOTE_ADDR: %s, ua: %s' % (remoteaddr, useragent))

	def perform_select_on_incomingstate(self, remoteaddr):
		# Query 5
		selectvalues = (remoteaddr, 1, 0)
		select_query = 'SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=? AND incomingstate=? AND state=? ORDER BY ts'
		#self.cursor.execute('SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=? AND incomingstate=? AND state=? ORDER BY ts', selectvalues)
		results = self.execute_parameterised_query_via_cursor_with_results(select_query, selectvalues)
		#results = self.cursor.fetchall()
		app.logger.info('11 SELECT BY REMOTE_ADDR: %s incomingstate: %s, state: %s, results: %s' % (remoteaddr, 1, 0, results))
		return results

	def is_incoming_trigger_recieved(self, remoteaddr):
		results = self.perform_select_on_incomingstate(remoteaddr)
		app.logger.info('Step 2. In is_incoming_trigger_recieved results: %s' % (results,))
		return results

	def update_based_on_incomingtrigger(self, remoteaddr, cvss):
		# Query 6
		results = self.perform_select_on_state(remoteaddr)
		app.logger.info('Step 3. In update_based_on_incomingtrigger results: %s remoteaddr: %s' % (results, remoteaddr))
		if results:
			for each_result in results:
				updatevalues = (1, cvss, each_result[0])
				#self.cursor.execute(UPDATE_SQL_IS_VA, updatevalues)
				self.execute_parameterised_query_via_cursor(UPDATE_SQL_IS_VA, updatevalues)
				app.logger.info('11 UPDATE incomingstate: 1, vulassessment: %s for ID: %s' % (cvss, each_result[0],))
			return True
		else:
			return False

	def is_request_allowed_by_vulassess(self, itresult):
		# TODO: Business logic here. Currently assume that request returns either True or False
		# Input: remote address of request
		# Need inputs from other services: webhook trigger from Splunk, vul assessment from OPA, etc
		app.logger.info('Last step-> itresult: %s' % (itresult,))
		if itresult[6] > CVSS_THRESHOLD_FOR_REJECTION:
			return True
		else:
			return False

	def close(self):
		self.connection.close()


# ------------------------------------------------------- #

class ProcessHashHandler(object):

	def __init__(self):
		self.ph_store = {}

	def get_version_by_ph(self, ph):
		if ph in self.ph_store:
			app.logger.info('get_version_by_ph return from ph_store')
			return self.ph_store[ph]

		if VT_CALL_ENABLE:
			return self.get_version_from_vt(ph)
		else:
			# TODO: When External call as well as ph_store does not have the data, then what to do?
			return provide_version_for_testing()


	def get_version_from_vt(self, ph):
		phresponse = requests.get(VT_URL % (ph,))

		if phresponse:
			if phresponse.status_code == 200:
				vt_response_json = phresponse.json()
				write_json_file(VT_JSON_STORE, vt_response_json)
				try:
					exiftool = vt_response_json['data'][0]['attributes']['exiftool']
					file_version = exiftool['FileVersion']
					file_description = exiftool['FileDescription']
				except KeyError:
					return {'status': False,  'reason': 'KeyError'}
			else:
				return {'status': False, 'reason': 'Non 200 response'}
		else:
			return {'status': False, 'reason': 'phresponse empty'}

		self.ph_store[ph] = { 'file_version': file_version, 'file_description': file_description }

		app.logger.info('get_version_from_vt ph: %s' % (file_version,))
		return {'status': True , 'file_version': file_version, 'file_description': file_description }


# ------------------------------------------------------- #

def perform_splunk_alert_action(reqjson):
	app.logger.info('In perform_splunk_alert_action reqjson: %s' % (reqjson,))
	#reqjson = request.json
	#print reqjson
	write_json_file(SPLUNK_JSON_STORE, reqjson)
	rawevent = reqjson['result']['_raw']

	# TODO: Change to regex
	splitbyph = rawevent.split("ph=")
	ph = splitbyph[1][1:65]
	pph = splitbyph[2][1:65]
	#print 'ph: %s, pph: %s' % (ph, pph)

	if not ph:
		return {'status': False, 'reason': 'ph/pph not found: %s %s' % (ph, pph)}

	response = app.phhandle.get_version_by_ph(ph)
	app.logger.info('In perform_splunk_alert_action response: %s' % (response,))

	return response


# ------------------------------------------------------- #

def write_json_file(filepath, data):
	ts = str(datetime.datetime.now()).replace(' ','-').replace(':','-').replace('.','-')
	with open('%s%s%s.json' % (filepath, os.sep, ts,), 'w') as outfile:
		json.dump(data, outfile)

def get_remote_address(request):
	# TODO: Need to change based on the request parameters from Istio Gateway
	if request.headers.getlist("X-Forwarded-For"):
		remote_addr = request.headers.getlist("X-Forwarded-For")[0]
	else:
		remote_addr = request.remote_addr
	return remote_addr

def provide_version_for_testing():
	status = { 'status': True }
	status.update( VT_TEST_DATA )
	return status

def get_cvss_from_cpe(cpe):
	# TODO: OPA call?
	app.logger.info('TODO: cpe to cvss score. response: %s' % (cpe,))
	return SAMPLE_CVSS_VALUE

def make_cpe_format(file_version, file_description):
	# TODO
	pass


# ------------------------------------------------------- #
@app.route('/performvulassessment', methods=['GET'])
def performvulnerabilityassessment():

	#handle = EventProcessor()
	user_response = {}
	waiting_time = 0

	app.logger.info('/performvulassessment request.headers: %s' % (request.headers,))

	# Get the User Agent
	custom_header = request.headers.get(HEADER_OF_INTEREST)
	user_response['result'] = {}
	user_response['request'] = {}
	user_response['request']['custom_header'] = custom_header

	# Get the Remote Address
	#remote_addr = get_remote_address(request)
	remote_addr = request.headers['X-Initiator-Remote-Addr-1'].split(',')[0]

	user_response['request']['remote_address'] = remote_addr

	app.ephandle.clear_current_remoteaddr_entries(remote_addr)

	app.ephandle.create_entry_of_incoming_request(remote_addr, custom_header)

	enable_header = False
	while (waiting_time <= WAIT_TIME_IN_SECONDS):
		results = app.ephandle.is_incoming_trigger_recieved(remote_addr)
		if results:
			# TODO: Ensure that we always get back just 1 result. Currently assuming
			itresult = results[0]
			if app.ephandle.is_request_allowed_by_vulassess(itresult):
				enable_header = True
			app.ephandle.release_wait(results)
			break
		time.sleep(SLEEP_TIME_SLICE)
		waiting_time += SLEEP_TIME_SLICE

	#if is_request_allowed_by_vulassess(itresult):
	if enable_header:
		user_response['result'][CUSTOM_HEADER_NAME] = CUSTOM_HEADER_STATE_ON
	else:
		user_response['result'][CUSTOM_HEADER_NAME] = CUSTOM_HEADER_STATE_OFF

	return jsonify(user_response)

# ------------------------------------------------------- #
@app.route('/eventwebhook', methods=['POST'])
def eventwebhook():
	handle = EventProcessor()
	cpe_format = None
	user_response = {}
	request_data = json.loads(request.data)
	request_json = request.json

	# request.json - ['result']['_raw']
	# request_data - ipaddress
	#print 'eventwebhook request.json: ',request.json
	#print 'eventwebhook request_data: ',request_data
	app.logger.info('request.json: %s     :::::::       request_data: %s' % (request_json, request_data))

	splunk_webhook_response = {}
	if request.json:
		splunk_webhook_response = perform_splunk_alert_action(request_json)
		if not splunk_webhook_response['status']:
			pass
		else:
			file_version = splunk_webhook_response['file_version']
			file_description = splunk_webhook_response['file_description']
			cpe_format = make_cpe_format(file_version, file_description)
	else:
		splunk_webhook_response = { 'request.json': request_json, 'status': 'Failure' }
	user_response.update( {'splunk_webhook_response' : splunk_webhook_response } )

	# Based on incoming trigger request, decide and update whether the other header needs to be populated
	ipaddress = request_json['result']['host']
	#ipaddress = request_data.get('ipaddress')

	cvss = get_cvss_from_cpe(cpe_format)

	result = app.ephandle.update_based_on_incomingtrigger(ipaddress, cvss)
	if not result:
		user_response.update( {'status': 'failure (if not result)'} )
	
	#print 'user_response: %s' % (user_response,)
	app.logger.info('user_response: %s' % (user_response,))

	return jsonify(user_response)

# ------------------------------------------------------- #

@app.before_first_request
def init():
	app.phhandle = ProcessHashHandler()
	app.ephandle = EventProcessor()
	app.ephandle.create_table()

	logHandler = RotatingFileHandler('logs/applog.log', maxBytes=1024)
	logHandler.setLevel(logging.INFO)
	app.logger.setLevel(logging.INFO)
	app.logger.addHandler(logHandler)



# ------------------------------------------------------- #

# P1 TODOs:
# 1. Log store create directories? Their permission should be www-data
# mkdir /var/log/istiopoc
# mkdir /var/log/istiopoc/json_store_vt
# mkdir /var/log/istiopoc/json_store_splunk
# sudo chown -R www-data /var/log/istiopoc




# ------------------------------------------------------- #

if __name__ == '__main__':
	#phhandle = ProcessHashHandler()
	#handle = EventProcessor()
	#handle.create_table()

	#logHandler = RotatingFileHandler('logs/applog.log', maxBytes=1024)
	#logHandler.setLevel(logging.INFO)
	#app.logger.setLevel(logging.INFO)
	#app.logger.addHandler(logHandler)

	#app.run(host='0.0.0.0', port=9090)
	app.run()

	#handle.close()

