import os
import time
import json
import requests
import random
import sqlite3, datetime
from flask import Flask, request, jsonify

import logging
from logging.handlers import RotatingFileHandler

import localsettings as ls

from workflow_handler import invoke_step1, invoke_step2

app = Flask(__name__)


# ------------------ Use Case  ---------------------- #
# Use case to get the request from Istio and based on a timeout
# send back result that header is not present


# ------------------------------------------------------- #

def write_json_file(filepath, data):
	ts = str(datetime.datetime.now()).replace(' ','-').replace(':','-').replace('.','-')
	with open('%s%s%s.json' % (filepath, os.sep, ts,), 'w') as outfile:
		json.dump(data, outfile)

# ------------------------------------------------------- #
@app.route('/performvulassessment', methods=['GET'])
def performvulnerabilityassessment():

	app.logger.info('/performvulassessment request.headers: %s' % (request.headers,))

	# Get the User Agent
	#custom_header = request.headers.get(ls.HEADER_OF_INTEREST)
	user_response = {}
	user_response['result'] = {}
	user_response['request'] = {}
	#user_response['request'][ls.HEADER_OF_INTEREST] = custom_header

	# Get the Remote Address
	remote_addr = request.headers['X-Initiator-Remote-Addr-1'].split(',')[0]
	intiator_ua = request.headers['X-Initiator-Ua']
	user_response['request']['remote_address'] = remote_addr
	user_response['request']['X-Initiator-Ua'] = intiator_ua

	step1_response = invoke_step1(remote_addr, intiator_ua)

	user_response['result']['step1_response'] = step1_response

	print 'user_response: ',user_response

	return jsonify(user_response)

# ------------------------------------------------------- #
@app.route('/eventwebhook', methods=['POST'])
def eventwebhook():
	user_response = {}
	request_data = json.loads(request.data)
	request_json = request.json

	app.logger.info('request.json: %s     :::::::       request_data: %s' % (request_json, request_data))

	ipaddress = request_json['result']['host']
	status, ph = get_ph_from_splunk_event(request_json)

	if not status:
		# Did not get process hash. Error condition TODO
		pass
	else:
		response_step2 = invoke_step2(ipaddress, ph)

	user_response['ph'] = ph
	user_response['ip'] = ipaddress
	user_response['response_step2'] = response_step2
	app.logger.info('user_response: %s' % (user_response,))
	return jsonify(user_response)

# ------------------------------------------------------- #

def get_ph_from_splunk_event(reqjson):
	app.logger.info('In get_ph_from_splunk_event reqjson: %s' % (reqjson,))
	write_json_file(ls.SPLUNK_JSON_STORE, reqjson)
	rawevent = reqjson['result']['_raw']

	# TODO: Change to regex
	splitbyph = rawevent.split("ph=")
	ph = splitbyph[1][1:65]
	#pph = splitbyph[2][1:65]

	if not ph:
		return False, 'ph not found: %s' % (ph,)
	return True, ph


@app.route('/', methods=['GET'])
def serverbaseurl():
	log_me_dict = { 'invoked_url': '/', 'headers': request.headers }
	user_response = { 'response': 'Unauthorized action. Would be reported!' }
	log_me_dict.update(user_response)
	app.logger.info('log_me_dict: %s' % (log_me_dict,))
	return jsonify(user_response)


# ------------------------------------------------------- #


@app.before_first_request
def init():

	logHandler = RotatingFileHandler(ls.APP_LOG, maxBytes=1024)
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

# mkdir /var/data
# chown -R www-data /var/data

# ------------------------------------------------------- #

if __name__ == '__main__':
	app.run()
