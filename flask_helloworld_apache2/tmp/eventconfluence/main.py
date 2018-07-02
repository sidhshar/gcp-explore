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

#from workflow_handler import invoke_istio_integration, invoke_step2
from istio_integration import invoke_istio_integration
from splunk_integration import invoke_step2, get_ph_from_splunk_event

app = Flask(__name__)



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

	step1_response = invoke_istio_integration(remote_addr, intiator_ua)

	user_response['result'] = step1_response

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

@app.route('/syslogcollection', methods=['POST'])
def syslogcollection():
    user_response = {}

    request_json = request.json
    process_hash = request_json['process_hash']
    source_address = request_json['source_address']

    user_response['ph'] = process_hash
    user_response['sa'] = source_address

    return jsonify(user_response)

# ------------------------------------------------------- #

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

if __name__ == '__main__':
	app.run()
