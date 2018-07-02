

@app.route('/performvulassessment', methods=['POST'])
def performvulnerabilityassessment():

        app.logger.info('/performvulassessment request.headers: %s' % (request.headers,))

        # Get the User Agent
        #custom_header = request.headers.get(ls.HEADER_OF_INTEREST)
        user_response = {}
        user_response['result'] = {}
        user_response['request'] = {}
        #user_response['request'][ls.HEADER_OF_INTEREST] = custom_header

        request_json = request.json
        #request_data = json.loads(request.data)
        app.logger.info('request.json: %s    ' % (request_json,))

        # Get the Remote Address
        #remote_addr = request.headers['X-Initiator-Remote-Addr-1'].split(',')[0]
        #intiator_ua = request.headers['X-Initiator-Ua']
        remote_addrs = request_json['X-Initiator-Remote-Addr-1']
        remote_addr = remote_addrs.split(',')[0]
        intiator_ua = request_json['X-Initiator-Ua']
        user_response['request']['remote_address'] = remote_addr
        user_response['request']['X-Initiator-Ua'] = intiator_ua

        #step1_response = invoke_step1(remote_addr, intiator_ua)
        step1_response = { ls.INSERT_HEADER_NAME: True }
        #user_response['result']['step1_response'] = step1_response
        user_response['result'].update(step1_response)

        print 'user_response: ',user_response

        return jsonify(user_response)
