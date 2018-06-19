import os

# ------------------ LOCALSETTINGS ---------------------- #
TEST_CVSS_SCORE = 8
TEST_CVSS_THRESHOLD = 7
TIMEOUT_IN_SECS = 5
SLEEP_TIME_SLICE = 0.5

RECEIVED_FROM_ISTIO = 'recieved from istio'
RECIEVED_WEBHOOK_TRIGGER = 'recieved nvm trigger from splunk webhook'
VUL_ASSESS_COMPLETE = 'vulnerability assessment done'
ALL_PROCESSING_DONE = 'processing complete'

WORKFLOW_STATES = { RECEIVED_FROM_ISTIO: 1, RECIEVED_WEBHOOK_TRIGGER: 2, VUL_ASSESS_COMPLETE: 3, ALL_PROCESSING_DONE: 4 }
WORKFLOW_STATES_VERBOSE = { 1: RECEIVED_FROM_ISTIO, 2: RECIEVED_WEBHOOK_TRIGGER, 3: VUL_ASSESS_COMPLETE, 4: ALL_PROCESSING_DONE }


PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))


LOG_DIR = os.path.expanduser('/var/log/istiopoc')
VT_JSON_STORE = os.path.join(LOG_DIR, 'json_store_vt')
SPLUNK_JSON_STORE = os.path.join(LOG_DIR, 'json_store_splunk')

# ------------------ LOCALSETTINGS ---------------------- #

HEADER_OF_INTEREST = 'User-Agent'
INSERT_HEADER_NAME = 'x_is_enabled'
# CUSTOM_HEADER_STATE_ON = True
# CUSTOM_HEADER_STATE_OFF = False
# WAIT_TIME_IN_SECONDS = 20
# SLEEP_TIME_SLICE = 0.5
# CVSS_THRESHOLD_FOR_REJECTION = 7
# SAMPLE_CVSS_VALUE = 8

# VT_URL = 'https://www.virustotal.com/ui/search?query=%s'
# VT_CALL_ENABLE = False
# TEST_FLAG_STATE = True
# VT_TEST_DATA = {'file_version': '47.0.2526.111', 'file_description': 'Google Chrome'}


# ------------------ SQLITE3 ---------------------- #

DBSTORE = os.path.join(PROJECT_ROOT, 'istiodemo.db')

# ------------------ SQL ---------------------- #

UPDATE_SQL_STATE = '''UPDATE EVENT_PROCESSOR
          SET state = ?
          WHERE ID = ?'''


UPDATE_SQL_IS_VA = '''UPDATE EVENT_PROCESSOR
          			  SET incomingstate = ?,
          			  vulassessment = ?
          			  WHERE ID = ?'''

# ------------------------------------------------------- #

