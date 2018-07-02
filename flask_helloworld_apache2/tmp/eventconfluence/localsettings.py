import os

# ------------------ LOCALSETTINGS ---------------------- #

VUL_DOCKER_SERVICE = '172.17.0.2:7777'

# ------------------------------------------------------- #
TEST_CVSS_SCORE = 8
TEST_CVSS_THRESHOLD = 7
CVSS_IN_TIMEOUT_CASES = 10
TIMEOUT_IN_SECS = 2
SLEEP_TIME_SLICE = 0.2

RECEIVED_FROM_ISTIO = 'recieved from istio'
RECIEVED_WEBHOOK_TRIGGER = 'recieved nvm trigger from splunk webhook'
VUL_ASSESS_COMPLETE = 'vulnerability assessment done'
ALL_PROCESSING_DONE = 'processing complete'

WORKFLOW_STATES = { RECEIVED_FROM_ISTIO: 1, RECIEVED_WEBHOOK_TRIGGER: 2, VUL_ASSESS_COMPLETE: 3, ALL_PROCESSING_DONE: 4 }
WORKFLOW_STATES_VERBOSE = { 1: RECEIVED_FROM_ISTIO, 2: RECIEVED_WEBHOOK_TRIGGER, 3: VUL_ASSESS_COMPLETE, 4: ALL_PROCESSING_DONE }


PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))


LOG_DIR = '/var/log/istiopoc'
APP_LOG = os.path.join(LOG_DIR, 'applog.log')

INSERT_HEADER_NAME = 'x_is_enabled'

# ------------------ SQLITE3 ---------------------- #

DBSTORE = '/var/data/istiodemo.db'

# ------------------ SQL ---------------------- #

CREATE_SQL_EVENT_PROCESSOR = '''CREATE TABLE IF NOT EXISTS EVENT_PROCESSOR
			(ID INTEGER PRIMARY KEY, REMOTE_ADDR text, ua text, ph text, ts timestamp, vulassessment int, retrycount int, retry_timestamps text)'''

UPDATE_SQL_STATE = '''UPDATE EVENT_PROCESSOR
          SET state = ?
          WHERE ID = ?'''

UPDATE_SQL_IS_VA = '''UPDATE EVENT_PROCESSOR
          			  SET incomingstate = ?,
          			  vulassessment = ?
          			  WHERE ID = ?'''

SELECT_SQL_RA = 'SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=?'

INSERT_SQL_EP = "INSERT INTO EVENT_PROCESSOR(REMOTE_ADDR, ua, ph, ts, vulassessment, retrycount, retry_timestamps) values (?, ?, ?, ?, ?, ?, ?)"

# ------------------------------------------------------- #

TEST_DATA_PROCESS_HASHES = ["0830AF92B1959E2137B8E4B304266842AED1EA5B40735A5F0CA3792A3779D7C0",
                            "6BCAA2B71971433CFEEEA784A782C57E1A8AFC209BEEC285DCB037B20C9C0F35",
                            "C00B9F2B32828341A9185AE2BE1A0649C9F503F0B5CCCEBC75BE4C2F8C596530"]


# ------------------------------------------------------- #
