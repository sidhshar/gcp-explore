import sqlite3
import datetime

import localsettings as ls
# from singleton import Singleton

# class Singleton(type):
#     _instances = {}
#     def __call__(cls, *args, **kwargs):
#         if cls not in cls._instances:
#             cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
#         return cls._instances[cls]

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
		# create_query = '''CREATE TABLE IF NOT EXISTS EVENT_PROCESSOR
		# 	(ID INTEGER PRIMARY KEY, REMOTE_ADDR text, ua text, ph text, ts timestamp, vulassessment int, retrycount int, retry_timestamps text)'''
		self.execute_query_via_cursor(ls.CREATE_SQL_EVENT_PROCESSOR)
	def write_to_db(self, ip, ua, ph, ts, cvss, rcount, rts):
		now = datetime.datetime.now()
		# insert_query = "INSERT INTO EVENT_PROCESSOR(REMOTE_ADDR, ua, ph, ts, vulassessment, retrycount, retry_timestamps) values (?, ?, ?, ?, ?, ?, ?)"
		insert_values = (ip, ua, ph, ts, cvss, rcount, rts)
		self.execute_parameterised_query_via_cursor(ls.INSERT_SQL_EP, insert_values)
	def perform_select_on_ip(self, ip):
		selectvalues = (ip,)
		# select_query = 'SELECT * FROM EVENT_PROCESSOR WHERE REMOTE_ADDR=?'
		results = self.execute_parameterised_query_via_cursor_with_results(ls.SELECT_SQL_RA, selectvalues)
		return results
	def close(self):
		self.connection.close()

