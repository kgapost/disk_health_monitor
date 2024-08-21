import platform
import sys
import os
import string
import psutil
import subprocess
import socket
import time
import multiprocessing
import gc

#### parameters
PRINT_CMD_OUTPUT = True
ERROR_THRESHOLD = 0
EMAIL_SENDER = 'diskhealthstatusmonitor@gmail.com'
EMAIL_PASSWORD = 'annhmnqnubsosgad'
EMAIL_RECEIPIENTS = ['kapost@iti.gr']
RECHECK_INTERVAL = 24 * 3600 # 12 hours
TIME_OUT = 30 * 60 # 30 minutes - higher than 20 minutes recommended
SMART_CTL_TIME = 4 * 60

def main_proc():
	print('**********************************')
	print('*** Disk health status monitor ***')
	print('**********************************')
	print('\n')
	
	os_info = platform.system()
	version_info = platform.version()
	hostname_info = socket.gethostname()
	machine_info = platform.machine()

	print(' {')
	print('   os:', os_info)
	print('   version:', version_info)
	print('   machine:', machine_info)
	print('   hostname:', hostname_info)
	print('   ip:', get_ip())
	print(' }\n')
	
	print(' {')
	print('   ERROR_THRESHOLD:', ERROR_THRESHOLD)
	print('   EMAIL_SENDER:', EMAIL_SENDER)
	print('   EMAIL_RECEIPIENTS:', EMAIL_RECEIPIENTS)
	print('   RECHECK_INTERVAL:', RECHECK_INTERVAL)
	print('   TIME_OUT:', TIME_OUT)
	print(' }\n')
	
	if 'linux' in os_info.lower():
		print(' ---> Proceeding to analyze disk on Linux system...')
	elif 'windows' in os_info.lower():
		print(' ---> Proceeding to analyze disk on Windows system...')
	else:	
		print(' Unrecognized OS')	
		print(' Cannot continue...')
		sys.exit()
			
	# get list of drives
	print(' ~~~~ Getting list of drives...')
	drives_to_check = []
	if 'linux' in os_info.lower():
		drives = str(psutil.disk_partitions()).split('sdiskpart(')
		drives = [x.replace('),', '') for x in drives if not '/loop' in x]
		drives = drives[1:]
		for d in drives:
			pd = d.split("device='")[1].split("'")[0]
			drives_to_check.append(pd)
			print(' --->', pd,':', d)
			
	elif 'windows' in os_info.lower():
		import win32api
		from ctypes import windll

		drives = str(psutil.disk_partitions()).split('sdiskpart(')
		drives = [x.replace('),', '') for x in drives if not '/loop' in x]
		drives = drives[1:]
		for d in drives:
			pd = d.split("device='")[1].split("'")[0]
			drives_to_check.append(pd)
			print(' --->', pd,':', d)


	while True:
		print(' ~~~~ Starting tests in new process... (TIME_OUT=%d)'%TIME_OUT)
		check_proc = multiprocessing.Process(target=check_call_timed_proc, args=(drives_to_check,))
		check_proc.start()

		# Wait for TIME_OUT seconds or until process finishes
		check_proc.join(TIME_OUT)
		
		for i in range(3):
			print('..', end='')
			time.sleep(1)
		
		if check_proc.is_alive():
			print('\n')
			print(' check is stil running after TIME_OUT=%d seconds...' % TIME_OUT)
			print(' killing check process...')

			# Terminate - may not work if process is stuck for good
			#p.terminate()
			# OR Kill - will work for sure, no chance for process to finish nicely however
			check_proc.kill()
			check_proc.join()
			
			print(' sending check failure email to %s...' % str(EMAIL_RECEIPIENTS))
			fail_report = '~~~ %s ~~~\n\n'%construct_header() + \
				'WARNING: check process took more than %d seconds and was killed\n' % TIME_OUT
			send_email(fail_report)
			
		# collect garbage
		gc.collect()
		
		# sleep and wait RECHECK_INTERVAL seconds before re-checking 
		for i in range(RECHECK_INTERVAL):
			print('\r sleeping... (%5d/%5d)' % (i+1, RECHECK_INTERVAL), end='')
			time.sleep(1)
		print(' ')

		
def get_ip():
	s_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s_temp.connect(("8.8.8.8", 80))
	ip_info = str(s_temp.getsockname()[0])
	s_temp.close()
	return ip_info
	

def send_email(report):
	# importing here - quick fix (i'm not lazy)
	import smtplib
	from email.message import EmailMessage
	
	os_info = platform.system()
	version_info = platform.version()
	hostname_info = socket.gethostname()
			
	# create email
	msg = EmailMessage()
	msg['Subject'] = 'Disk health monitor ' + hostname_info + ' report'
	msg['From'] = EMAIL_SENDER
	msg['To'] = ', '.join(EMAIL_RECEIPIENTS)
	msg.set_content(report)


	with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
		smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
		smtp.send_message(msg)


def check_report(report, errs):
	print('')
	print(report)
	print('')
	
	if errs>=ERROR_THRESHOLD:
		print(' ', errs, ' is >= than ERROR_THRESHOLD (=', ERROR_THRESHOLD, ')', sep ='')
		print(' sending email to %s...' % str(EMAIL_RECEIPIENTS))
		send_email(report)
	else:
		print(errs, ' is lower than ERROR_THRESHOLD (', ERROR_THRESHOLD, ')', sep ='')


def execute(cmd):
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
	for stdout_line in iter(popen.stdout.readline, ""):
		yield stdout_line 
	for stdout_line in iter(popen.stderr.readline, ""):
		yield stdout_line 
	popen.stdout.close()
	return_code = popen.wait()
	if return_code and PRINT_CMD_OUTPUT:
		print(' (!!! calling last cmd returned "%s")' % str(return_code))


def construct_header():
	os_info = platform.system()
	hostname_info = socket.gethostname()
	return 'Report for ' + hostname_info + ' (' + get_ip() + ') (' + os_info + ')'


def construct_report(info, results, passed):
	errs_no = len(info) - sum(passed)
	report = ''
	report += ' ~~~ %s ~~~\n' % construct_header()
	report += ' Passed %d out of %d tests\n' % (sum(passed), len(info))
	report += ' ' + '-' * 100 + '\n'
	report += '   %3s %-52s: %-28s %s\n' % ('###', 'Test', 'Result', 'Passed?')
	for i in range(len(info)):
		report += '   %3d %-52s: %-28s (%d)\n' % (i+1, info[i], results[i], passed[i])
	report += " ~~~ End or report ~~~\n"
	return report, errs_no

## smartctl - a command line utility designed to :printing the SMART self-test and error logs, enabling/disabling SMART automatic testing, and initiating device self-tests.
## sudo apt-get update -y
## sudo apt install smartmontools
# sudo smartctl -t short /dev/
# sudo smartctl -i /dev/
# sudo smartctl -H /dev/
# sudo smartctl -A /dev/

## mdadm - tool to administer Linux MD arrays (software RAID)
## sudo apt-get update -y
## sudo apt-get install -y mdadm
# sudo mdadm --detail
def check_disk_linux(pdrc):
	info = []
	results = []
	passed = []
	
	# cmd = ["smartctl", "-s",  "on", pdrc]
	
	# perform short smarctl test
	cmd = ["smartctl", "-t", "short",  pdrc]
	try:
		print('	   ~~~~ Testing disk: %s (cmd=%s)...' % (pdrc,str(cmd)))
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().startswith('copyright'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")

		# smartctl short test takes about 2 minutes. Wait 3 minutes and then continue
		for i in range(SMART_CTL_TIME):
			n = i % 4
			dots_string = ''.join([char*n for char in '.'])
			print('\r	   ---> waiting for test to complete (%5d/%5d) %s	 ' % (i+1, SMART_CTL_TIME, dots_string), end='')
			time.sleep(1)
		print(' ')
	except Exception as e:
		print('	   !--> smartctl short test failed!')
		print('(' + str(e) + ')')
		info.append(pdrc + ': ' + 'smartctl short test')
		results.append('failed')
		passed.append(0)
		
	# check smartctl results
	cmd = ["smartctl", "-i",  pdrc]
	try:
		print('	   ~~~~ checking disk info (cmd=%s)...' % (str(cmd)))
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().startswith('copyright'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if 'smart support' in msg.lower():
				status1 = msg.split(':')[1].strip()
				info.append(pdrc + ': ' + msg.lower().split(':')[0].strip() )
				results.append(status1.lower().replace('device has smart capability','').strip().replace('.','').strip().replace('-','').strip())
				if 'enabled' in status1.lower() or 'device has smart' in status1.lower():
					passed.append(1)
				else:
					passed.append(0)
	except Exception as e:
		print('	   !--> smartctl info parse failed!')
		print('(' + str(e) + ')')
		info.append(pdrc + ': ' + 'smartctl info parse')
		results.append('failed')
		passed.append(0)
		
		
	cmd = ["smartctl", "-H",  pdrc]
	try:
		print('	   ~~~~ checking health status (cmd=%s)...' % (str(cmd)))
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().startswith('copyright'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if 'smart overall-health self-assessment test result: ' in msg.lower():
				status2 = msg.split(':')[1].strip()
				results.append(status2)
				info.append(pdrc + ': ' + msg.lower().split(':')[0].strip().replace('test','').strip().replace('smart','').strip().replace('result','').strip())
				if 'passed' in status2.lower():
					passed.append(1)
				else:
					passed.append(0)
	except Exception as e:
		print('	   !--> smartctl health parse failed!')
		print('(' + str(e) + ')')
		info.append(pdrc + ': ' + 'smartctl health')
		results.append('failed')
		passed.append(0)


	cmd = ["smartctl", "-a",  pdrc]
	try:
		print('	   ~~~~ checking report (cmd=%s)...' % (str(cmd)))
		started_parsing = 0
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().startswith('copyright'):
				continue
			if 'attributes with thresholds' in msg.lower():
				started_parsing = 1
			if 'drive failure expected' in msg.lower():
				info.append(pdrc + ': ' + 'drive failure expected')
				results.append(msg.split('expected')[1])
				passed.append(0)
			if started_parsing and 'error log version: ' in msg.lower():
				started_parsing = 0
			if started_parsing and 'FLAG' in msg:
				h = msg.split(' ')
				hf = [x.strip().lower() for x in h if len(x.strip())>0]
			if started_parsing and '0x00' in msg:
				c = msg.split(' ')
				cf = [x.strip() for x in c if len(x.strip())>0]
				name = cf[hf.index('attribute_name')]
				val = float(cf[hf.index('value')])
				worst = float(cf[hf.index('worst')])
				thresh = float(cf[hf.index('thresh')])

				info.append(pdrc + ': ' + name.strip()+' val')
				results.append(str(int(val))+'/'+str(int(thresh)))
				if val>thresh:
					passed.append(1)
				else:
					passed.append(0)

				info.append(pdrc + ': ' + name.strip()+' worst')
				results.append(str(int(worst))+'/'+str(int(thresh)))
				if worst>thresh:
					passed.append(1)
				else:
					passed.append(0)
	except Exception as e:
		print('	   !--> smartctl all parse failed!')
		print('(' + str(e) + ')')
		info.append(pdrc + ': ' + 'smartctl all')
		results.append('failed')
		passed.append(0)
		
		
	if len(info)<5:
		info.append(pdrc + ': ' + 'very few tests completed')
		results.append('warning')
		passed.append(0)


	return info, results, passed

## diskdrive
# wmic diskdrive get status
## MSStorageDriver_FailurePredictStatus
# wmic /namespace:\\root\wmi path MSStorageDriver_FailurePredictStatus
## powershell.exe Get-PhysicalDisk | Format-Table -AutoSize
## chkdsk
## diskpart

def check_disk_win(pdrcs):
	info = []
	results = []
	passed = []
	
	cmd = ["wmic", "diskdrive", "get",  "status"]
	try:
		print('	   ~~~~ Checking diskdrive status (cmd=%s)...' % (str(cmd)))
		passed_current = False
		info_current = ''
		saved_msg = ''
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if msg.strip().lower() == "status":
				passed_current = True
			if msg.strip().lower() == "ok":
				passed_current = True
				saved_msg = msg.strip()
			info_current += msg.strip() + ' '
		info.append("wmic diskdrive get status")
		results.append(saved_msg)
		passed.append(int(passed_current))
	except Exception as e:
		print('	   !--> diskdrive status parse failed!')
		print('(' + str(e) + ')')
		info.append('diskdrive status')
		results.append('failed')
		passed.append(0)
		
		
	cmd = ["wmic", "/namespace:\\\\root\\wmi", "path", "MSStorageDriver_FailurePredictStatus"]
	try:
		print('	   ~~~~ checking "FailurePredictStatus" (cmd=%s)...' % (str(cmd)))
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().strip().startswith('copyright'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if 'smart support' in msg.lower():
				status1 = msg.split(':')[1].strip()
				info.append(msg.split(':')[0].strip())
				results.append(status1)


				if 'enabled' in status1.lower() or 'device has smart' in status1.lower():
					passed.append(1)
				else:
					passed.append(0)
	except Exception as e:
		print('	   !--> FailurePredictStatus parse failed!')
		print('(' + str(e) + ')')
		info.append('FailurePredictStatus parse')
		results.append('failed')
		passed.append(0)



	cmd = ["powershell.exe", "Get-PhysicalDisk", "|",  "Format-Table", "-AutoSize"]
	try:
		print('	   ~~~~ checking "OperationalStatus" (cmd=%s)...' % (str(cmd)))
		can_process = False
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().strip().startswith('copyright'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if 'number' in msg.lower():
				h = msg
			if can_process:
				i1 = h.index('OperationalStatus')
				info.append('OperationalStatus')
				results.append(msg[i1:].split(' ')[0].strip())
				if 'OK' in results[-1]:
					passed.append(1)
				else:
					passed.append(0)

				i1 = h.index('HealthStatus')
				info.append('HealthStatus')
				results.append(msg[i1:].split(' ')[0].strip())
				if 'Healthy' in results[-1]:
					passed.append(1)
				else:
					passed.append(0)
			if msg.startswith('-----'):
				can_process = True
	except Exception as e:
		print('	   !--> OperationalStatus parse failed!')
		print('(' + str(e) + ')')
		info.append('OperationalStatus parse')
		results.append('failed')
		passed.append(0)

	for pdrc in pdrcs:
		cmd = ["chkdsk", pdrc.replace('\\','')]
		print('	   ~~~~ checking disk %s with "chkdsk" (cmd=%s)...' % (pdrc,str(cmd)))
		try:
			for msg in execute(cmd):
				if not msg.strip():
					continue
				if msg.lower().strip().startswith('copyright'):
					continue
				if msg.lower().strip().startswith('progress'):
					continue
				if msg.lower().strip().startswith('The type of the file system'):
					continue
				if msg.lower().strip().startswith('stage'):
					continue
				if msg.lower().strip().startswith('running'):
					continue
				if 'parameter not specified' in msg:
					continue

				if 'windows has scanned the file system' in msg.lower():
					info.append(pdrc + ': ' + 'chkdsk result')
					if 'found no problems' in msg.lower():
						passed.append(1)
						results.append('found no problems')
					else:
						passed.append(0)
						results.append('errors')

				if 'in bad sectors' in msg.lower():
					info.append(pdrc + ': ' + 'bad sectors')
					results.append(msg.replace('in bad sectors.', '').strip().lower())
					if '0 kb' in msg.lower():
						passed.append(1)
					else:
						passed.append(0)
		except Exception as e:
			print('	   !--> chkdsk on', pdrc, 'failed!')
			print('(' + str(e) + ')')
			info.append(pdrc + ': ' + 'chkdsk')
			results.append('failed')
			passed.append(0)

	try:
		with open('dp_script.txt', 'w') as fp:
			fp.write('list volume')
	except Exception as e:
		print('	   !--> diskpart parsing failed!')
		print('(' + str(e) + ')')
		info.append('diskpart script')
		results.append('failed')
		passed.append(0)
		
	cmd = ["diskpart", "/s",  "dp_script.txt"]
	try:
		print('	   ~~~~ checking diskpart report (cmd=%s)...' % (str(cmd)))
		can_process = False
		for msg in execute(cmd):
			if not msg.strip():
				continue
			if msg.lower().strip().startswith('copyright'):
				continue
			if msg.lower().strip().startswith('microsoft'):
				continue
			if msg.lower().strip().startswith('on computer'):
				continue
			if PRINT_CMD_OUTPUT:
				print(msg, end="")
			if ('volume' in msg.lower()) and not can_process:
				h = msg.lower().strip()
			if can_process:
				i1 = h.index('status')
				i2 = h.index('ltr')
				i3 = h.index('info')
				disk_type = msg[i3:].strip().split(' ')[0].strip().lower()
				if 'system' in disk_type:
					continue
				if 'hidden' in disk_type:
					continue
				msg = msg.strip()

				info.append('Status of '+msg[i2:].strip().split(' ')[0].strip())
				results.append(msg[i1:].split(' ')[0])
				if 'healthy' in results[-1].lower():
					passed.append(1)
				else:
					passed.append(0)
			if msg.strip().startswith('---'):
				can_process = True
	except Exception as e:
		print('	   !--> diskpart parsing failed!')
		print('(' + str(e) + ')')
		info.append('diskpart')
		results.append('failed')
		passed.append(0)
			
	
	return info, results, passed

# sudo mdadm --detail
def check_call_timed_proc(drives_to_check):
	os_info = platform.system()
	info = []
	results = []
	passed = []
	

	if 'linux' in os_info.lower():
		for pd in drives_to_check:
			info_temp = []
			results_temp = []
			passed_temp = []
			
			cmd = ["mdadm", "--detail", pd]
			raid_devices = []
			print('    ~~~~ RAID status for disk: %s (cmd=%s)...' % (pd,str(cmd)))
			line_no = 0
			for msg in execute(cmd):
				if PRINT_CMD_OUTPUT:
					print(msg, end="")
				line_no+=1
				if line_no>5:
					if '/dev/' in msg:
						raid_devices.append('/dev/' + msg.split('/dev/')[1].strip())
			print('    ---> RAID devices found:', raid_devices)
				
			if len(raid_devices)==0:
				print('       > Checking non-RAID disk', pd, '::')
				info_temp, results_temp, passed_temp = check_disk_linux(pd)
			else:
				for pdrc in raid_devices:
					print('       > Checking RAID disk', pdrc, 'of', pd, '::')
					info_temp, results_temp, passed_temp = check_disk_linux(pdrc)

			info += info_temp
			results += results_temp
			passed += passed_temp

	elif 'windows' in os_info.lower():
		info, results, passed  = check_disk_win(drives_to_check)
		
	report, errs_no = construct_report(info, results, passed)
	check_report(report,errs_no)


if __name__ == '__main__':
	multiprocessing.freeze_support()
	time.sleep(1)
	main_proc()




# end
