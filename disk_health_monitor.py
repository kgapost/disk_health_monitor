import platform
import sys
import os
import psutil
import subprocess
import socket
import time
import multiprocessing
import gc
import smtplib
from email.message import EmailMessage
import logging
import ctypes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PRINT_CMD_OUTPUT = True
EMAIL_SENDER = 'diskhealthstatusmonitor@gmail.com'
EMAIL_PASSWORD = 'annhmnqnubsosgad'
EMAIL_RECIPIENTS = ['kapost@iti.gr']
CHECK_INTERVAL_SEC = 48 * 3600  # 48 hours
TOTAL_TIME_OUT_SEC = 60 * 60  #  60 minutes
SMART_CTL_WAIT_TIME_SEC = 5 * 60  # smartctl typically takes 2 minutes for a 1TB HDD


def check_admin_privileges(os_info):
    try:
        if 'windows' in os_info:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0

        if is_admin:
            logging.info('Administrative privileges detected')
        else:
            logging.error('!!! Administrative privileges are required to run this script.')
            sys.exit(1)
                    
    except Exception as e:
        logging.error(f'!!! Error checking administrative privileges: {e}')
        sys.exit(1)

		
def get_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_temp:
            s_temp.connect(("8.8.8.8", 80))
            ip_info = s_temp.getsockname()[0]
        return ip_info
    except Exception as e:
        logging.error(f'!!! Failed to get IP address: {e}')
        return 'Unknown'


def send_email(report):
    try:
        msg = EmailMessage()
        msg['Subject'] = f'Disk Health Monitor Report for {socket.gethostname()}'
        msg['From'] = EMAIL_SENDER
        msg['To'] = ', '.join(EMAIL_RECIPIENTS)
        msg.set_content(report)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        logging.info('Email sent successfully.')
    except Exception as e:
        logging.error(f'!!! Failed to send email: {e}')


def execute(cmd):
    try:
        logging.info(f'   (executing {cmd})')
        print('   ')
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as popen:
            for stdout_line in iter(popen.stdout.readline, ""):
                print(stdout_line, end='')
                yield stdout_line
            for stderr_line in iter(popen.stderr.readline, ""):
                print(stderr_line, end='')
                yield stderr_line
        return_code = popen.wait()
        print('   ')
        if PRINT_CMD_OUTPUT:
            logging.info(f'Command returned {return_code}')
    except Exception as e:
        logging.error(f'!!! Error executing command {cmd}: {e}')


def is_relevant_partition(partition):
    try:
        partition_info = psutil.disk_partitions(all=True)
        for p in partition_info:
            if p.device == partition:
                if any(kw in p.mountpoint for kw in ['/boot', '/efi']):
                    return True
                if p.fstype in ['swap', 'efi']:
                    return True

                cmd = ["lsblk", "-no", "TYPE", partition]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.stdout.strip() in ['part', 'rom']:
                    return True

        return False
    except Exception as e:
        logging.error(f'!!! Failed to check if partition is relevant: {e}')
        return True


def get_drives_to_check_main(os_info):
    drives_to_check = []
    try:
        if 'linux' in os_info:
            block_devices = [os.path.join('/sys/block', d) for d in os.listdir('/sys/block')]
            for device in block_devices:
                device_name = os.path.basename(device)
                if not any(substring in device_name for substring in ['loop', 'ram', 'sr']):
                    partitions = [f"/dev/{p}" for p in os.listdir(f'/sys/block/{device_name}') if p.startswith(device_name)]
                    for partition in partitions:
                        if is_relevant_partition(partition):
                            drives_to_check.append(partition)

        elif 'windows' in os_info:
            cmd = ["wmic", "logicaldisk", "where", "drivetype=3", "get", "deviceid, volumename, description"]
            for line in execute(cmd):
                if "DeviceID" in line or not line.strip():
                    continue
                drive = line.strip().split()[0]
                drives_to_check.append(drive)

        else:
            logging.error(f'!!! Unsupported OS: {os_info}')

    except Exception as e:
        logging.error(f'!!! Failed to get drives with get_drives_to_check_main: {e}')

    return drives_to_check


def get_drives_to_check_alt(os_info):
    drives_to_check = []
    try:
        partitions = psutil.disk_partitions()
        if 'linux' in os_info:
            drives = [p.device for p in partitions if 'loop' not in p.device]
        elif 'windows' in os_info:
            drives = [p.device for p in partitions]
        else:
            drives = []

        drives_to_check.extend(drives)
    except Exception as e:
        logging.error(f'!!! Failed to get drives with get_drives_to_check_alt: {e}')

    return drives_to_check


def perform_disk_checks(drives_to_check):
    os_info = platform.system().lower()
    info, results, passed = [], [], []

    try:
        if 'linux' in os_info:
            for drive in drives_to_check:
                raid_devices = check_raid_linux(drive)
                if not raid_devices:
                    logging.info(f'Checking non-RAID disk: {drive}')
                    info_temp, results_temp, passed_temp = check_disk_linux(drive)
                else:
                    for raid_device in raid_devices:
                        logging.info(f'Checking RAID disk: {raid_device} of {drive}')
                        info_temp, results_temp, passed_temp = check_disk_linux(raid_device)
                info.extend(info_temp)
                results.extend(results_temp)
                passed.extend(passed_temp)
        elif 'windows' in os_info:
            for drive in drives_to_check:
                info_temp, results_temp, passed_temp = check_disk_win(drive)
                info.extend(info_temp)
                results.extend(results_temp)
                passed.extend(passed_temp)
    except Exception as e:
        logging.error(f'!!! Error in disk check process: {e}')

    return info, results, passed


def check_raid_linux(drive):
    raid_devices = []
    try:
        cmd = ["mdadm", "--detail", drive]
        logging.info(f'Checking RAID status for disk: {drive}')
        for msg in execute(cmd):
            if '/dev/' in msg and 'not' not in msg:
                raid_devices.append(f"/dev/{msg.split('/dev/')[1].strip()}")
    except Exception as e:
        logging.error(f'!!! Failed to check RAID status: {e}')

    logging.info(f'RAID devices found: {raid_devices}')
    return raid_devices

def check_disk_linux(drive):
    info, results, passed = [], [], []
    try:
        logging.info(f'Testing disk: {drive}')
        if not run_smartctl_short_test(drive):
            logging.error(f'!!! smartctl short test failed for {drive}')
            return info, results, passed

        info_temp, results_temp, passed_temp = parse_smartctl_results(drive)
        info.extend(info_temp)
        results.extend(results_temp)
        passed.extend(passed_temp)
    except Exception as e:
        logging.error(f'!!! Failed to check disk {drive}: {e}')

    return info, results, passed


def run_smartctl_short_test(drive):
    try:
        # cmd = ["smartctl", "-X", drive]
        # for _ in execute(cmd):
        #     pass
        cmd = ["smartctl", "-t", "short", drive]
        for _ in execute(cmd):
            pass
        countdown(SMART_CTL_WAIT_TIME_SEC, f'Waiting for smartctl test on {drive}')
        return True
    except Exception as e:
        logging.error(f'!!! Failed to run smartctl short test: {e}')
        return False


def parse_smartctl_results(drive):
    info, results, passed = [], [], []

    try:
        cmd_info = ["smartctl", "-i", drive]
        logging.info(f'Checking smartctl info for {drive}')
        info.extend(list(execute(cmd_info)))

        cmd_health = ["smartctl", "-H", drive]
        logging.info(f'Checking smartctl health for {drive}')
        results.extend(list(execute(cmd_health)))

        cmd_attributes = ["smartctl", "-A", drive]
        logging.info(f'Checking smartctl attributes for {drive}')
        results.extend(list(execute(cmd_attributes)))

        passed.append("PASSED" in "".join(results))
    except Exception as e:
        logging.error(f'!!! Failed to parse smartctl results for {drive}: {e}')

    return info, results, passed


def check_disk_win(drive):
    info, results, passed = [], [], []

    try:
        logging.info(f'Testing disk: {drive}')
        cmd_info = ["wmic", "diskdrive", "get", "status"]
        cmd_check = ["chkdsk", drive]
        cmd_health = ["wmic", "diskdrive", "get", "predictfailure"]

        info.extend(list(execute(cmd_info)))
        results.extend(list(execute(cmd_check)))
        health_results = list(execute(cmd_health))
        results.extend(health_results)

        passed.append("OK" in "".join(health_results))
    except Exception as e:
        logging.error(f'!!! Failed to check Windows disk {drive}: {e}')

    return info, results, passed


def countdown(seconds, message):
    try:
        while seconds > 0:
            minutes, secs = divmod(seconds, 60)
            timeformat = f'{minutes:02d}:{secs:02d}'
            print(f"{message}: {timeformat}", end="\r")
            time.sleep(1)
            seconds -= 1
    except Exception as e:
        logging.error(f'!!! Error in countdown: {e}')


def main_proc():
    try:
        os_info = platform.system().lower()
        version_info = platform.version()
        hostname_info = socket.gethostname()
        machine_info = platform.machine()
        ip_address = get_ip()

        logging.info('System Info:')
        logging.info(f' - OS: {os_info}')
        logging.info(f' - OS Version: {version_info}')
        logging.info(f' - Hostname: {hostname_info}')
        logging.info(f' - Machine: {machine_info}')
        logging.info(f' - IP: {ip_address}')
        
        logging.info('Checking admin privileges')
        check_admin_privileges(os_info)

        drives_to_check = get_drives_to_check_main(os_info)
        if not drives_to_check:
            logging.error('No drives found with get_drives_to_check_main, attempting with get_drives_to_check_alt...')
            drives_to_check = get_drives_to_check_alt(os_info)
        if not drives_to_check:
            logging.error('No drives found to check, exiting...')
            sys.exit(1)
            
        logging.info('Drives found:')
        for drive in drives_to_check:
            logging.info(f' - {drive}')

        logging.info('perform_disk_checks::')
        info, results, passed = perform_disk_checks(drives_to_check)

		report = "\n".join(info + results)
		send_email(report)


    except Exception as e:
        logging.error(f'!!! Error in main process: {e}')
        sys.exit(1)
    finally:
        logging.info('Cleaning up resources...')
        gc.collect()

		
def monitor_disk_health():
    while True:
        process = multiprocessing.Process(target=main_proc)
        process.start()

        start_time = time.time()
        while process.is_alive():
            remaining_time = TOTAL_TIME_OUT_SEC - (time.time() - start_time)
            if remaining_time <= 0:
                process.terminate()
                process.join()
                logging.error('!!! Process timed out.')
                send_email('The disk health check process has timed out.')
                break

            time.sleep(10)  # FIX: Sleep a bit to avoid busy-waiting

        process.join()
        logging.info(f'Waiting {CHECK_INTERVAL_SEC} seconds before next check...')
        countdown(CHECK_INTERVAL_SEC, "Time until next check")
        time.sleep(CHECK_INTERVAL_SEC)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    monitor_disk_health()
