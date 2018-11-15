import logging.handlers
from apscheduler.schedulers.blocking import BlockingScheduler

from mgr import UserMgr, HostMgr

handler = logging.handlers.RotatingFileHandler('log/ssrmgr.log', maxBytes=5*1024*1024, backupCount=5)

logging.basicConfig(
    format='[%(asctime)s-%(filename)s-%(levelname)s:%(message)s]',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %I:%M:%S %p',
    handlers=(handler,)
)

sched = BlockingScheduler()


@sched.scheduled_job("cron", minute="*")
def sync_user():
    """同步用户"""
    um = UserMgr()
    um.update_user()


@sched.scheduled_job("cron", day="*")
def send_user_usage():
    """发送用户流量记录"""
    um = UserMgr()
    um.send_data_usage()


@sched.scheduled_job("cron", day="*")
def send_host_usage():
    """发送主机流量记录"""
    hm = HostMgr()
    hm.send_data_usage()


@sched.scheduled_job("cron", minute="*")
def report_status():
    """上报主机状态"""
    hm = HostMgr()
    hm.report_status()


if __name__ == '__main__':
    sched.start()
