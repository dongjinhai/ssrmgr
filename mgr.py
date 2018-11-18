import json
import config
import psutil
import requests
import logging
from datetime import date, timedelta
from subprocess import Popen, PIPE, call
from mytoken import token
from datetime import datetime


class JsonLoader(object):
    def __init__(self):
        self.json = None

    def load(self, path):
        l = "{}"
        try:
            with open(path, 'rb+') as f:
                l = f.read().decode('utf8')
        except:
            pass
        self.json = json.loads(l)

    def save(self, path):
        if self.json is not None:
            output = json.dumps(self.json, sort_keys=True, indent=4, separators=(',', ': '))
            with open(path, 'a'):
                pass
            with open(path, 'rb+') as f:
                f.write(output.encode('utf8'))
                f.truncate()


class MuJsonLoader(JsonLoader):

    def load(self, path):
        l = "[]"
        try:
            with open(path, 'rb+') as f:
                l = f.read().decode('utf8')
        except:
            pass
        self.json = json.loads(l)


class MuMgr(object):
    def __init__(self):
        self.config_path = config.MUDB_FILE
        self.data = MuJsonLoader()

    def add(self, user):
        up = {
            'enable': 1,
            'u': 0,
            'd': 0,
            'method': "aes-128-ctr",
            'protocol': "auth_aes128_md5",
            'obfs': "tls1.2_ticket_auth_compatible",
            'transfer_enable': 9007199254740992,
            "forbidden_port": "",
            "speed_limit_per_user": 0,
            "speed_limit_per_con": 0,
            "protocol_param": "",
        }
        up.update(user)
        self.data.load(self.config_path)
        for row in self.data.json:
            match = False
            if 'user' in user and row['user'] == user['user']:
                match = True
            if 'port' in user and row['port'] == user['port']:
                match = True
            if match:
                return
        self.data.json.append(up)
        self.data.save(self.config_path)

    def edit(self, user):
        self.data.load(self.config_path)
        for row in self.data.json:
            match = True
            if 'user' in user and row['user'] != user['user']:
                match = False
            if 'port' in user and row['port'] != user['port']:
                match = False
            if match:
                row.update(user)
                break
        self.data.save(self.config_path)

    def delete(self, user):
        self.data.load(self.config_path)
        index = 0
        for row in self.data.json:
            match = True
            if 'user' in user and row['user'] != user['user']:
                match = False
            if 'port' in user and row['port'] != user['port']:
                match = False
            if match:
                del self.data.json[index]
                break
            index += 1
        self.data.save(self.config_path)

    def exist_port(self):
        self.data.load(self.config_path)
        ports = []
        for row in self.data.json:
            ports.append(row['port'])
        return ports


# 服务器管理
class HostMgr(object):
    def __init__(self):
        pass

    def save_aptables(self):
        save = "iptables-save > /etc/iptables.up.rules && ip6tables-save > /etc/ip6tables.up.rules"
        call(save, shell=True)

    def add_iptables(self, port):
        v4_cmd_tcp = "iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport {} -j ACCEPT".format(port)
        v4_cmd_udp = "iptables -I INPUT -m state --state NEW -m udp -p udp --dport {} -j ACCEPT".format(port)
        v6_cmd_tcp = "ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport {} -j ACCEPT".format(port)
        v6_cmd_udp = "ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport {} -j ACCEPT".format(port)
        cmd = "{} && {} && {} && {}".format(v4_cmd_tcp, v4_cmd_udp, v6_cmd_tcp, v6_cmd_udp)
        call(cmd, shell=True)
        self.save_aptables()

    def delete_iptables(self, port):
        v4_cmd_tcp = "iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport {} -j ACCEPT".format(port)
        v4_cmd_udp = "iptables -D INPUT -m state --state NEW -m udp -p udp --dport {} -j ACCEPT".format(port)
        v6_cmd_tcp = "ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport {} -j ACCEPT".format(port)
        v6_cmd_udp = "ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport {} -j ACCEPT".format(port)
        cmd = "{} && {} && {} && {}".format(v4_cmd_tcp, v4_cmd_udp, v6_cmd_tcp, v6_cmd_udp)
        call(cmd, shell=True)
        self.save_aptables()

    def is_online(self):
        """判断node是否在线
        """
        p = Popen(['pgrep', '-f', 'python /usr/local/shadowsocksr/server.py'], stdin=PIPE, stdout=PIPE)
        p.wait()
        out = p.stdout.read()
        if out:
            return True
        else:
            return False

    def port_con_ips(self, port):
        """获得端口上连接的IP
        :return ip的set集合
        """
        ips = set()
        net_connections = psutil.net_connections()
        for key in net_connections:
            if key.laddr[1] == port and key.status == 'ESTABLISHED':
                ips.add(key.raddr[0].replace("::ffff:", ""))
        return list(ips)

    def record_data_usage(self, ifname='eth0'):
        usage = {}
        today = date.today()
        yesterday = today - timedelta(days=1)
        jloader = JsonLoader()
        jloader.load(config.HOST_DATA_FILE)

        if ifname:
            bytes_recv = psutil.net_io_counters(pernic=True).get(ifname).bytes_recv
            # bytes_recv = 109
            bytes_sent = psutil.net_io_counters(pernic=True).get(ifname).bytes_sent
            # bytes_sent = 98
        else:
            bytes_recv = 0
            bytes_sent = 0

        node_id = str(config.NODE_ID)
        if node_id in jloader.json:
            host_data = jloader.json[node_id]
            if host_data['date'] == str(yesterday):
                val = {
                    'sent': bytes_sent - host_data['data']['sent'],
                    'recv': bytes_recv - host_data['data']['recv'],
                }
                usage.setdefault(node_id, val)
            else:
                val = {
                    'sent': 0,
                    'recv': 0,
                }
                usage.setdefault(node_id, val)
            host_data['data']['sent'] = bytes_sent
            host_data['data']['recv'] = bytes_recv
            host_data['date'] = str(today)
        else:
            val = {
                'date': str(today),
                'data': {
                    'sent': bytes_sent,
                    'recv': bytes_recv,
                }
            }
            jloader.json.setdefault(node_id, val)
            usage.setdefault(node_id, {'sent': 0, 'recv': 0})

        # 将主机流量保存下来，必备下次比较
        jloader.save(config.HOST_DATA_FILE)
        return usage

    def send_data_usage(self):
        usage = self.record_data_usage()
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token.token,
        }
        rest = requests.post(r"{}/api/node/transfer/".format(config.WEBAPI_DOMAIN),
                             headers=headers,
                             data=json.dumps(usage),
                             timeout=1)

        logging.info("上报主机流量结果，HTTP状态码：{}".format(rest.status_code))

    def status(self):
        stat = {
            'node_id': config.NODE_ID,
            'is_online': self.is_online(),
            # 'is_online': True,
        }
        mur = MuMgr()
        ports = mur.exist_port()
        val = {}
        for port in ports:
            ips = self.port_con_ips(port)
            val.setdefault(str(port), ips)
        stat.setdefault('port', val)

        return stat

    def report_status(self):
        stat = self.status()
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token.token,
        }
        rest = requests.post(r"{}/api/node/status/".format(config.WEBAPI_DOMAIN),
                             headers=headers,
                             data=json.dumps(stat),
                             timeout=10)
        logging.info("上报主机状态结果，HTTP状态码:{}".format(rest.status_code))


class UserMgr(object):
    def __init__(self):
        pass

    def remote_user(self):
        """获取远端用户列表"""
        payload = {'node_id': config.NODE_ID, }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token.token,
        }
        remote_users = []
        try:
            rest = requests.get(r"{}/api/user/".format(config.WEBAPI_DOMAIN),
                                params=payload,
                                headers=headers,
                                timeout=1)
            remote_users = rest.json()
            remote_users = remote_users["ssrs"]
        except Exception as e:
            logging.error("请求用户列表出错{}".format(e))
        return remote_users

    def update_user(self):
        r_users = self.remote_user()
        now = datetime.now()
        mur = MuMgr()
        exist_port = mur.exist_port()
        for user in r_users:
            # 当用户过期，则删除用户
            if (datetime.strptime(user['expiration_time'].replace('T', " "), "%Y-%m-%d %H:%M:%S.%f")
                    < now):
                mur = MuMgr()
                mur.delete(user)
                # 删除iptables规则
                hm = HostMgr()
                hm.delete_iptables(user['port'])
            else:
                user = self.verify_user(user)
                # 当用户已存在就直接修改用户
                if 'port' in user and user['port'] in exist_port:
                    mur = MuMgr()
                    mur.edit(user)
                # 当用户不存在就直接添加用户
                if 'port' in user and user['port'] not in exist_port:
                    mur = MuMgr()
                    mur.add(user)
                    # 添加iptables规则
                    hm = HostMgr()
                    hm.add_iptables(user['port'])

    def verify_user(self, user):
        """校验User
        检查一个user是否符合合法的user结构，如果出现非法的key就删除这个key。
        :param user: dict类型，用户类型
        :return: dict
        """
        valid_keys = ['d', 'u', 'enable', 'forbidden_port', 'method', 'obfs', 'passwd', 'port', 'protocol',
                      'protocol_param', 'user']
        user_keys = list(user.keys())
        for key in user_keys:
            if key not in valid_keys:
                del user[key]
        return user

    def record_data_usage(self):
        usage = {}
        today = date.today()
        yesterday = today - timedelta(days=1)
        jloader = JsonLoader()
        jloader.load(config.MUDB_DATA_FILE)
        muloader = MuJsonLoader()
        muloader.load(config.MUDB_FILE)
        for row in muloader.json:
            port = str(row['port'])
            print(type(port))
            if port in jloader.json:
                mudb_data = jloader.json[port]
                if mudb_data['date'] == str(yesterday):
                    val = {
                        'd': row['d'] - mudb_data['data']['d'],
                        'u': row['u'] - mudb_data['data']['u'],
                    }
                    usage.setdefault(port, val)
                else:
                    val = {
                        'd': 0,
                        'u': 0,
                    }
                    usage.setdefault(port, val)
                # 更新旧的流量记录
                mudb_data['data']['d'] = row['d']
                mudb_data['data']['u'] = row['u']
                mudb_data['date'] = str(today)
            else:
                val = {
                    'date': str(today),
                    'data': {
                        'd': row['d'],
                        'u': row['u'],
                    }
                }
                jloader.json.setdefault(port, val)

                usage.setdefault(port, {'d': 0, 'u': 0})
        # 最后将流量记录保存到文件中以便下次使用
        jloader.save(config.MUDB_DATA_FILE)
        return usage

    def send_data_usage(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token.token,
        }
        usage = self.record_data_usage()
        rest = requests.post(r"{}/api/transfer/".format(config.WEBAPI_DOMAIN),
                             headers=headers,
                             data=json.dumps(usage),
                             timeout=20)
        logging.info("上报用户流量结果，HTTP状态码：{}".format(rest.status_code))


if __name__ == '__main__':
    pass
    hm = UserMgr()
    hm.send_data_usage()
