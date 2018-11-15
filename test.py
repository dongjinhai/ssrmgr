import psutil
import requests
from subprocess import call, Popen, PIPE


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
        return ips


if __name__ == '__main__':
    hm = HostMgr()
    hm.delete_iptables(7001)
