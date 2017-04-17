#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
heatman probe.
This application 
1. obtians ping targets from a 'heatman' server via http
2. sends ping to the targets periodically and saves results.
3. export result to configured the 'heatman' server via http
"""


import os
import re
import sys
import json
import time
import commands
import socket
import requests
import syslog
import signal
from optparse import OptionParser

from datetime import datetime
from requests.exceptions import ConnectionError



DEFAULT_SAVED_RTTS_NUM = 128 # Number of saved ping resulsts


DEFAULT_EXPORT_INTERVAL = 10
DEFAULT_PROBE_INTERVAL = 1
DEFAULT_REFRESH_INTERVAL = 60


FAILED_EXPORT_INTERVAL = 60 # if export failed, try after 60 sec
FAILED_REFRESH_INTERVAL = 60 # if get config failed, try after 60 sec



# Syslog Iinit
syslog.openlog("heatman-probe", syslog.LOG_PID|syslog.LOG_PERROR,
               syslog.LOG_SYSLOG)




class PingResult :

    def __init__(self, ping_output) :

        self.success = False
        self.rtt = 0.0
        self.ttl = 0

        self.load(ping_output)

        return


    def load(self, ping_output) :

        """
        Load ping comand output and set parameters
        """

        rttm = re.search(r'time=(\d+\.\d+)', ping_output)
        if not rttm:
            rttm = re.search(r'time=(\d+)', ping_output)

        ttlm = re.search(r'ttl=(\d+)', ping_output)
        if not ttlm:
            ttlm = re.search(r'hlim=(\d+)', ping_output)

        if rttm :
            self.success = True
            self.rtt = float(rttm.group (1))
            if ttlm :
                self.ttl = int(ttlm.group (1))
            else :
                self.ttl = -1

        else :
            self.sucess = False
            self.rtt = 0.0
            self.ttl = -1



class Ping :

    def __init__(self, addr, osname, timeout = 1) :

        self.addr = addr
        self.osname = osname

        ipv = self.whichipversion(addr)
        if ipv == 4 :
            self.ipversion = 4
        elif ipv == 6 :
            self.ipversion = 6

        self.pingcmdstr = self.pingcmdstrings(osname, ipv)

        return


    def pingcmdstrings(self, osname, ipv) :

        if osname == "Linux" :
            if ipv == 4 : p = "ping -W 1 -c 1"
            if ipv == 6 : p = "ping6 -i 1 -c 1"
        elif osname == "Darwin" :
            if ipv == 4 : p = "ping -W 1000 -c 1"
            if ipv == 6 : p = "ping6 -i 1 -c 1"
        else :
            raise RuntimeError("unsupported OS %s"% osname)

        return p + " %s" % self.addr
        

    def send(self) :

        output = commands.getoutput(self.pingcmdstr)
        return PingResult(output)


    def whichipversion (self, addr) :

        if re.match (r'^(\d{1,3}\.){3,3}\d{1,3}$', addr)  :
            return 4

        if re.match (r'((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$', addr) :
            return 6

        raise RuntimeError("invalid IP address %s" % addr)


class PingTarget :


    def __init__(self, name, addr, osname,
                 saved_rtts_num = DEFAULT_SAVED_RTTS_NUM, timeout = 1) :

        self.name = name
        self.addr = addr

        self.saved_rtts_num = saved_rtts_num

        self.lossrate = 0.0 # rate of packet loss
        self.lost = 0.0 # sum of lost packet
        self.rtt = 0.0  # RTT value of LAST ping
        self.tot = 0.0  # sum of RTTs of executed pings
        self.avg = 0.0  # average of all RTTs
        self.snt = 0    # number of sent ping
        self.suc = 0    # number of ping succeeded
        self.ttl = 0
        self.result = [] # array of RTTs (-1 means failed)

        self.ping = Ping(self.addr, osname, timeout = timeout)

        return


    def send(self) :

        res = self.ping.send()

        self.snt += 1

        if res.success :
            # Ping success, save RTT, increment params and calculate average
            self.rtt = res.rtt
            self.tot += res.rtt
            self.suc += 1
            self.avg = self.tot / self.suc
            self.ttl = res.ttl
            self.result.insert(0, self.rtt)

        else :
            # Ping failed
            self.lost += 1
            self.lossrate = self.lost / self.snt * 100.0
            self.result.insert(0, -1)

        # trim over saved_rtts_num result
        while len(self.result) > self.saved_rtts_num :
            self.result.pop()

        return


    def dump(self) :
        """
        Dump current status as a dict.
        {
          "name" : target_name, "addr" : target_addr,
          "lossrate" : lossrate, "last" : last_rtt,
          "average" : average, "sent" : num_of_sent_pings,
          "rtts" : [ rtt, rtt, rtt, rtt, ... ]
        }
        """
    
        d = {}
        d["name"] = self.name
        d["addr"] = self.addr
        d["lossrate"] = self.lossrate
        d["last"] = self.rtt
        d["average"] = self.avg
        d["sent"] = self.snt
        d["rtts"] = self.result

        return d


class HeatmanProbe :

    def __init__(self, probe_name, probe_addr, heatman_addr) :

        """
        Heatman Probe.
        check ping status of targets and export ping
        resulsts to a server 'heatman_addr'
        """

        self.probe_name = probe_name
        self.probe_addr = probe_addr
        self.heatman_addr = heatman_addr
        
        self.export_interval = DEFAULT_EXPORT_INTERVAL
        self.probe_interval = DEFAULT_PROBE_INTERVAL
        self.saved_rtts_num = DEFAULT_SAVED_RTTS_NUM
        self.refresh_interval = DEFAULT_REFRESH_INTERVAL
        self.targets = []

        self.osname = commands.getoutput("uname -s")


        return


    def add_target(self, target_name, target_addr) :

        self.targets.append(PingTarget(target_name, target_addr,
                            self.osname, saved_rtts_num = self.saved_rtts_num))
        return
        

    def delete_target(self, target_name, target_addr) :

        cnt = 0
        for target in self.targets :
            if target.name == target_name and target.addr == target_addr :
                list.remove(targets[cnt])
                break
            cnt += 1
        return


    def find_target(self, target_name, target_addr) :

        for target in self.targets :
            if target.name == target_name and target.addr == target_addr :
                return target

        return None


    def probe(self) :

        for target in self.targets :
            target.send()

        return


    def export(self) :

        """
        export current ping resulsts.
        export json fomrat is
        {
          "probe_name" : probe_name,
          "probe_addr" : probe_addr,
          "udpated" : "HH:MM:SS",
          "results" : [
            {
              "name" : target_name, "addr" : target_addr,
              "lossrate" : lossrate, "last" : last_rtt,
              "average" : average, "sent" : num_of_sent_pings,
              "rtts" : [ rtt, rtt, rtt, rtt, ... ]
            },
            ...
          ]
        }
        """

        d = {
            "probe_name" : self.probe_name,
            "probe_addr" : self.probe_addr,
            "updated" : datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            "results" : []
            }

        for target in self.targets :
            d["results"].append(target.dump())


        url = "http://%s/rest/post/result/%s" % (self.heatman_addr,
                                                 self.probe_name)

        try :
            r = requests.post(url,
                              headers = {"Content-Type" : "application/json"},
                              data = json.dumps(d))
        except ConnectionError :
            self.export_interval = FAILED_EXPORT_INTERVAL
            syslog.syslog(syslog.LOG_ERR,
                          "conncetion failed to %s." % url)
            return


        if r.status_code != 200 :
            self.export_interval = FAILED_EXPORT_INTERVAL
            syslog.syslog(syslog.LOG_ERR,
                          "post %s failed '%d'." % (url, r.status_code))
            return

        # post success
        self.export_interval = self.export_configured_interval

        return


    def refresh(self) :
        """
        Re-obtain config file from heatman_addr and update ping targets
        """

        url = "http://%s/rest/get/config/%s" % (self.heatman_addr,
                                                self.probe_name)

        try :
            r = requests.get(url)

        except ConnectionError :
            self.refresh_interval = FAILED_REFRESH_INTERVAL
            syslog.syslog(syslog.LOG_ERR,
                          "refresh: connction failed to %s." % url)
            return False

        if r.status_code != 200 :
            self.refresh_interval = FAILED_REFRESH_INTERVAL
            syslog.syslog(syslog.LOG_ERR,
                          "get %s failed '%d'." % (url, r.status_code))
            return False

        config = r.json()
        self.probe_interval = config["probe_interval"]
        self.export_interval = config["export_interval"]
        self.export_configured_interval = config["export_interval"]
        self.saved_rtts_num = config["saved_rtts_num"]

        for target in self.targets :
            target.saved_rtts_num = self.saved_rtts_num

        # find new targets
        for new_target in config["targets"]:
            if not self.find_target(new_target[0], new_target[1]) :
                # new target !
                self.add_target(new_target[0], new_target[1])
                syslog.syslog(syslog.LOG_INFO,
                              "add new ping target %s %s" %
                              (new_target[0], new_target[1]))

        # find deleted targets
        deleted = []
        for target in self.targets :

            exist = False

            for new_target in config["targets"] :
                if (target.name == new_target[0] and
                    target.addr == new_target[1]) :
                    exist = True

            if not exist :
                # delete target !
                delete.append([target.name, target.addr])

        for deleted_target in deleted :
            syslog.syslog(syslog.LOGINFO, "delete ping target %s %s" %
                          (deleted_target[0], deleted_target[1]))
            self.delete_target(deleted_target[0], deleted_target[1])


        self.refresh_interval = DEFAULT_REFRESH_INTERVAL

        return True



    def run(self) :

        cnt = 0

        while True :

            if cnt % self.probe_interval == 0 :
                self.probe()

            if cnt % self.export_interval == 0 :
                self.export()

            if cnt % self.refresh_interval == 0:
                self.refresh()

            cnt += 1
            time.sleep(1)

        return




def sigint_handler(signum, frame) :
    sys.exit(1)



if __name__ == '__main__' :

    desc = "usage : %prog [options]"
    parser = OptionParser(desc)

    parser.add_option("-n", "--probe-name", type = "string", default = None,
                      dest = "probe_name", help = "name of this probe node")

    parser.add_option("-a", "--probe-addr", type = "string", default = None,
                      dest = "probe_addr", help = "address of this probe node")

    parser.add_option("-r", "--remote-heatman", type = "string",
                      default = None, dest = "heatman_addr",
                      help = "address of remote heatman server")


    (options, args) = parser.parse_args()

    if not options.probe_name :
        syslog.syslog(syslog.LOG_ERR,
                      "probe name '-n' must be specified")
        sys.exit(1)

    if not options.probe_addr :
        syslog.syslog(syslog.LOG_ERR,
                      "probe addr '-a' must be specified")
        sys.exit(1)

    if not options.heatman_addr :
        syslog.syslog(syslog.LOG_ERR,
                      "heatman server addr '-r' must be specified")
        sys.exit(1)



    signal.signal(signal.SIGINT, sigint_handler)


    probe = HeatmanProbe(options.probe_name,
                         options.probe_addr,
                         options.heatman_addr)

    syslog.syslog(syslog.LOG_INFO,
                  "start heatman-probe. try to fetch config from %s..." %
                  ("http://%s/rest/get/config/%s" % 
                   (options.heatman_addr, options.probe_name)))

    while not probe.refresh() :
        time.sleep(10)


    syslog.syslog(syslog.LOG_INFO, "start to run heatman-probe!")
    probe.run()



