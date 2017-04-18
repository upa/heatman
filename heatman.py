#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
heatman server.
This application
1. returns ping targets to 'heatman' probes conncting
2. obtains ping resulsts from the probes via http
3. display results as a web server
"""

import os
import re
import sys
import json
import time
import socket
import requests
import syslog
import ConfigParser

from flask import Flask, Response, render_template, request, jsonify
app = Flask(__name__)


heatman = None # HeatmanServer instance for access from flask 'app'

DEFAULT_EXPORT_INTERVAL = 10
DEFAULT_PROBE_INTERVAL = 1
DEFAULT_SAVED_RTTS_NUM = 128

index_html_values = { "version" : "0.0.1",
                      "browser_update_interval" : 10000 }



class HeatmanProbeNode() :
    
    def __init__(self, probe_name,
                 probe_interval = DEFAULT_PROBE_INTERVAL,
                 export_interval = DEFAULT_EXPORT_INTERVAL,
                 saved_rtts_num = DEFAULT_SAVED_RTTS_NUM) :

        self.name = probe_name
        self.probe_interval = probe_interval
        self.export_interval = export_interval
        self.saved_rtts_num = saved_rtts_num
        self.targets = [] # [[ NAME, ADDR], [ NAME, ADDR], ... ]

        self.probe_result = None # exported json is hold here.

        return

    def add_target(self, target_name, target_addr) :
        self.targets.append([target_name, target_addr])
        return


    def dump(self) :
        return self.probe_result


    def dump_for_config(self) :
        return {
            "probe_interval" : self.probe_interval,
            "export_interval" : self.export_interval,
            "saved_rtts_num" : self.saved_rtts_num,
            "targets" : self.targets
            }

    def print_for_debug(self) :
        print json.dumps(self.dump_for_config(), indent = 4)


class HeatmanServer() :

    def __init__(self, configfile) :

        self.probes = []

        defaults = {
            "bind_addr" : "127.0.0.1", 
            "bind_port" : "8080",
            "probe_interval" : str(DEFAULT_PROBE_INTERVAL),
            "export_interval" : str(DEFAULT_EXPORT_INTERVAL),
            "saved_rtts_num" : str(DEFAULT_SAVED_RTTS_NUM),
            "browser_update_interval" : str(10000),
            }

        conf = ConfigParser.SafeConfigParser(defaults)
        conf.read(configfile)


        try :
            self.secret = conf.get("settings", "secret")
        except ConfigParser.NoOptionError :
            print "'secret' in section 'settings' must be configured"
            sys.exit(1)

        self.bind_addr = conf.get("settings", "bind_addr")
        self.bind_port = int(conf.get("settings", "bind_port"))
        self.probe_interval = int(conf.get("settings", "probe_interval"))
        self.export_interval = int(conf.get("settings", "export_interval"))
        self.saved_rtts_num = int(conf.get("settings", "saved_rtts_num"))
        self.browser_update_interval = int(conf.get("settings",
                                           "browser_update_interval"))


        for section in conf.sections() :
            if section == "settings" :
                continue

            probe = HeatmanProbeNode(section,
                                     probe_interval = self.probe_interval,
                                     export_interval = self.export_interval,
                                     saved_rtts_num = self.saved_rtts_num)

            for option in conf.options(section) :
                if option in defaults :
                    continue

                probe.add_target(option, conf.get(section, option))

            self.probes.append(probe)

        return


    def find_probe(self, probe_name) :

        for probe in self.probes :
            if probe.name == probe_name :
                return probe
        return None

    

    def print_for_debug(self) :
        print "bind_addr: ", self.bind_addr
        print "bind_port: ", self.bind_port
        print "probe_interval: ", self.probe_interval
        print "export_interval: ", self.export_interval
        print "saved_rtts_num: ", self.saved_rtts_num

        for probe in self.probes :
            probe.print_for_debug()



@app.route("/", methods = [ "GET" ])
def index() :
    return render_template("index.html", v = index_html_values)


@app.route("/rest/get/config/<probe_name>", methods = [ "GET" ])
def reset_get_config_probe(probe_name) :
    
    probe = heatman.find_probe(probe_name)
    if not probe :
        content = { "error" : "probe node '%s' does not exist" % probe_name}
        return jsonify(content), 404

    return jsonify(probe.dump_for_config())


@app.route("/rest/post/result/<probe_name>", methods = [ "POST" ])
def rest_post_result_probe(probe_name) :

    probe = heatman.find_probe(probe_name)
    if not probe :
        content = { "error" : "probe node '%s' does not exist" % probe_name}
        return jsonify(content), 404

    if request.json["secret"] != heatman.secret :
        content = { "error"  : "invalid secret key"}
        return jsonify(content), 401

    probe.probe_result = request.json
    probe.probe_result.pop("secret")
    
    return jsonify(res = "success")


@app.route("/rest/get/result", methods = [ "GET" ])
def rest_get_result() :

    all_results = []
    for probe in heatman.probes :
        all_results.append(probe.dump())

    print all_results

    return jsonify({ "result" : all_results })



if __name__ == "__main__" :

    if len(sys.argv) < 2 :
        print "usage: heatman [config]"
        sys.exit(1)

    heatman = HeatmanServer(sys.argv[1])
    heatman.print_for_debug()

    index_html_values["browser_update_interval"] = \
        heatman.browser_update_interval

    app.run(host = heatman.bind_addr, port = heatman.bind_port, debug = True)


    
    
