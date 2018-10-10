#!/usr/bin/python3

import sys

from pppoe_proto import *

from collections import OrderedDict
from optparse import OptionParser

# Run single test
#  - testdict: Test dictionary
#  - test: Test name
#  - interface: Client interface
def run_single_test(testdict, test, interface):
    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

    success = testdict[test] (test, interface)
    if(success):
        print(" >>> SUCCESS")
    else:
        print(" >>> FAIL")

    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

    if(not success):
        sys.exit(1)

# Run test
#  - testdict: Test dictionary
#  - test: Test name
#  - interface: Client interface
def run_test(testdict, test, interface):
    if test == '':
        for key in testdict:
            run_single_test(testdict, key, interface)
    else:
        if test in testdict:
            run_single_test(testdict, test, interface)

# Run tests on specified suite
#  - suite: Suite name
#  - test: Test name
#  - interface: Client interface
def run_suite(suite, test, interface):
    testdict = OrderedDict()
    module = sys.modules["pppoe_proto.{0}".format(suite)]
    func = getattr(module, "register", None)
    func(testdict)
    run_test(testdict, test, interface)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-s", "--suite", dest="suite", default="", help="suite name")
    parser.add_option("-t", "--test", dest="test", default="", help="test name")
    parser.add_option("-i", "--interface", dest="interface", default="veth2", help="client interface")
    (options, args) = parser.parse_args()
    run_suite(options.suite, options.test, options.interface)
