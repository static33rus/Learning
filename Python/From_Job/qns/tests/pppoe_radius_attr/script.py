#!/usr/bin/python3

import os
import time
from pppoe_proto.configure import *
from pppoe_proto.packet import *

establish_full_session_with_PAP("veth0", 'ololo', 0.1)