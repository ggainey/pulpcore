#!/usr/bin/python
#
# Copyright (c) 2011 Red Hat, Inc.
#
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

#
# Contains mock agent content handlers.
#

import os
import shutil
from pulp.client.agent.dispatcher import HandlerReport

#
# Handlers to be deployed for loader testing
#

RPM = dict(
name='RPM Handler',
descriptor="""
[main]
enabled=1
types=rpm

[rpm]
class=RpmHandler
""",
handler=
"""
from pulp.client.agent.dispatcher import HandlerReport
class RpmHandler:
  def __init__(self, cfg):
    pass
  def install(self, units, options):
    return HandlerReport()
  def update(self, units, options):
    return HandlerReport()
  def uninstall(self, units, options):
    return HandlerReport()
  def profile(self):
    {}
""")

#
# Mock Deployer
#

class MockDeployer:

    ROOT = '/tmp/etc/agent/handler'
    PATH = ['/tmp/usr/lib/agent/handler',]

    def deploy(self):
        for path in (self.ROOT, self.PATH[0]):
            shutil.rmtree(path, ignore_errors=True)
            os.makedirs(path)
        for handler in (RPM,):
            self.__deploy(handler)
    
    def clean(self):
        for path in (self.ROOT, self.PATH[0]):
            shutil.rmtree(path, ignore_errors=True)
    
    def __deploy(self, handler):
        name = handler['name']
        fn = '.'.join((name, 'conf'))
        path = os.path.join(self.ROOT, fn)
        f = open(path, 'w')
        f.write(handler['descriptor'])
        f.close()
        fn = '.'.join((name, 'py'))
        path = os.path.join(self.PATH[0], fn)
        f = open(path, 'w')
        f.write(handler['handler'])
        f.close()

#
# Mock Handlers
#

class RpmHandler:

  def __init__(self, cfg=None):
    pass

  def install(self, units, options):
    report = HandlerReport()
    installed = []
    details = dict(
        installed=installed,
        deps=[],
        )
    report.succeeded('rpm', details)
    return report

  def update(self, units, options):
    report = HandlerReport()
    return report

  def uninstall(self, units, options):
    report = HandlerReport()
    return report

  def profile(self):
    {}