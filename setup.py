import io
import os
import sys
import subprocess
from setuptools import setup, find_packages
from distutils.command.build import build as _build

# https://github.com/apache/beam/blob/master/sdks/python/apache_beam/examples/complete/juliaset/setup.py
# This class handles the pip install mechanism.
class build(_build):  # pylint: disable=invalid-name
  """A build command class that will be invoked during package install.
  The package built using the current setup.py will be staged and later
  installed in the worker using `pip install package'. This class will be
  instantiated during install for this specific scenario and will trigger
  running the custom commands specified.
  """
  sub_commands = _build.sub_commands + [('CustomCommands', None)]


# Some custom command to run during setup. The command is not essential for this
# workflow. It is used here as an example. Each command will spawn a child
# process. Typically, these commands will include steps to install non-Python
# packages. For instance, to install a C++-based library libjpeg62 the following
# two commands will have to be added:
#
#     ['apt-get', 'update'],
#     ['apt-get', '--assume-yes', 'install', 'libjpeg62'],
#
# First, note that there is no need to use the sudo command because the setup
# script runs with appropriate access.
# Second, if apt-get tool is used then the first command needs to be 'apt-get
# update' so the tool refreshes itself and initializes links to download
# repositories.  Without this initial step the other apt-get install commands
# will fail with package not found errors. Note also --assume-yes option which
# shortcuts the interactive confirmation.
#
# Note that in this example custom commands will run after installing required
# packages. If you have a PyPI package that depends on one of the custom
# commands, move installation of the dependent package to the list of custom
# commands, e.g.:
#
#     ['pip', 'install', 'my_package'],
#

CUSTOM_COMMANDS = [ 
# PBC
                    ['rm', '-rf', 'pbc-0.5.14'],
                    ['wget', 'https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz'],
                    ['tar', '-xvf', 'pbc-0.5.14.tar.gz'],
                    ['sh', '-c', 'cd pbc-0.5.14 && ./configure'],
                    ['sh', '-c', 'cd pbc-0.5.14 && make'],
                    ['sh', '-c', 'cd pbc-0.5.14 && make install'],
                    ['rm', 'pbc-0.5.14.tar.gz'],
                    ['rm', '-rf', 'pbc-0.5.14'],
# Charm crypto                     
                    ['rm', '-rf', 'charm'],
                    ['git', 'clone', 'https://github.com/JHUISI/charm.git'],
                    ['sh', '-c', 'cd charm && ./configure.sh'],
                    ['sh', '-c', 'cd charm && make'],
                    ['sh', '-c', 'cd charm && make install'],
                    ['rm', '-rf', 'charm']
                  ]

class CustomCommands(setuptools.Command):
  """A setuptools Command class able to run arbitrary commands."""
  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def RunCustomCommand(self, command_list):
    print('Running command: %s' % command_list)
    p = subprocess.Popen(
        command_list,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    # Can use communicate(input='y\n'.encode()) if the command run requires
    # some confirmation.
    stdout_data, _ = p.communicate()
    print('Command output: %s' % stdout_data)
    if p.returncode != 0:
      raise RuntimeError(
          'Command %s failed: exit code: %s' % (command_list, p.returncode))

  def run(self):
    for command in CUSTOM_COMMANDS:
      self.RunCustomCommand(command)

def setup_module():

  root = os.path.abspath(os.path.dirname(__file__))

  with io.open(os.path.join(root, "lsabe_ma", "__about__.py"), encoding="utf8") as f:
            __about__ = {}
            exec(f.read(), __about__)

  with io.open(os.path.join(root, "README.md"), encoding="utf8") as f:
    readme = f.read()

  PACKAGES = find_packages()

  setup(
    name                          = __about__["__name__"],
    packages                      = PACKAGES,
    description                   =  __about__["__summary__"],
    long_description              = readme,
    long_description_content_type = "text/markdown",
    author                        = __about__["__author__"],
    author_email                  = __about__["__email__"],
    version                       = __about__["__version__"],
    url                           = __about__["__uri__"],
    license                       = __about__["__license__"],
    classifiers=[
      "Environment :: Console",
      "Intended Audience :: Developers",
      "Intended Audience :: Science/Research",
      "Operating System :: POSIX :: Linux",
      "Programming Language :: Python :: 3.7",
      "Topic :: Scientific/Engineering"
    ],
    setup_requires = [
       "setuptools", 
       "wheel",
       "requests"
    ],
    install_requires=[
        "flask",
        "requests",
    ],
    cmdclass={
        # Command class instantiated and run during pip install scenarios.
        'build': build,
        'CustomCommands': CustomCommands,
    }
  )

if __name__ == "__main__":
    setup_module()

