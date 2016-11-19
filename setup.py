from distutils.core import setup
import subprocess

setup(
      name='maeg',
      version='0.01',
      packages=['maeg'],
      install_requires=[
            'angr',
            'povsim',
            'simuvex',
            'tracer',
            'angrop',
            'compilerex',
      ],
)