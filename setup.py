from distutils.core import setup
import subprocess

setup(
      name='maeg',
      version='0.01',
      packages=['maeg','maeg.exploits','maeg.exploit', 'maeg.exploit.cgc', 'maeg.exploit.cgc.type1', 'maeg.exploit.cgc.type2', 'maeg.exploit.cgc.c_templates', 'maeg.exploit.techniques', 'maeg.exploit.shellcodes'],
)
