from setuptools import setup

setup(name='magiclog',
      version='1.0',
      description='Tool allowing to easily scan through log files mixing standard messages and XML',
      url='https://github.com/mochodek/magiclog',
      author='',
      author_email='',
      license='Apache-2.0',
      packages=['magiclog'],
      install_requires=[
            'paramiko',
            'termcolor'
      ],
      scripts=[
          'bin/magiclog'],
      zip_safe=False)
