
FILE = ['open',\
        'file'\
        ]

OS_COMMAND = ['os.system']

OTHER = [ 'os.popen', 'eval', 'evec', 'popen', 'execfile', 'os.spawnl', 'os.spawnlp',
             'os.spawnlpe', 'os.spawnle', \
             'os.spawnv', 'os.spawnve', 'os.spawnvp', 'os.spawnvpe', 'os.execv', 'os.execve', 'os.execvp', \
             'os.execvpe', 'os.open', 'os.popen2', 'os.popen3', 'os.popen4', 'os.putenv', 'os.rename', \
             'os.renames', 'call', 'Popen', 'Popen2', 'getoutput', 'getstatusoutput', 'eval' ]

SOURCE = FILE + OS_COMMAND + OTHER

