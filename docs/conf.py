import pkg_resources
try:
    release = pkg_resources.get_distribution('pyblade').version
except pkg_resources.DistributionNotFound:
    print 'To build the documentation, The distribution information of pyblade'
    print 'Has to be available.  Either install the package into your'
    print 'development environment or run "setup.py develop" to setup the'
    print 'metadata.  A virtualenv is recommended!'
    sys.exit(1)
del pkg_resources

version = '.'.join(release.split('.')[:2])