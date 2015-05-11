from setuptools import setup, find_packages

setup(
    version='v0.0.1',
    description='django-tastyprofiles',
    long_description=open('README.md').read(),
    author='Jony Kalavera',
    author_email='mr.jony@gmail.com',
    name='tastyprofiles',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'tastypie',
        'django-recaptcha'
    ],
    license="MIT",
)
