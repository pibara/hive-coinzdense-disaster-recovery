from setuptools import setup

setup(
    name='hiveqdpr',
    version="0.1.0",
    description="Hive Quantum-Disaster Prepare tool",
    long_description="Leave some data on your HIVE account for a one-time quantum disaster recovery.",
    author='Rob Meijer',
    author_email='pibara@gmail.com',
    url='https://github.com/pibara/hive-coinzdense-disaster-recovery',
    license='BSD',
    py_modules=['hiveqdpr'],
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'hqpdr-userpost-masterpass = hiveqdpr:_main_userpost_masterpass',
            'hqpdr-userpost-altpass = hiveqdpr:_main_userpost_altpass',
            'hqpdr-userpost-randomkey = hiveqdpr:_main_userpost_randomkey',
            'hqpdr-userpost-wif = hiveqdpr:_main_userpost_wif',
            'hqpdr-userverify-ecdsa = hiveqdpr:_main_userverify_ecdsa',
            'hqpdr-disasterkey-pass = hiveqdpr:_main_disasterkey_pass',
            'hqpdr-disasterkey-bip39 = hiveqdpr:_main_disasterkey_bip38',
            'hqpdr-bip39-wif = hiveqdpr:_main_bip38_wif',
            'hqpdr-bip39-masterpass = hiveqdpr:_main_bip38_masterpass',
            'hqpdr-sign-pass = hiveqdpr:_main_sign_pass',
            'hqpdr-sign-wif = hiveqdpr:_main_sign_wif',
            'hqpdr-sign-bip38 = hiveqdpr:_main_sign_bip38',
            'hqpdr-validate = hiveqdpr:_main_validate'
        ],
    },
    keywords='hive postquantum coinzdense signing crypto',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=["base58", "lighthive","starkbank-ecdsa","bip39","PyNaCl","libnacl"],
)
