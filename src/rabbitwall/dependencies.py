"""Small dependency checks shared by preflight and the DNS service."""
import re


def check_dns_version(version):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:[.+-].*)?', version)
    if not match or not ( (2, 6, 1) <= tuple(map(int, match.groups())) < (3, 0, 0)):
        raise ValueError('dnspython >=2.6.1,<3 is required; update python3-dnspython (CVE-2023-29483).')


def require_dns():
    try:
        import dns
    except ImportError as error:
        raise ValueError('Install python3-dnspython >=2.6.1,<3') from error
    check_dns_version(dns.__version__)


def require_observer():
    require_dns()
    try:
        import google.protobuf
        import dnstap_pb2
    except ImportError as error:
        raise ValueError('Install python3-protobuf for the dnstap observer') from error


def require_drop_dns():
    try:
        from dns_drops import library
        library()
    except (OSError, AttributeError, ValueError) as error:
        raise ValueError('Install libnetfilter-log1 for dropped DNS observation') from error
