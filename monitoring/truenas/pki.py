"""Private, persistent dedicated TLS syslog PKI; no automatic key rotation."""
import datetime as dt
import ipaddress
import os
from pathlib import Path
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPOSITORY = Path(__file__).resolve().parents[2]
FILES = ('ca.pem', 'ca-key.pem', 'server.pem', 'server-key.pem', 'client.pem', 'client-key.pem')


class PrivateInputError(ValueError):
    pass


def private_path(value):
    try:
        path = Path(value).expanduser()
        if not path.is_absolute() or path.is_symlink():
            raise ValueError()
        resolved = path.resolve()
        if resolved.is_relative_to(REPOSITORY):
            raise ValueError()
        # Reject symlinked components, including aliases to otherwise safe paths.
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError()
        return resolved
    except Exception:
        raise PrivateInputError('Private inputs require absolute nonsymlink paths outside the checkout') from None


def private_directory(value, *, create=False):
    path = private_path(value)
    try:
        if create and not path.exists():
            path.mkdir(mode=0o700)  # Parent must already exist; no broad mkdir tree.
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError()
        return path
    except Exception:
        raise PrivateInputError('Private directory must be owned by the current user with mode 0700') from None


def read_private(value, limit=1024 * 1024):
    path = private_path(value)
    private_directory(path.parent)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError()
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            data = stream.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError()
        return data
    except Exception:
        raise PrivateInputError('Private input must be a nonempty owner-only regular mode-0600 file') from None
    finally:
        if fd is not None:
            os.close(fd)


def write_new(value, content):
    path = private_path(value)
    private_directory(path.parent)
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        raise PrivateInputError('Private artifact creation failed; existing files are never overwritten') from None
    finally:
        if fd is not None:
            os.close(fd)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _pub(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _validate_existing(directory, address):
    try:
        certs = {name: x509.load_pem_x509_certificate(read_private(directory / (name + '.pem')))
                 for name in ('ca', 'server', 'client')}
        keys = {name: serialization.load_pem_private_key(read_private(directory / (name + '-key.pem')), None)
                for name in certs}
        now = dt.datetime.now(dt.timezone.utc)
        for name, cert in certs.items():
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError()
            if _pub(cert.public_key()) != _pub(keys[name].public_key()):
                raise ValueError()
            cert.verify_directly_issued_by(certs['ca'])
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca != (name == 'ca'):
                raise ValueError()
        if certs['ca'].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != 'homelab-truenas-syslog-ca':
            raise ValueError()
        if certs['client'].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != 'homelab-truenas':
            raise ValueError()
        if ExtendedKeyUsageOID.CLIENT_AUTH not in certs['client'].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError()
        if ExtendedKeyUsageOID.SERVER_AUTH not in certs['server'].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError()
        sans = certs['server'].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if sans.get_values_for_type(x509.IPAddress) != [address]:
            raise ValueError()
        try:
            certs['client'].extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            pass
        else:
            raise ValueError()
    except Exception:
        raise PrivateInputError('Existing dedicated PKI is incomplete, invalid or differs from the reviewed receiver; no rotation performed') from None


def ensure_materials(directory, receiver_ipv4):
    """Create once or validate exact existing private PKI; return file paths only."""
    try:
        address = ipaddress.IPv4Address(receiver_ipv4)
        if not any(address in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError()
    except Exception:
        raise PrivateInputError('PKI receiver must be an RFC1918 IPv4 address') from None
    directory = private_directory(directory, create=True)
    present = [bool((directory / name).exists() or (directory / name).is_symlink()) for name in FILES]
    if any(present):
        if not all(present):
            raise PrivateInputError('Partial dedicated PKI exists; restore or review privately before proceeding')
        _validate_existing(directory, address)
        return {name: str(directory / name) for name in FILES}
    now = dt.datetime.now(dt.timezone.utc)
    keys = {name: rsa.generate_private_key(public_exponent=65537, key_size=3072) for name in ('ca', 'server', 'client')}
    names = dict(ca='homelab-truenas-syslog-ca', server='homelab-wazuh-syslog', client='homelab-truenas')
    subjects = {name: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) for name, cn in names.items()}
    certs = {}
    for name in keys:
        ca = name == 'ca'
        builder = (x509.CertificateBuilder().subject_name(subjects[name]).issuer_name(subjects['ca'])
                   .public_key(keys[name].public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + dt.timedelta(days=3650 if ca else 825))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(keys[name].public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(keys['ca'].public_key()), critical=False))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if name == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        if name == 'server':
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=False)
        certs[name] = builder.sign(keys['ca'], hashes.SHA256())
    # O_EXCL prevents overwrite even if another process wins a create race. A
    # partial write is intentionally refused on retry, never silently regenerated.
    for name in keys:
        write_new(directory / (name + '-key.pem'), _key_pem(keys[name]))
        write_new(directory / (name + '.pem'), _cert_pem(certs[name]))
    _validate_existing(directory, address)
    return {name: str(directory / name) for name in FILES}


def validate_existing(directory, receiver_ipv4):
    """Read-only validation for a saved-plan review; never creates or rotates files."""
    directory = private_directory(directory)
    try:
        address = ipaddress.IPv4Address(receiver_ipv4)
        if not any(address in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError()
    except Exception:
        raise PrivateInputError('PKI receiver must be an RFC1918 IPv4 address') from None
    _validate_existing(directory, address)
    return {name: str(directory / name) for name in FILES}


def main():
    import argparse
    import json
    import sys
    parser = argparse.ArgumentParser(description='Prepare dedicated private TrueNAS syslog PKI without network access')
    parser.add_argument('--directory', required=True)
    parser.add_argument('--receiver-ipv4', required=True)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.validate_only:
            validate_existing(args.directory, args.receiver_ipv4)
        else:
            ensure_materials(args.directory, args.receiver_ipv4)
        print(json.dumps({'valid': True}))
        return 0
    except Exception:
        print('Private PKI preparation failed; existing materials were preserved. Inspect privately.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
