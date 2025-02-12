import os
import logging
import subprocess
from base64 import b64decode
from random import randrange
from tempfile import NamedTemporaryFile

import xmlsig  # pylint: disable=W7936
from cryptography.hazmat.primitives import serialization  # pylint: disable=W7936
from cryptography.hazmat.primitives.serialization import pkcs12  # pylint: disable=W7936
from cryptography.x509 import ExtensionNotFound  # pylint: disable=W7936
from cryptography.x509.oid import ExtensionOID, NameOID  # pylint: disable=W7936
from lxml import etree
from xades import XAdESContext, template  # pylint: disable=W7936
from xades.policy import ImpliedPolicy  # pylint: disable=W7936

from odoo import fields, models, tools
from odoo.exceptions import UserError
from odoo.tools.translate import _

_logger = logging.getLogger(__name__)

openssl_config = """
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
"""


def convert_key_cer_to_pem(key, password):
    # Crear un archivo de configuración temporal para OpenSSL
    with NamedTemporaryFile("w", delete=False) as config_file:
        config_file.write(openssl_config)
        config_path = config_file.name

    try:
        # Crear archivos temporales para la clave y la clave en formato PEM
        with NamedTemporaryFile("wb", suffix=".key", prefix="edi.ec.tmp.", delete=False) as key_file, \
                NamedTemporaryFile("rb", suffix=".pem", prefix="edi.ec.tmp.", delete=False) as keypem_file:

            key_file.write(key)
            key_file.flush()

            # # Logs de los nombres de los archivos temporales y la contraseña
            # _logger.info("Key file path: %s", key_file.name)
            # _logger.info("PEM file path: %s", keypem_file.name)
            # _logger.info("Password for key decryption: %s", password)

            # Construye y loguea el comando completo antes de ejecutarlo
            command = f"OPENSSL_CONF={config_path} openssl pkcs12 -nocerts -in {key_file.name} -out {keypem_file.name} -passin pass:{password} -passout pass:{password}"
            # _logger.info("OpenSSL Command: %s", command)

            # Ejecutar el comando y capturar la salida
            process = subprocess.run(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if process.returncode != 0:
                _logger.error(
                    "OpenSSL command failed with stderr: %s", process.stderr.decode())
                _logger.error(
                    "OpenSSL command failed with stdout: %s", process.stdout.decode())

            keypem_file.seek(0)  # Regresa al principio del archivo para leerlo
            key_pem = keypem_file.read().decode()
            # _logger.info("Extracted PEM: %s", key_pem[:100])

            return key_pem

    finally:
        # Eliminar archivos temporales
        os.remove(config_path)
        os.remove(key_file.name)
        os.remove(keypem_file.name)


class SriKeyType(models.Model):
    _name = "sri.key.type"
    _description = "Type of electronic key"

    name = fields.Char(size=255, required=True, readonly=False)
    file_content = fields.Binary(string="Signature File")
    file_name = fields.Char(string="Filename", readonly=True)
    password = fields.Char(string="Signing key")
    active = fields.Boolean(string="Active?", default=True)
    company_id = fields.Many2one(
        comodel_name="res.company",
        string="Company",
        default=lambda self: self.env.company,
    )
    state = fields.Selection(
        [
            ("unverified", "Unverified"),
            ("valid", "Valid Signature"),
            ("expired", "Signature Expired"),
        ],
        default="unverified",
        readonly=True,
    )
    # datos informativos del certificado
    issue_date = fields.Date(string="Date of issue", readonly=True)
    expire_date = fields.Date(string="Expiration date", readonly=True)
    subject_serial_number = fields.Char(
        string="Serial Number(Subject)", readonly=True)
    subject_common_name = fields.Char(
        string="Organization(Subject)", readonly=True)
    issuer_common_name = fields.Char(
        string="Organization (Issuer)", readonly=True)
    cert_serial_number = fields.Char(
        string="Serial number (certificate)", readonly=True
    )
    cert_version = fields.Char(string="Version", readonly=True)

    @tools.ormcache("self.file_content", "self.password", "self.state")
    def _decode_certificate(self):
        self.ensure_one()
        if not self.password:
            return None, None, None
        file_content = b64decode(self.file_content)
        try:
            p12 = pkcs12.load_pkcs12(file_content, self.password.encode())
        except Exception as ex:
            _logger.warning(str(ex))
            raise UserError(
                _(
                    "Error opening the signature, possibly the signature key has "
                    "been entered incorrectly or the file is not supported. \n%s"
                )
                % (str(ex))
            ) from None
        certificate = p12.cert.certificate
        # revisar si el certificado tiene la extension digital_signature activada
        # caso contrario tomar del listado de certificados el primero que tengan esta extension
        is_digital_signature = True
        try:
            extension = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            is_digital_signature = extension.value.digital_signature
        except ExtensionNotFound as ex:
            _logger.debug(str(ex))
        if not is_digital_signature:
            # cuando hay mas de un certificado, tomar el certificado correcto
            # este deberia tener entre las extensiones digital_signature = True
            # pero si el certificado solo tiene uno, devolvera None
            for other_cert in p12.additional_certs:
                try:
                    extension = other_cert.certificate.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE
                    )
                except ExtensionNotFound as ex:
                    _logger.debug(str(ex))
                if extension.value.digital_signature:
                    certificate = other_cert.certificate
                    break
        private_key_str = convert_key_cer_to_pem(file_content, self.password)
        start_index = private_key_str.find("Signing Key")
        # cuando el archivo tiene mas de una firma electronica
        # viene varias secciones con BEGIN ENCRYPTED PRIVATE KEY
        # diferenciandose por:
        # * Decryption Key
        # * Signing Key
        # asi que tomar desde Signing Key en caso de existir
        if start_index >= 0:
            private_key_str = private_key_str[start_index:]
        start_index = private_key_str.find(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        private_key_str = private_key_str[start_index:]
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            self.password.encode(),
        )
        return private_key, certificate

    def action_validate_and_load(self):
        _private_key, cert = self._decode_certificate()
        issuer = cert.issuer
        subject = cert.subject
        subject_common_name = (
            subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            else ""
        )
        subject_serial_number = (
            subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
            if subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
            else ""
        )
        issuer_common_name = (
            issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            else ""
        )
        vals = {
            "issue_date": fields.Datetime.context_timestamp(
                self, cert.not_valid_before
            ).date(),
            "expire_date": fields.Datetime.context_timestamp(
                self, cert.not_valid_after
            ).date(),
            "subject_common_name": subject_common_name,
            "subject_serial_number": subject_serial_number,
            "issuer_common_name": issuer_common_name,
            "cert_serial_number": cert.serial_number,
            "cert_version": cert.version,
            "state": "valid",
        }
        self.write(vals)
        return True

    def action_sign(self, xml_string_data):
        def new_range():
            return randrange(100000, 999999)

        p12 = self._decode_certificate()
        doc = etree.fromstring(xml_string_data)
        signature_id = f"Signature{new_range()}"
        signature_property_id = f"{signature_id}-SignedPropertiesID{new_range()}"
        certificate_id = f"Certificate{new_range()}"
        reference_uri = f"Reference-ID-{new_range()}"
        signature = xmlsig.template.create(
            xmlsig.constants.TransformInclC14N,
            xmlsig.constants.TransformRsaSha1,
            signature_id,
        )
        xmlsig.template.add_reference(
            signature,
            xmlsig.constants.TransformSha1,
            name=f"SignedPropertiesID{new_range()}",
            uri=f"#{signature_property_id}",
            uri_type="http://uri.etsi.org/01903#SignedProperties",
        )
        xmlsig.template.add_reference(
            signature, xmlsig.constants.TransformSha1, uri=f"#{certificate_id}"
        )
        ref = xmlsig.template.add_reference(
            signature,
            xmlsig.constants.TransformSha1,
            name=reference_uri,
            uri="#comprobante",
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        ki = xmlsig.template.ensure_key_info(signature, name=certificate_id)
        data = xmlsig.template.add_x509_data(ki)
        xmlsig.template.x509_data_add_certificate(data)
        xmlsig.template.add_key_value(ki)
        qualifying = template.create_qualifying_properties(
            signature, name=signature_id)
        props = template.create_signed_properties(
            qualifying, name=signature_property_id
        )
        signed_do = template.ensure_signed_data_object_properties(props)
        template.add_data_object_format(
            signed_do,
            f"#{reference_uri}",
            description="contenido comprobante",
            mime_type="text/xml",
        )
        doc.append(signature)
        ctx = XAdESContext(ImpliedPolicy(xmlsig.constants.TransformSha1))
        ctx.load_pkcs12(p12)
        ctx.sign(signature)
        ctx.verify(signature)
        return etree.tostring(doc, encoding="UTF-8", pretty_print=True).decode()
