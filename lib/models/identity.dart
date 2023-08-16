import 'dart:convert';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';
import 'package:asn1lib/asn1lib.dart';

class Identity {
  final String name;
  late final Uint8List cert;
  late final Uint8List privateKey;
  late final String certString;
  late final String privateKeyString;
  late final Map<String, String?> subject;
  final List<String> pages = [];

  Uint8List convertStringToUint8List(String str) {
    final List<int> codeUnits = str.codeUnits;
    final Uint8List unit8List = Uint8List.fromList(codeUnits);

    return unit8List;
  }

  Identity(this.name,
      {days = 365000,
      String? existingCertString,
      String? existingPrivateKeyString}) {
    AsymmetricKeyPair keyPair = CryptoUtils.generateRSAKeyPair();

    if (existingCertString != null) {
      certString = existingCertString;
      var x509 = X509Utils.x509CertificateFromPem(certString);

      subject = x509.subject.entries.fold({}, (accum, entry) {
        // TODO
        var a =
            ASN1ObjectIdentifier.fromBytes(convertStringToUint8List(entry.key));

        if (entry.value != null && a.identifier != null) {
          accum[a.identifier!] = entry.value;
        }
        return accum;
      });
    } else {
      Map<String, String> newSubject = {'commonName': name};
      subject = newSubject;
      var x = X509Utils.generateRsaCsrPem(
          newSubject,
          keyPair.privateKey as RSAPrivateKey,
          keyPair.publicKey as RSAPublicKey);

      certString =
          X509Utils.generateSelfSignedCertificate(keyPair.privateKey, x, 100);
    }

    if (existingPrivateKeyString != null) {
      privateKeyString = existingPrivateKeyString;
      CryptoUtils.rsaPrivateKeyFromPem(privateKeyString);
    } else {
      privateKeyString = CryptoUtils.encodeRSAPrivateKeyToPem(
          keyPair.privateKey as RSAPrivateKey);
    }
    var utf8encoder = const Utf8Encoder();
    cert = utf8encoder.convert(certString);
    privateKey = utf8encoder.convert(privateKeyString);
  }

  static bool validateCert(certString) {
    try {
      X509Utils.x509CertificateFromPem(certString);
    } catch (e) {
      return false;
    }
    return true;
  }

  static bool validatePrivateKey(privateKeyString) {
    try {
      CryptoUtils.rsaPrivateKeyFromPem(privateKeyString);
    } catch (e) {
      return false;
    }
    return true;
  }

  addPage(String page) {
    pages.add(page);
  }

  matches(Uri uri) {
    var check = uri.toString();
    return pages.any((page) {
      return check == page ||
          check.startsWith(page.endsWith("/") ? page : page + "/");
    });
  }
}
