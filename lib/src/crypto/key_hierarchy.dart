import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

/// Gestión de la jerarquía de claves del ecosistema BDJ Studio:
/// Clave Raíz (propietario) -> firma -> Certificado de Administrador (operador).
class AdminCertificate {
  AdminCertificate({
    required this.adminId,
    required this.operatorPublicKeyBase64,
    required this.validFromUtc,
    required this.validUntilUtc,
    this.rootSignatureBase64,
  });

  factory AdminCertificate.fromJson(Map<String, dynamic> json) {
    return AdminCertificate(
      adminId: json['adminId'] as String,
      operatorPublicKeyBase64: json['operatorPublicKey'] as String,
      validFromUtc: DateTime.parse(json['validFrom'] as String).toUtc(),
      validUntilUtc: DateTime.parse(json['validUntil'] as String).toUtc(),
      rootSignatureBase64: json['rootSignature'] as String?,
    );
  }

  factory AdminCertificate.fromEncodedString(String base64UrlCert) {
    final decodedBytes = base64Url.decode(base64UrlCert);
    final jsonStr = utf8.decode(decodedBytes);
    return AdminCertificate.fromJson(jsonDecode(jsonStr) as Map<String, dynamic>);
  }

  final String adminId;
  final String operatorPublicKeyBase64;
  final DateTime validFromUtc;
  final DateTime validUntilUtc;
  final String? rootSignatureBase64;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'adminId': adminId,
        'operatorPublicKey': operatorPublicKeyBase64,
        'validFrom': validFromUtc.toIso8601String(),
        'validUntil': validUntilUtc.toIso8601String(),
        if (rootSignatureBase64 != null) 'rootSignature': rootSignatureBase64,
      };

  String toUnsignedCanonicalString() =>
      '$adminId.$operatorPublicKeyBase64.${validFromUtc.toIso8601String()}.${validUntilUtc.toIso8601String()}';

  String toEncodedString() {
    if (rootSignatureBase64 == null) {
      throw StateError('El certificado de administrador debe estar firmado antes de serializarse.');
    }
    return base64UrlEncode(utf8.encode(jsonEncode(toJson())));
  }

  bool get isExpired => DateTime.now().toUtc().isAfter(validUntilUtc);

  Future<bool> verify(String rootPublicKeyBase64, {DateTime? checkTimeUtc}) async {
    if (rootSignatureBase64 == null) return false;
    final now = checkTimeUtc ?? DateTime.now().toUtc();
    if (now.isBefore(validFromUtc) || now.isAfter(validUntilUtc)) {
      return false;
    }

    try {
      final sigBytes = base64Url.decode(rootSignatureBase64!);
      final pubKeyBytes = base64Url.decode(rootPublicKeyBase64);
      final dataBytes = utf8.encode(toUnsignedCanonicalString());
      final ed25519 = Ed25519();
      final pubKey = SimplePublicKey(pubKeyBytes, type: KeyPairType.ed25519);
      final signature = Signature(sigBytes, publicKey: pubKey);
      return await ed25519.verify(dataBytes, signature: signature);
    } catch (_) {
      return false;
    }
  }
}

class KeyHierarchy {
  /// Clave pública raíz oficial del ecosistema BDJ Studio para la verificación de licencias SPP3.
  static const String ecosystemRootPublicKey = '2gXPq5NU2vxqThjCclrlVwQi7Z7khys-pd-2xv6LEq8=';

  static final _ed25519 = Ed25519();

  static Future<SimpleKeyPair> generateKeyPair() => _ed25519.newKeyPair();

  static Future<SimpleKeyPair> generateKeyPairFromSeed(List<int> seed) =>
      _ed25519.newKeyPairFromSeed(seed);

  static Future<AdminCertificate> issueAdminCertificate({
    required String adminId,
    required String operatorPublicKeyBase64,
    required SimpleKeyPair rootKeyPair,
    required Duration validityDuration,
  }) async {
    final now = DateTime.now().toUtc();
    final validFrom = now.subtract(const Duration(minutes: 5));
    final validUntil = now.add(validityDuration);
    final unsignedCert = AdminCertificate(
      adminId: adminId.trim().toLowerCase(),
      operatorPublicKeyBase64: operatorPublicKeyBase64,
      validFromUtc: validFrom,
      validUntilUtc: validUntil,
    );

    final dataBytes = utf8.encode(unsignedCert.toUnsignedCanonicalString());
    final signature = await _ed25519.sign(dataBytes, keyPair: rootKeyPair);
    final sigBase64 = base64UrlEncode(signature.bytes);

    return AdminCertificate(
      adminId: unsignedCert.adminId,
      operatorPublicKeyBase64: unsignedCert.operatorPublicKeyBase64,
      validFromUtc: unsignedCert.validFromUtc,
      validUntilUtc: unsignedCert.validUntilUtc,
      rootSignatureBase64: sigBase64,
    );
  }

  /// Derivación de hash seguro SHA-256 para HWID canónico
  static String hashHwid(String rawHwid) {
    final normalized = rawHwid
        .trim()
        .toUpperCase()
        .replaceAll(RegExp(r'\s+'), '')
        .replaceAll(RegExp(r'[^A-Z0-9-]'), '');
    return crypto.sha256.convert(utf8.encode(normalized)).toString();
  }
}
