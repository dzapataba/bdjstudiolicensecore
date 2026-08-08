import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../crypto/key_hierarchy.dart';

class Spp3Payload {
  Spp3Payload({
    required this.licenseId,
    required this.customerId,
    required this.deviceId,
    required this.hwidHash,
    required this.productCode,
    required this.exactVersion,
    required this.plan,
    required this.issuedAtUtc,
    this.expiresAtUtc,
    this.features,
  });

  factory Spp3Payload.fromJson(Map<String, dynamic> json) {
    return Spp3Payload(
      licenseId: json['id'] as String,
      customerId: json['cid'] as String,
      deviceId: json['did'] as String,
      hwidHash: json['hhash'] as String,
      productCode: json['pcode'] as String,
      exactVersion: json['ver'] as String,
      plan: json['plan'] as String,
      issuedAtUtc: DateTime.parse(json['iat'] as String).toUtc(),
      expiresAtUtc: json['exp'] != null ? DateTime.parse(json['exp'] as String).toUtc() : null,
      features: json['feat'] as Map<String, dynamic>?,
    );
  }

  final String licenseId;
  final String customerId;
  final String deviceId;
  final String hwidHash;
  final String productCode;
  final String exactVersion;
  final String plan;
  final DateTime issuedAtUtc;
  final DateTime? expiresAtUtc;
  final Map<String, dynamic>? features;

  static String stripBuildNumber(String version) {
    final trimmed = version.trim();
    if (trimmed.isEmpty) {
      throw const FormatException('La cadena de versión está vacía.');
    }
    // Ignorar únicamente +build
    final cleaned = trimmed.split('+').first.trim();
    // Validar formato estricto major.minor.patch (con o sin -prerelease)
    final versionRegExp = RegExp(r'^\d+\.\d+\.\d+(-[0-9A-Za-z\-\.]+)?$');
    if (!versionRegExp.hasMatch(cleaned)) {
      throw FormatException('Formato de versión corrupto o no conforme a major.minor.patch: "$version"');
    }
    return cleaned;
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': licenseId,
        'cid': customerId,
        'did': deviceId,
        'hhash': hwidHash,
        'pcode': productCode,
        'ver': stripBuildNumber(exactVersion),
        'plan': plan,
        'iat': issuedAtUtc.toIso8601String(),
        if (expiresAtUtc != null) 'exp': expiresAtUtc!.toIso8601String(),
        if (features != null) 'feat': features,
      };

  String toBase64Url() => base64UrlEncode(utf8.encode(jsonEncode(toJson())));
}

enum Spp3VerificationStatus {
  valid,
  invalidFormat,
  invalidCertificate,
  expiredCertificate,
  invalidSignature,
  productMismatch,
  versionMismatch,
  hwidMismatch,
  expired,
}

class Spp3VerificationResult {
  const Spp3VerificationResult({
    required this.status,
    this.payload,
    this.signerCertificate,
    this.errorMessage,
  });

  final Spp3VerificationStatus status;
  final Spp3Payload? payload;
  final AdminCertificate? signerCertificate;
  final String? errorMessage;

  bool get isValid => status == Spp3VerificationStatus.valid;
}

class Spp3Token {
  static const String protocolPrefix = 'SPP3';

  /// Genera un token en formato SPP3.<payload_base64url>.<signer_cert_base64url>.<signature_base64url>
  static Future<String> issue({
    required Spp3Payload payload,
    required AdminCertificate signerCertificate,
    required SimpleKeyPair operatorKeyPair,
  }) async {
    if (signerCertificate.rootSignatureBase64 == null) {
      throw StateError('El certificado del administrador debe estar firmado por la Clave Raiz.');
    }
    final payloadB64 = payload.toBase64Url();
    final certB64 = signerCertificate.toEncodedString();
    final dataToSign = utf8.encode('$protocolPrefix.$payloadB64.$certB64');

    final ed25519 = Ed25519();
    final signature = await ed25519.sign(dataToSign, keyPair: operatorKeyPair);
    final sigB64 = base64UrlEncode(signature.bytes);

    return '$protocolPrefix.$payloadB64.$certB64.$sigB64';
  }

  /// Verifica la integridad del token SPP3 en 2 etapas defensivas y evalúa el acoplamiento exacto de versión y HWID.
  static Future<Spp3VerificationResult> verify({
    required String token,
    required String rootPublicKeyBase64,
    required String expectedProductCode,
    required String expectedVersion,
    required String currentHwidHash,
    DateTime? currentClockUtc,
  }) async {
    final cleanToken = token.trim();
    if (!cleanToken.startsWith('$protocolPrefix.')) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidFormat,
        errorMessage: 'El formato de la licencia no corresponde al protocolo seguro SPP3.',
      );
    }

    final parts = cleanToken.split('.');
    if (parts.length != 4) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidFormat,
        errorMessage: 'Estructura de licencia SPP3 corrompida o modificada (segmentos incorrectos).',
      );
    }

    final payloadB64 = parts[1];
    final certB64 = parts[2];
    final sigB64 = parts[3];

    // 1. Decodificar el Payload y el Certificado Emisor para contrastar la fecha de emisión (issuedAtUtc)
    Spp3Payload payload;
    try {
      final jsonBytes = base64Url.decode(payloadB64);
      final jsonMap = jsonDecode(utf8.decode(jsonBytes)) as Map<String, dynamic>;
      payload = Spp3Payload.fromJson(jsonMap);
    } catch (_) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidFormat,
        errorMessage: 'El contenido interno del payload SPP3 no es válido.',
      );
    }

    AdminCertificate signerCert;
    try {
      signerCert = AdminCertificate.fromEncodedString(certB64);
    } catch (_) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidCertificate,
        errorMessage: 'El certificado de autorización del administrador es inválido.',
      );
    }

    // 2. Verificación de vigencia del Certificado del Administrador en el momento de la emisión (issuedAtUtc)
    if (payload.issuedAtUtc.isAfter(signerCert.validUntilUtc)) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.expiredCertificate,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'El certificado del administrador emisor ya había expirado cuando se emitió la licencia (${signerCert.validUntilUtc.toLocal()}).',
      );
    }
    if (payload.issuedAtUtc.isBefore(signerCert.validFromUtc)) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidCertificate,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'El certificado del administrador emisor aún no era válido cuando se emitió la licencia.',
      );
    }

    final certValid = await signerCert.verify(rootPublicKeyBase64, checkTimeUtc: payload.issuedAtUtc);
    if (!certValid) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidCertificate,
        errorMessage: 'La firma de raíz en el certificado del administrador emisor es inválida o fue revocada.',
      );
    }

    // 3. Verificación de la Firma Ed25519 del Token contra la Clave Pública del Administrador
    try {
      final pubKeyBytes = base64Url.decode(signerCert.operatorPublicKeyBase64);
      final sigBytes = base64Url.decode(sigB64);
      final dataToSign = utf8.encode('$protocolPrefix.$payloadB64.$certB64');
      final ed25519 = Ed25519();
      final pubKey = SimplePublicKey(pubKeyBytes, type: KeyPairType.ed25519);
      final signature = Signature(sigBytes, publicKey: pubKey);
      final isValidSignature = await ed25519.verify(dataToSign, signature: signature);

      if (!isValidSignature) {
        return const Spp3VerificationResult(
          status: Spp3VerificationStatus.invalidSignature,
          errorMessage: 'La firma digital criptográfica de la licencia no coincide (posible alteración de contenido).',
        );
      }
    } catch (_) {
      return const Spp3VerificationResult(
        status: Spp3VerificationStatus.invalidSignature,
        errorMessage: 'Fallo al verificar la firma criptográfica del token.',
      );
    }

    // 4. Validar Parámetros Estrictos de Licenciamiento (Product, Versión Exacta, HWID y Caducidad)
    if (payload.productCode != expectedProductCode) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.productMismatch,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'Licencia no válida.',
      );
    }

    String targetVer;
    String licVer;
    try {
      targetVer = Spp3Payload.stripBuildNumber(expectedVersion);
      licVer = Spp3Payload.stripBuildNumber(payload.exactVersion);
    } catch (e) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.versionMismatch,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'Discrepancia o formato de versión inválido: $e',
      );
    }

    if (licVer != targetVer) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.versionMismatch,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'Esta licencia es válida exclusivamente para la versión $licVer y no se autoriza en la versión actual ($targetVer).',
      );
    }

    if (payload.hwidHash.toLowerCase() != currentHwidHash.toLowerCase()) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.hwidMismatch,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'El identificador físico de hardware de este equipo no coincide con el dispositivo autorizado en la licencia.',
      );
    }

    final now = currentClockUtc ?? DateTime.now().toUtc();
    if (payload.expiresAtUtc != null && now.isAfter(payload.expiresAtUtc!)) {
      return Spp3VerificationResult(
        status: Spp3VerificationStatus.expired,
        payload: payload,
        signerCertificate: signerCert,
        errorMessage: 'Su licencia caducó formalmente el ${payload.expiresAtUtc!.toLocal()}.',
      );
    }

    return Spp3VerificationResult(
      status: Spp3VerificationStatus.valid,
      payload: payload,
      signerCertificate: signerCert,
    );
  }
}
