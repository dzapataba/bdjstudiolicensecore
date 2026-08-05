import 'dart:convert';
import 'package:test/test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:bdj_license_core/bdj_license_core.dart';

void main() {
  group('Vigencia del Certificado Administrativo y Licencias Históricas', () {
    late SimpleKeyPair rootKeyPair;
    late String rootPublicKeyBase64;
    late SimpleKeyPair operatorKeyPair;
    late String operatorPublicKeyBase64;

    setUp(() async {
      final seed = base64Url.decode('QkRKX1NUVURJT19TUFAzX1JPT1RfU0VDUkVUXzIwMjY=');
      rootKeyPair = await KeyHierarchy.generateKeyPairFromSeed(seed);
      rootPublicKeyBase64 = KeyHierarchy.ecosystemRootPublicKey;

      operatorKeyPair = await KeyHierarchy.generateKeyPair();
      operatorPublicKeyBase64 = base64UrlEncode((await operatorKeyPair.extractPublicKey()).bytes);
    });

    test('1. Certificado vigente actualmente - licencia emitida válidamente se aprueba', () async {
      final now = DateTime.now().toUtc();
      final adminCert = AdminCertificate(
        adminId: 'admin_active@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: now.subtract(const Duration(days: 1)),
        validUntilUtc: now.add(const Duration(days: 365)),
      );
      // Firmar con clave raíz
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(adminCert.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: adminCert.adminId,
        operatorPublicKeyBase64: adminCert.operatorPublicKeyBase64,
        validFromUtc: adminCert.validFromUtc,
        validUntilUtc: adminCert.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      final payload = Spp3Payload(
        licenseId: 'LIC-001',
        customerId: 'CUST-001',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'pro',
        issuedAtUtc: now,
        expiresAtUtc: now.add(const Duration(days: 30)),
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      final verifyResult = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
      );
      expect(verifyResult.isValid, isTrue);
    });

    test('2. Certificado expirado DESPUÉS de emitir licencia - licencia legítima histórica NO vence', () async {
      final year2025 = DateTime.utc(2025, 6, 1);
      final certExpiredIn2025 = AdminCertificate(
        adminId: 'admin_historical@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: DateTime.utc(2025, 1, 1),
        validUntilUtc: DateTime.utc(2025, 12, 31),
      );
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(certExpiredIn2025.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: certExpiredIn2025.adminId,
        operatorPublicKeyBase64: certExpiredIn2025.operatorPublicKeyBase64,
        validFromUtc: certExpiredIn2025.validFromUtc,
        validUntilUtc: certExpiredIn2025.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      // Licencia permanente emitida en junio de 2025 (cuando el cert ERA válido)
      final payload = Spp3Payload(
        licenseId: 'LIC-HISTORICAL-01',
        customerId: 'CUST-OLD',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'permanente',
        issuedAtUtc: year2025, // emitida en junio 2025
        expiresAtUtc: null,    // permanente
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      
      // Verificado hoy (2026 o posterior, cuando el cert del admin YA EXPIRÓ)
      final verifyResult = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
        currentClockUtc: DateTime.utc(2028, 1, 1), // Estamos en 2028
      );

      // ¡DEBE SER VÁLIDA porque cuando se emitió (2025), el certificado emisor era legítimo!
      expect(verifyResult.isValid, isTrue);
      expect(verifyResult.status, equals(Spp3VerificationStatus.valid));
    });

    test('3. Certificado YA expirado cuando se emitió - se RECHAZA emisión ilegítima', () async {
      final certExpiredIn2024 = AdminCertificate(
        adminId: 'rogue_admin@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: DateTime.utc(2024, 1, 1),
        validUntilUtc: DateTime.utc(2024, 12, 31),
      );
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(certExpiredIn2024.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: certExpiredIn2024.adminId,
        operatorPublicKeyBase64: certExpiredIn2024.operatorPublicKeyBase64,
        validFromUtc: certExpiredIn2024.validFromUtc,
        validUntilUtc: certExpiredIn2024.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      // Alguien intenta firmar una licencia con fecha de emisión de 2025 usando un cert caducado en 2024
      final payload = Spp3Payload(
        licenseId: 'LIC-FRAUD-01',
        customerId: 'CUST-BAD',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'pro',
        issuedAtUtc: DateTime.utc(2025, 6, 1),
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      
      final verifyResult = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
      );

      expect(verifyResult.isValid, isFalse);
      expect(verifyResult.status, equals(Spp3VerificationStatus.expiredCertificate));
      expect(verifyResult.errorMessage, contains('ya había expirado cuando se emitió la licencia'));
    });

    test('4. Certificado AÚN NO VIGENTE cuando se emitió - se RECHAZA token prematuro/anómalo', () async {
      final certFuture = AdminCertificate(
        adminId: 'future_admin@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: DateTime.utc(2030, 1, 1),
        validUntilUtc: DateTime.utc(2031, 12, 31),
      );
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(certFuture.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: certFuture.adminId,
        operatorPublicKeyBase64: certFuture.operatorPublicKeyBase64,
        validFromUtc: certFuture.validFromUtc,
        validUntilUtc: certFuture.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      final payload = Spp3Payload(
        licenseId: 'LIC-PREMATURE',
        customerId: 'CUST-001',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'pro',
        issuedAtUtc: DateTime.utc(2026, 1, 1),
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      
      final verifyResult = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
      );

      expect(verifyResult.isValid, isFalse);
      expect(verifyResult.status, equals(Spp3VerificationStatus.invalidCertificate));
      expect(verifyResult.errorMessage, contains('aún no era válido cuando se emitió'));
    });

    test('5. Licencia permanente emitida válidamente - no caduca en el futuro lejano (2099)', () async {
      final now = DateTime.now().toUtc();
      final adminCert = AdminCertificate(
        adminId: 'admin_permanent@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: now.subtract(const Duration(days: 1)),
        validUntilUtc: now.add(const Duration(days: 365)),
      );
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(adminCert.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: adminCert.adminId,
        operatorPublicKeyBase64: adminCert.operatorPublicKeyBase64,
        validFromUtc: adminCert.validFromUtc,
        validUntilUtc: adminCert.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      final payload = Spp3Payload(
        licenseId: 'LIC-PERM-2099',
        customerId: 'CUST-PERM',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'studio_bundle',
        issuedAtUtc: now,
        expiresAtUtc: null, // Licencia permanente
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      
      final verifyResult = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
        currentClockUtc: DateTime.utc(2099, 12, 31), // Año 2099
      );
      expect(verifyResult.isValid, isTrue);
    });

    test('6. Licencia temporal emitida válidamente - válida dentro de plazo y caducada tras plazo', () async {
      final now = DateTime.utc(2026, 8, 1);
      final adminCert = AdminCertificate(
        adminId: 'admin_temp@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyBase64,
        validFromUtc: DateTime.utc(2026, 1, 1),
        validUntilUtc: DateTime.utc(2027, 1, 1),
      );
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(utf8.encode(adminCert.toUnsignedCanonicalString()), keyPair: rootKeyPair);
      final signedCert = AdminCertificate(
        adminId: adminCert.adminId,
        operatorPublicKeyBase64: adminCert.operatorPublicKeyBase64,
        validFromUtc: adminCert.validFromUtc,
        validUntilUtc: adminCert.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );

      // Licencia de 30 días
      final payload = Spp3Payload(
        licenseId: 'LIC-TEMP-30',
        customerId: 'CUST-TEMP',
        deviceId: 'DEVICE-001',
        hwidHash: 'HASH-001',
        productCode: 'sample_pad',
        exactVersion: '1.0.0',
        plan: 'mensual',
        issuedAtUtc: now,
        expiresAtUtc: now.add(const Duration(days: 30)),
      );

      final token = await Spp3Token.issue(payload: payload, signerCertificate: signedCert, operatorKeyPair: operatorKeyPair);
      
      // Día 15 -> Válida
      final validVerify = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
        currentClockUtc: now.add(const Duration(days: 15)),
      );
      expect(validVerify.isValid, isTrue);

      // Día 31 -> Caducada
      final expiredVerify = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: '1.0.0',
        currentHwidHash: 'HASH-001',
        currentClockUtc: now.add(const Duration(days: 31)),
      );
      expect(expiredVerify.isValid, isFalse);
      expect(expiredVerify.status, equals(Spp3VerificationStatus.expired));
    });
  });
}
