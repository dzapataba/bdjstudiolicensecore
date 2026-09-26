import 'dart:convert';
import 'package:test/test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:bdj_license_core/bdj_license_core.dart';

void main() {
  group('Licenciamiento por Versión Exacta (major.minor.patch)', () {
    late SimpleKeyPair operatorKeyPair;
    late AdminCertificate signedCert;
    late String rootPublicKeyBase64;

    setUp(() async {
      final rootSeed = base64Url.decode('QkRKX1NUVURJT19TUFAzX1JPT1RfU0VDUkVUXzIwMjY=');
      final rootKeyPair = await KeyHierarchy.generateKeyPairFromSeed(rootSeed);
      rootPublicKeyBase64 = KeyHierarchy.ecosystemRootPublicKey;

      operatorKeyPair = await KeyHierarchy.generateKeyPair();
      final opPub = base64UrlEncode((await operatorKeyPair.extractPublicKey()).bytes);

      final now = DateTime.now().toUtc();
      final unsignedCert = AdminCertificate(
        adminId: 'admin@bdjstudio.com',
        operatorPublicKeyBase64: opPub,
        validFromUtc: now.subtract(const Duration(days: 1)),
        validUntilUtc: now.add(const Duration(days: 365)),
      );
      final sig = await Ed25519().sign(
        utf8.encode(unsignedCert.toUnsignedCanonicalString()),
        keyPair: rootKeyPair,
      );
      signedCert = AdminCertificate(
        adminId: unsignedCert.adminId,
        operatorPublicKeyBase64: opPub,
        validFromUtc: unsignedCert.validFromUtc,
        validUntilUtc: unsignedCert.validUntilUtc,
        rootSignatureBase64: base64UrlEncode(sig.bytes),
      );
    });

    Future<String> issueForVersion(String ver) async {
      return Spp3Token.issue(
        payload: Spp3Payload(
          licenseId: 'LIC-VER-001',
          customerId: 'CUST-VER-01',
          deviceId: 'DEV-001',
          hwidHash: 'HASH-123',
          productCode: 'sample_pad',
          exactVersion: ver,
          plan: 'pro',
          issuedAtUtc: DateTime.now().toUtc(),
        ),
        signerCertificate: signedCert,
        operatorKeyPair: operatorKeyPair,
      );
    }

    Future<Spp3VerificationResult> verifyAgainst(String token, String targetVer) async {
      return Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyBase64,
        expectedProductCode: 'sample_pad',
        expectedVersion: targetVer,
        currentHwidHash: 'HASH-123',
      );
    }

    test('1. 1.0.3 contra 1.0.3 (Acepta - coincidencia idéntica)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.0.3');
      expect(res.isValid, isTrue);
      expect(res.status, equals(Spp3VerificationStatus.valid));
    });

    test('2. 1.0.3 contra 1.0.3+1 (Acepta - ignora +build en app en curso)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.0.3+1');
      expect(res.isValid, isTrue);
    });

    test('3. 1.0.3 contra 1.0.3+25 (Acepta - ignora +build posterior)', () async {
      final token = await issueForVersion('1.0.3+5'); // incluso si se emitió con +5
      final res = await verifyAgainst(token, '1.0.3+25');
      expect(res.isValid, isTrue);
    });

    test('4. 1.0.3 contra 1.0.2 (Acepta - versión no restrictiva)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.0.2');
      expect(res.isValid, isTrue);
    });

    test('5. 1.0.3 contra 1.0.4 (Acepta - versión no restrictiva)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.0.4');
      expect(res.isValid, isTrue);
    });

    test('6. 1.0.3 contra 1.1.0 (Acepta - versión no restrictiva)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.1.0');
      expect(res.isValid, isTrue);
    });

    test('7. 1.0.3 contra 2.0.0 (Acepta - versión no restrictiva)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '2.0.0');
      expect(res.isValid, isTrue);
    });

    test('8. Prerelease: 1.0.3 contra 1.0.3-beta.1 (Acepta - versión no restrictiva)', () async {
      final token = await issueForVersion('1.0.3');
      final res = await verifyAgainst(token, '1.0.3-beta.1');
      expect(res.isValid, isTrue);
    });
  });
}
