import 'dart:convert';
import 'package:bdj_license_core/bdj_license_core.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('SPP3 Token & Key Hierarchy Security Suite', () {
    late SimpleKeyPair rootKeyPair;
    late String rootPublicKeyB64;
    late SimpleKeyPair operatorKeyPair;
    late String operatorPublicKeyB64;
    late AdminCertificate validAdminCert;

    setUp(() async {
      rootKeyPair = await KeyHierarchy.generateKeyPair();
      final rootPub = await rootKeyPair.extractPublicKey();
      rootPublicKeyB64 = base64UrlEncode(rootPub.bytes);

      operatorKeyPair = await KeyHierarchy.generateKeyPair();
      final operatorPub = await operatorKeyPair.extractPublicKey();
      operatorPublicKeyB64 = base64UrlEncode(operatorPub.bytes);

      validAdminCert = await KeyHierarchy.issueAdminCertificate(
        adminId: 'operator_alpha@bdjstudio.com',
        operatorPublicKeyBase64: operatorPublicKeyB64,
        rootKeyPair: rootKeyPair,
        validityDuration: const Duration(days: 30),
      );
    });

    test('1. Certificado de Administrador emitido por Clave Raíz es válido', () async {
      final isValid = await validAdminCert.verify(rootPublicKeyB64);
      expect(isValid, isTrue);
    });

    test('2. Certificado con firma de raíz falsa es rechazado', () async {
      final fakeRootKeyPair = await KeyHierarchy.generateKeyPair();
      final fakePub = base64UrlEncode((await fakeRootKeyPair.extractPublicKey()).bytes);
      final isFakeValid = await validAdminCert.verify(fakePub);
      expect(isFakeValid, isFalse);
    });

    test('3. Emisión y verificación exitosa de Token SPP3 (ignorando build numbers)', () async {
      final hwidHash = KeyHierarchy.hashHwid('BDJ-WIN-2026-X86');
      final payload = Spp3Payload(
        licenseId: 'LIC-00001',
        customerId: 'CLIENT-01',
        deviceId: 'BDJ-WIN-2026-X86',
        hwidHash: hwidHash,
        productCode: 'bdj_studio_sample_pad',
        exactVersion: '1.0.3+4', // Versión de emisión con build +4
        plan: 'year',
        issuedAtUtc: DateTime.now().toUtc(),
        expiresAtUtc: DateTime.now().toUtc().add(const Duration(days: 365)),
      );

      final token = await Spp3Token.issue(
        payload: payload,
        signerCertificate: validAdminCert,
        operatorKeyPair: operatorKeyPair,
      );

      expect(token, startsWith('SPP3.'));

      // Verificamos en la aplicación cliente que corre la versión "1.0.3+99" (diferente build)
      final result = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyB64,
        expectedProductCode: 'bdj_studio_sample_pad',
        expectedVersion: '1.0.3+99', // Debe coincidir al descartar el build
        currentHwidHash: hwidHash,
      );

      expect(result.status, equals(Spp3VerificationStatus.valid));
      expect(result.payload?.licenseId, equals('LIC-00001'));
      expect(result.payload?.exactVersion, equals('1.0.3')); // Guardado puro sin build
    });

    test('4. Rechazo estricto ante discrepancia de Versión Exacta de aplicación', () async {
      final hwidHash = KeyHierarchy.hashHwid('BDJ-MAC-PRO');
      final payload = Spp3Payload(
        licenseId: 'LIC-00002',
        customerId: 'CLIENT-02',
        deviceId: 'BDJ-MAC-PRO',
        hwidHash: hwidHash,
        productCode: 'bdj_studio_sample_pad',
        exactVersion: '1.0.3',
        plan: 'permanent',
        issuedAtUtc: DateTime.now().toUtc(),
      );

      final token = await Spp3Token.issue(
        payload: payload,
        signerCertificate: validAdminCert,
        operatorKeyPair: operatorKeyPair,
      );

      // El usuario actualizó su app a la versión 1.0.4 sin obtener nueva licencia para esta release
      final result = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyB64,
        expectedProductCode: 'bdj_studio_sample_pad',
        expectedVersion: '1.0.4',
        currentHwidHash: hwidHash,
      );

      expect(result.status, equals(Spp3VerificationStatus.versionMismatch));
      expect(result.errorMessage, contains('válida exclusivamente para la versión 1.0.3'));
    });

    test('5. Rechazo inmediato ante discrepancia en Hash de HWID', () async {
      final origHwidHash = KeyHierarchy.hashHwid('ORIGINAL-DEVICE-ID');
      final otherHwidHash = KeyHierarchy.hashHwid('STOLEN-DEVICE-ID');

      final payload = Spp3Payload(
        licenseId: 'LIC-00003',
        customerId: 'CLIENT-03',
        deviceId: 'ORIGINAL-DEVICE-ID',
        hwidHash: origHwidHash,
        productCode: 'bdj_studio_synth_pro',
        exactVersion: '2.0.0',
        plan: 'permanent',
        issuedAtUtc: DateTime.now().toUtc(),
      );

      final token = await Spp3Token.issue(
        payload: payload,
        signerCertificate: validAdminCert,
        operatorKeyPair: operatorKeyPair,
      );

      final result = await Spp3Token.verify(
        token: token,
        rootPublicKeyBase64: rootPublicKeyB64,
        expectedProductCode: 'bdj_studio_synth_pro',
        expectedVersion: '2.0.0',
        currentHwidHash: otherHwidHash, // Intento de activar en equipo no autorizado
      );

      expect(result.status, equals(Spp3VerificationStatus.hwidMismatch));
    });

    test('6. Rechazo ante alteración maliciosa del contenido del token', () async {
      final hwidHash = KeyHierarchy.hashHwid('DEVICE-VALID');
      final payload = Spp3Payload(
        licenseId: 'LIC-00004',
        customerId: 'CLIENT-04',
        deviceId: 'DEVICE-VALID',
        hwidHash: hwidHash,
        productCode: 'bdj_studio_wave_video',
        exactVersion: '1.5.0',
        plan: 'year',
        issuedAtUtc: DateTime.now().toUtc(),
      );

      final token = await Spp3Token.issue(
        payload: payload,
        signerCertificate: validAdminCert,
        operatorKeyPair: operatorKeyPair,
      );

      // Alteramos un carácter en el payload (parte 1 del token)
      final parts = token.split('.');
      final alteredPayload = '${parts[1].substring(0, parts[1].length - 2)}XX';
      final tamperedToken = 'SPP3.$alteredPayload.${parts[2]}.${parts[3]}';

      final result = await Spp3Token.verify(
        token: tamperedToken,
        rootPublicKeyBase64: rootPublicKeyB64,
        expectedProductCode: 'bdj_studio_wave_video',
        expectedVersion: '1.5.0',
        currentHwidHash: hwidHash,
      );

      expect(
        result.status,
        anyOf(
          equals(Spp3VerificationStatus.invalidSignature),
          equals(Spp3VerificationStatus.invalidFormat),
        ),
      );
    });
  });
}
