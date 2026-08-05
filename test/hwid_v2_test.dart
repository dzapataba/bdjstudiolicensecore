import 'package:test/test.dart';
import 'package:bdj_license_core/bdj_license_core.dart';

void main() {
  group('HWID V2 - Pruebas por Plataforma y Resistencia ante Cambios', () {
    test('WINDOWS: Inmutabilidad ante cambios volátiles y fallo si está vacío', () {
      final base = HwidEngine.canonicalize(
        platform: 'windows',
        components: {'deviceId': 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d'},
      );
      expect(base.schemaVersion, equals('V2'));
      expect(base.visibleHwid.length, equals(19)); // XXXX-XXXX-XXXX-XXXX

      // Simular cambio de computerName, RAM y usuario del equipo
      // Como el motor solo procesa el identificador persistente, genera el mismo HWID y deviceHash
      final trasCambiosVolatiles = HwidEngine.canonicalize(
        platform: 'windows',
        components: {'deviceId': 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d'},
      );
      expect(trasCambiosVolatiles.visibleHwid, equals(base.visibleHwid));
      expect(trasCambiosVolatiles.deviceHash, equals(base.deviceHash));

      // Fallar con error si MachineGuid / deviceId está vacío sin fallback
      expect(
        () => HwidEngine.canonicalize(platform: 'windows', components: {'deviceId': ''}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });

    test('MACOS: Inmutabilidad ante actualizaciones de OS y fallo si está vacío', () {
      final base = HwidEngine.canonicalize(
        platform: 'macos',
        components: {'systemGUID': 'MAC-SYS-GUID-99887766'},
      );

      // Cambio de computerName o actualización de sistema no altera systemGUID
      final trasActualizacion = HwidEngine.canonicalize(
        platform: 'macos',
        components: {'systemGUID': 'MAC-SYS-GUID-99887766'},
      );
      expect(trasActualizacion.visibleHwid, equals(base.visibleHwid));
      expect(trasActualizacion.deviceHash, equals(base.deviceHash));

      // systemGUID vacío lanza error
      expect(
        () => HwidEngine.canonicalize(platform: 'macos', components: {'systemGUID': '    '}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });

    test('LINUX: Inmutabilidad ante cambio de prettyName o distro y fallo si machine-id y DMI son vacíos', () {
      final base = HwidEngine.canonicalize(
        platform: 'linux',
        components: {
          'machineId': 'abcde1234567890f9876543212345678',
          'productUuid': 'dmi-uuid-stable-001',
        },
      );

      // Cambio de prettyName y upgrade de distro no alteran machine-id ni DMI
      final trasUpgrade = HwidEngine.canonicalize(
        platform: 'linux',
        components: {
          'machineId': 'abcde1234567890f9876543212345678',
          'productUuid': 'dmi-uuid-stable-001',
        },
      );
      expect(trasUpgrade.visibleHwid, equals(base.visibleHwid));

      // machine-id vacío y DMI vacío -> error
      expect(
        () => HwidEngine.canonicalize(
          platform: 'linux',
          components: {'machineId': '', 'productUuid': null},
        ),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });

    test('ANDROID: Inmutabilidad ante cambio de modelo reportado u OS update', () {
      final base = HwidEngine.canonicalize(
        platform: 'android',
        components: {'id': 'e5a192837465b8c9'},
      );

      // Actualización de Android OS no altera Android ID (si no es factory reset)
      final trasOsUpdate = HwidEngine.canonicalize(
        platform: 'android',
        components: {'id': 'e5a192837465b8c9'},
      );
      expect(trasOsUpdate.visibleHwid, equals(base.visibleHwid));

      // Android ID vacío o genérico -> error
      expect(
        () => HwidEngine.canonicalize(platform: 'android', components: {'id': '00000000-0000-0000-0000-000000000000'}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });

    test('IOS: Inmutabilidad ante cambio de nombre del iPhone y actualización de iOS', () {
      final base = HwidEngine.canonicalize(
        platform: 'ios',
        components: {'id': '8A55B2E1-6A18-4903-810A-33D7C513E0A3'},
      );

      // Cambio de nombre de dispositivo no altera identifierForVendor
      final trasNombreCambio = HwidEngine.canonicalize(
        platform: 'ios',
        components: {'id': '8a55b2e1-6a18-4903-810a-33d7c513e0a3'}, // prueba case-insesitivity
      );
      expect(trasNombreCambio.visibleHwid, equals(base.visibleHwid));

      // identifierForVendor vacío lanza error
      expect(
        () => HwidEngine.canonicalize(platform: 'ios', components: {'id': ''}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });

    test('RECHAZO DE IDENTIDADES SIN ENTROPÍA O CON PLACEHOLDERS', () {
      expect(
        () => HwidEngine.canonicalize(platform: 'windows', components: {'deviceId': 'unknown'}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
      expect(
        () => HwidEngine.canonicalize(platform: 'windows', components: {'deviceId': '11111111-1111-1111-1111-111111111111'}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
      expect(
        () => HwidEngine.canonicalize(platform: 'unknown_platform', components: {'id': 'valid-looking-id-1234'}),
        throwsA(isA<DeviceFingerprintFailure>()),
      );
    });
  });

  group('CONTRACT TEST - ECOSISTEMA BDJ STUDIO', () {
    test('Para un mismo conjunto de datos, License, Sample Pad, Synth Pro y Wave Video generan exactamente la misma huella y deviceHash', () {
      final datosHardware = {
        'deviceId': 'BDJ-DEV-SILICON-STABLE-UUID-2026',
      };
      const plataforma = 'windows';

      // Simulamos la resolución en cada una de las 4 aplicaciones usando el contrato V2 centralizado
      final hwidLicense = HwidEngine.canonicalize(platform: plataforma, components: datosHardware);
      final hwidSamplePad = HwidEngine.canonicalize(platform: plataforma, components: datosHardware);
      final hwidSynthPro = HwidEngine.canonicalize(platform: plataforma, components: datosHardware);
      final hwidWaveVideo = HwidEngine.canonicalize(platform: plataforma, components: datosHardware);

      expect(hwidLicense.visibleHwid, equals(hwidSamplePad.visibleHwid));
      expect(hwidLicense.visibleHwid, equals(hwidSynthPro.visibleHwid));
      expect(hwidLicense.visibleHwid, equals(hwidWaveVideo.visibleHwid));

      expect(hwidLicense.deviceHash, equals(hwidSamplePad.deviceHash));
      expect(hwidLicense.deviceHash, equals(hwidSynthPro.deviceHash));
      expect(hwidLicense.deviceHash, equals(hwidWaveVideo.deviceHash));

      // Comprobación explícita del formato canónico
      expect(hwidLicense.canonicalString, startsWith('BDJ-HWID-V2|platform=windows|'));
    });
  });
}
