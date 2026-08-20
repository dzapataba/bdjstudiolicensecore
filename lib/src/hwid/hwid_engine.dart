import 'dart:convert';
import 'package:crypto/crypto.dart' as crypto;
import '../crypto/key_hierarchy.dart';

class DeviceFingerprintFailure implements Exception {
  final String message;
  const DeviceFingerprintFailure(this.message);
  @override
  String toString() => 'DeviceFingerprintFailure: $message';
}

class HwidResult {
  final String schemaVersion;
  final String platform;
  final Map<String, String> components;
  final String canonicalString;
  final String visibleHwid;

  /// Firma de estabilidad: hash V2 de los componentes de hardware que NO son
  /// volátiles (excluye p. ej. ANDROID_ID / identifierForVendor). Sirve para
  /// reutilizar el mismo HWID tras un formateo del sistema.
  final String stabilitySignature;
  final String deviceHash;

  const HwidResult({
    required this.schemaVersion,
    required this.platform,
    required this.components,
    required this.canonicalString,
    required this.visibleHwid,
    required this.stabilitySignature,
    required this.deviceHash,
  });

  Map<String, dynamic> toJson() => {
    'schemaVersion': schemaVersion,
    'platform': platform,
    'components': components,
    'canonicalString': canonicalString,
    'visibleHwid': visibleHwid,
    'stabilitySignature': stabilitySignature,
    'deviceHash': deviceHash,
  };
}

class HwidEngine {
  static const String hwidSchemaVersion = 'V2';
  static const String _prefix = 'BDJ-HWID-$hwidSchemaVersion';

  /// Claves de componentes que se reinician con un formateo/reinstalación del
  /// sistema y por tanto se EXCLUYEN de la firma de estabilidad:
  ///  - 'id' en Android = ANDROID_ID (Settings.Secure.ANDROID_ID), se reinicia
  ///    con factory reset y es distinto por firma de app.
  ///  - 'id' en iOS = identifierForVendor, puede cambiar tras borrado total.
  static const Set<String> volatileComponentKeys = {'id'};

  static const List<String> _invalidPlaceholders = [
    '00000000-0000-0000-0000-000000000000',
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
    '0000-0000-0000-0000',
    'unknown_platform',
    'unknown',
    'generic',
    'example',
    'test',
    'null',
    '0',
    '1',
    'n/a',
    'none',
  ];

  /// Genera y valida la representación canónica V2 para el identificador del dispositivo.
  /// Lanza [DeviceFingerprintFailure] si el material de identidad es inadecuado, inseguro o sin entropía.
  static HwidResult canonicalize({
    required String platform,
    required Map<String, String?> components,
  }) {
    final cleanPlatform = platform.trim().toLowerCase();
    if (cleanPlatform.isEmpty || cleanPlatform == 'unknown_platform' || cleanPlatform == 'unknown') {
      throw const DeviceFingerprintFailure('Plataforma desconocida o no compatible (unknown_platform).');
    }

    final validPairs = <String, String>{};
    for (final entry in components.entries) {
      final key = entry.key.trim().toLowerCase();
      final val = entry.value?.trim();

      if (val == null || val.isEmpty || val.toLowerCase() == 'null') {
        continue; // Excluye valores opcionales vacíos o nulos
      }

      // Limpia espacios no significativos
      final normalizedVal = val.replaceAll(RegExp(r'\s+'), ' ').trim();
      if (normalizedVal.isNotEmpty) {
        validPairs[key] = normalizedVal;
      }
    }

    if (validPairs.isEmpty) {
      throw const DeviceFingerprintFailure('No existe material de identidad de hardware suficiente o seguro en este dispositivo para vincular la licencia.');
    }

    // Verificación de placeholders conocidos y trivialidad
    bool allBypasses = true;
    final combinedValues = validPairs.values.join(' ').toLowerCase();

    for (final val in validPairs.values) {
      final lower = val.toLowerCase();
      if (!_invalidPlaceholders.contains(lower) && !_isTrivialOrRepeating(lower)) {
        allBypasses = false;
        break;
      }
    }

    if (allBypasses) {
      throw const DeviceFingerprintFailure('El identificador de hardware coincide con un fallback constante, genérico o de ejemplo.');
    }

    // Verificación de entropía mínima
    final alphanumericOnly = combinedValues.replaceAll(RegExp(r'[^a-z0-9]'), '');
    if (alphanumericOnly.length < 4) {
      throw const DeviceFingerprintFailure('Insuficiente entropía en la identidad del dispositivo (longitud mínima de material no alcanzada).');
    }

    final uniqueChars = alphanumericOnly.split('').toSet();
    if (uniqueChars.length < 3) {
      throw const DeviceFingerprintFailure('Insuficiente entropía en la identidad del dispositivo (cadena constante o repetitiva sin diversidad de bytes).');
    }

    // Ordenar campos alfabéticamente
    final sortedKeys = validPairs.keys.toList()..sort();
    final orderedParts = <String>[];
    for (final k in sortedKeys) {
      orderedParts.add('$k=${validPairs[k]!.toLowerCase()}');
    }

    final canonicalString = '$_prefix|platform=$cleanPlatform|${orderedParts.join('|')}';

    final visibleHwid = _hashToHwid(canonicalString);

    // Firma de estabilidad excluyendo componentes volátiles (reinitables por formateo)
    final stabilitySignature = _stableSignature(
      platform: cleanPlatform,
      validPairs: validPairs,
      fallback: visibleHwid,
    );

    // Hash completo para validación criptográfica SPP3
    final deviceHash = KeyHierarchy.hashHwid(visibleHwid);

    return HwidResult(
      schemaVersion: hwidSchemaVersion,
      platform: cleanPlatform,
      components: Map<String, String>.unmodifiable(validPairs),
      canonicalString: canonicalString,
      visibleHwid: visibleHwid,
      stabilitySignature: stabilitySignature,
      deviceHash: deviceHash,
    );
  }

  static String _hashToHwid(String data) {
    final hashBytes = crypto.sha256.convert(utf8.encode(data));
    final fullHashHex = hashBytes.toString().toUpperCase();
    final shortHash = fullHashHex.substring(0, 16);
    return '${shortHash.substring(0, 4)}-${shortHash.substring(4, 8)}-${shortHash.substring(8, 12)}-${shortHash.substring(12, 16)}';
  }

  static String _stableSignature({
    required String platform,
    required Map<String, String> validPairs,
    required String fallback,
  }) {
    final stable = <String, String>{};
    for (final entry in validPairs.entries) {
      if (volatileComponentKeys.contains(entry.key)) continue;
      stable[entry.key] = entry.value.toLowerCase();
    }
    if (stable.isEmpty) return fallback;

    final keys = stable.keys.toList()..sort();
    final parts = keys.map((k) => '$k=${stable[k]}').join('|');
    return _hashToHwid('$_prefix|platform=$platform|$parts');
  }

  /// Generación legacy V1 puramente para transición en la interfaz de BDJ Studio License.
  /// Nota: NO debe ser utilizada para nuevas activaciones o para validación con fallback inseguro.
  static String generateV1Legacy(String rawString) {
    final bytes = utf8.encode(rawString);
    final hashStr = crypto.sha256.convert(bytes).toString().toUpperCase();
    final shortHash = hashStr.substring(0, 16);
    return '${shortHash.substring(0, 4)}-${shortHash.substring(4, 8)}-${shortHash.substring(8, 12)}-${shortHash.substring(12, 16)}';
  }

  static bool _isTrivialOrRepeating(String str) {
    final cleaned = str.replaceAll(RegExp(r'[^a-zA-Z0-9]'), '');
    if (cleaned.isEmpty) return true;
    final firstChar = cleaned[0];
    for (var i = 1; i < cleaned.length; i++) {
      if (cleaned[i] != firstChar) return false;
    }
    return true;
  }
}
