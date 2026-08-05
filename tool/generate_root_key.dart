import 'dart:convert';
import 'package:cryptography/cryptography.dart';

void main() async {
  final ed25519 = Ed25519();
  final seed = utf8.encode('BDJ_STUDIO_SPP3_ROOT_SECRET_2026');
  if (seed.length != 32) {
    print('ERROR: La semilla tiene ${seed.length} bytes, se requieren exactamente 32.');
    return;
  }
  
  final keyPair = await ed25519.newKeyPairFromSeed(seed);
  final pubKey = await keyPair.extractPublicKey();

  final privateBase64Url = base64UrlEncode(seed);
  final publicBase64Url = base64UrlEncode(pubKey.bytes);

  print('==============================================');
  print('BDJ STUDIO SPP3 SYSTEM - KEY HIERARCHY SETUP');
  print('==============================================');
  print('ROOT PRIVATE KEY (PROPIETARIO - NUNCA COMPARTIR): $privateBase64Url');
  print('ROOT PUBLIC KEY  (APPS COMERCIALES & VALIDACIÓN): $publicBase64Url');
  print('==============================================');
}
