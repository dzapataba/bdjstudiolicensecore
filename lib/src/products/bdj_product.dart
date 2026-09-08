/// Catálogo oficial de productos del ecosistema BDJ Studio.
enum BdjProduct {
  samplePad('bdj_studio_sample_pad', 'BDJ Studio Sample Pad'),
  searchPro('bdj_studio_search_pro', 'BDJ Studio Search Pro');

  final String code;
  final String displayName;

  const BdjProduct(this.code, this.displayName);

  static BdjProduct? fromCode(String code) {
    for (final p in values) {
      if (p.code == code) return p;
    }
    return null;
  }
}
